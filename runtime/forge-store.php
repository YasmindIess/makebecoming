#!/usr/bin/env php
<?php
/**
 * FORGE R0 local journal. Immutable content blocks + atomically replaced HEAD.
 * Admission/geometry are delegated to the native C verifier; this is a local
 * orchestration prototype, not signed or distributed storage.
 */
declare(strict_types=1);
umask(0077);
const DOMAIN = "FORGE/OMISSION/V3\n";
const MAX_FILE = 3 * 1024 * 1024;
const MAX_EVENTS = 250;

function fail(string $message): never { throw new RuntimeException($message); }
function require_ok(bool $condition, string $message): void { if (!$condition) fail($message); }
function is_list_array(array $a): bool { return array_is_list($a); }
function canonical(mixed $v): string {
    if ($v === null) return 'null';
    if (is_string($v)) return json_encode($v, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (is_int($v)) return (string)$v;
    if (is_bool($v)) return $v ? 'true' : 'false';
    if (is_array($v)) {
        if (is_list_array($v)) return '[' . implode(',', array_map('canonical', $v)) . ']';
        ksort($v, SORT_STRING);
        $pairs = [];
        foreach ($v as $k => $val) {
            require_ok(is_string($k) && preg_match('/^[a-z0-9_]+$/D', $k) === 1, 'unexpected canonical key');
            $pairs[] = canonical($k) . ':' . canonical($val);
        }
        return '{' . implode(',', $pairs) . '}';
    }
    fail('unsupported record value');
}
function rows(string $source): array {
    require_ok(filesize($source) !== false && filesize($source) <= MAX_FILE, 'JSONL input exceeds 3 MiB');
    $content=file_get_contents($source);
    require_ok($content!==false,'cannot read journal');
    $lines=preg_split('/\r?\n/', $content);
    $result=[];
    foreach ($lines as $line) {
        if (trim($line)==='') continue;
        require_ok(strlen($line)<65536,'record exceeds native parser limit');
        $row=json_decode($line,true,32,JSON_THROW_ON_ERROR);
        require_ok(is_array($row) && isset($row['body'],$row['digest']) && count($row)===2, 'invalid record wrapper');
        $result[]=$row;
        require_ok(count($result)<=MAX_EVENTS,'record count exceeds limit');
    }
    return $result;
}
function run_kernel(string $source,?string $topology=null): array {
    $exe=dirname(__DIR__).'/forge-kernel';
    require_ok(is_file($exe) && is_executable($exe),'compile native kernel with make first');
    $cmd=[$exe,'replay',$source];
    if ($topology!==null){$cmd[]='--topology';$cmd[]=$topology;}
    $proc=proc_open($cmd,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,null,null,['bypass_shell'=>true]);
    require_ok(is_resource($proc),'unable to start native verifier');
    fclose($pipes[0]);$stdout=stream_get_contents($pipes[1]);fclose($pipes[1]);
    $stderr=stream_get_contents($pipes[2]);fclose($pipes[2]);
    $code=proc_close($proc);
    require_ok($code===0,'native admission rejected: '.trim($stderr));
    $result=json_decode($stdout,true,32,JSON_THROW_ON_ERROR);
    require_ok(is_array($result) && ($result['verified']??null)===true,'native verifier did not return valid result');
    return $result;
}
function ensure_dir(string $path): void {
    if (!is_dir($path)) require_ok(mkdir($path,0700,true) || is_dir($path),'failed to create storage directory');
    require_ok(!is_link($path),'symlink storage directories are not accepted');
}
function head_state(string $dir): array {
    $file=$dir.'/HEAD.json';
    if (!file_exists($file)) return ['head'=>null,'events'=>0];
    $h=json_decode((string)file_get_contents($file),true,8,JSON_THROW_ON_ERROR);
    require_ok(is_array($h) && array_keys($h)===['events','head'] || is_array($h) && array_keys($h)===['head','events'],'invalid HEAD');
    require_ok(is_int($h['events']) && $h['events']>=0 && $h['events']<=MAX_EVENTS,'HEAD count invalid');
    require_ok(($h['head']===null && $h['events']===0) || (is_string($h['head']) && preg_match('/^sha256:[0-9a-f]{64}$/D',$h['head'])===1 && $h['events']>0),'HEAD digest invalid');
    return $h;
}
function block_path(string $dir,string $digest): string {
    require_ok(preg_match('/^sha256:[0-9a-f]{64}$/D',$digest)===1,'invalid content-addressed block key');
    return $dir.'/blocks/'.substr($digest,7).'.json';
}
function write_immutable(string $path,string $content): void {
    if (file_exists($path)){
        require_ok(is_file($path) && !is_link($path),'existing block path invalid');
        require_ok(file_get_contents($path)===$content,'existing content block conflicts with canonical bytes');return;
    }
    $temp=$path.'.tmp.'.bin2hex(random_bytes(12));
    $fp=fopen($temp,'xb');require_ok($fp!==false,'cannot create staging block');
    try {
        require_ok(fwrite($fp,$content)===strlen($content),'short block write');
        require_ok(fflush($fp),'block flush failed');
        if (function_exists('fsync')) require_ok(fsync($fp),'block fsync failed');
    }finally{fclose($fp);}
    /* Under the exclusive store lock, only this process writes blocks. */
    require_ok(rename($temp,$path),'atomic block rename failed');
    chmod($path,0400);
}
function replace_head(string $dir,array $head): void {
    $tmp=$dir.'/HEAD.tmp.'.bin2hex(random_bytes(12));
    $fp=fopen($tmp,'xb');require_ok($fp!==false,'cannot stage HEAD');
    try {
        $data=canonical($head)."\n";
        require_ok(fwrite($fp,$data)===strlen($data),'short HEAD write');
        require_ok(fflush($fp),'HEAD flush failed');
        if(function_exists('fsync')) require_ok(fsync($fp),'HEAD fsync failed');
    }finally{fclose($fp);}
    require_ok(rename($tmp,$dir.'/HEAD.json'),'HEAD replacement failed');
}
function with_lock(string $dir,callable $f): mixed {
    ensure_dir($dir);ensure_dir($dir.'/blocks');
    $lock=fopen($dir.'/LOCK','c');require_ok($lock!==false && flock($lock,LOCK_EX),'could not acquire storage lock');
    try{return $f();}finally{flock($lock,LOCK_UN);fclose($lock);}
}
function store(string $source,string $dir): void {
    $verified=run_kernel($source);$candidate=rows($source);
    require_ok(count($candidate)===$verified['events'],'native and PHP record counts disagree');
    $result=with_lock($dir,static function()use($dir,$candidate,$verified){
        $old=head_state($dir);$oldCount=$old['events'];
        require_ok($oldCount<=count($candidate),'refusing journal rollback');
        if($oldCount>0)require_ok($candidate[$oldCount-1]['digest']===$old['head'],'refusing to replace prior head history');
        for($i=0;$i<count($candidate);$i++){
            $row=$candidate[$i];$calculated='sha256:'.hash('sha256',DOMAIN.canonical($row['body']));
            require_ok(hash_equals($calculated,$row['digest']),'PHP digest disagrees with native C');
            if($i<$oldCount)continue;
            $path=block_path($dir,$row['digest']);
            write_immutable($path,canonical($row)."\n");
        }
        if(count($candidate)>$oldCount)replace_head($dir,['events'=>count($candidate),'head'=>$verified['head']]);
        return ['schema'=>'forge.store.r0','new_blocks'=>count($candidate)-$oldCount,'stored_events'=>count($candidate),'head'=>$verified['head'],'storage'=>'local-immutable-blocks'];
    });
    echo canonical($result)."\n";
}
function cold_replay(string $dir,?string $topology): void {
    $result=with_lock($dir,static function()use($dir,$topology){
        $head=head_state($dir);$rows=[];$current=$head['head'];$seen=[];
        while($current!==null){
            require_ok(count($rows)<MAX_EVENTS,'history exceeds limit');
            require_ok(!isset($seen[$current]),'cycle detected in parent history');$seen[$current]=true;
            $path=block_path($dir,$current);require_ok(is_file($path)&&!is_link($path),'missing or unsafe immutable block');
            $raw=file_get_contents($path);require_ok($raw!==false,'unreadable block');
            $row=json_decode($raw,true,32,JSON_THROW_ON_ERROR);
            require_ok(is_array($row)&&($row['digest']??null)===$current,'block is under wrong CID');
            require_ok(canonical($row)."\n"===$raw,'block bytes are not canonical');
            require_ok('sha256:'.hash('sha256',DOMAIN.canonical($row['body']))===$current,'block has wrong semantic hash');
            $rows[]=$row;$current=$row['body']['parent_hash']??null;
        }
        require_ok(count($rows)===$head['events'],'head length disagrees with parent chain');
        $rows=array_reverse($rows);
        $tmp=tempnam(sys_get_temp_dir(),'forge-replay-');require_ok($tmp!==false,'cannot stage replay');
        try{
            $str='';foreach($rows as $row)$str.=canonical($row)."\n";
            require_ok(file_put_contents($tmp,$str,LOCK_EX)===strlen($str),'cannot stage replay JSONL');
            $replay=run_kernel($tmp,$topology);
            require_ok($replay['head']===$head['head']&&$replay['events']===$head['events'],'replay diverged');
            return ['schema'=>'forge.cold_replay.r0','reconstructed'=>true,'result'=>$replay];
        }finally{unlink($tmp);}
    });echo canonical($result)."\n";
}
function main(array $args): void {
    require_ok(count($args)>=3,'Usage: php runtime/forge-store.php append <jsonl> <dir> | replay <dir> [--topology <path>] | status <dir>');
    $action=$args[1];
    if($action==='append'){
        require_ok(count($args)===4,'append needs <jsonl> <store>');store($args[2],$args[3]);
    }elseif($action==='replay'){
        require_ok(count($args)===3||count($args)===5,'replay needs <store> [--topology <path>]');
        if(count($args)===5)require_ok($args[3]==='--topology','unknown replay option');
        cold_replay($args[2],count($args)===5?$args[4]:null);
    }elseif($action==='status'){
        require_ok(count($args)===3,'status needs <store>');
        $h=with_lock($args[2],static fn()=>head_state($args[2]));echo canonical(['schema'=>'forge.status.r0']+$h)."\n";
    }else fail('unknown subcommand');
}
try {main($argv);} catch(Throwable $e) {fwrite(STDERR,'FORGE STORE ERROR: '.$e->getMessage()."\n");exit(2);}