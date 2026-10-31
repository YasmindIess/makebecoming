#!/usr/bin/env php
<?php
/**
 * FORGE Chapter 7 — locally committed, nonce-bound relation.assert effects.
 * Root must be explicitly pinned. Not a global distributed consensus layer.
 */
declare(strict_types=1);
umask(0077);
const F_DOMAIN = "FORGE/EFFECT/V1\n";
const F_MAX = 250;
function reject(string $code, string $detail=''): never {
    $body=['schema'=>'forge.effect.receipt.v1','status'=>'rejected','reason'=>$code,'committed'=>false];
    if ($detail!=='') $body['detail']=substr($detail,0,180);
    $raw=json_encode($body,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES);
    $body['receipt_digest']='sha256:'.hash('sha256',F_DOMAIN.$raw);
    echo json_encode($body,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES)."\n";
    exit(2);
}
function must(bool $yes,string $code): void {if(!$yes)reject($code);}
function canonical(mixed $v): string {
    if($v===null)return 'null';
    if(is_string($v))return json_encode($v,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
    if(is_int($v))return (string)$v;
    if(is_bool($v))return $v?'true':'false';
    must(is_array($v),'unsupported_receipt_type');
    if(array_is_list($v))return '['.implode(',',array_map('canonical',$v)).']';
    ksort($v,SORT_STRING);$pairs=[];
    foreach($v as $k=>$value){must(is_string($k)&&preg_match('/^[a-z0-9_]+$/D',$k)===1,'unsupported_receipt_key');$pairs[]=canonical($k).':'.canonical($value);}
    return '{'.implode(',',$pairs).'}';
}
function readjson(string $path): array {
    must(is_file($path)&&!is_link($path),'missing_block');
    $bytes=file_get_contents($path);must($bytes!==false&&strlen($bytes)<16384,'unreadable_block');
    $obj=json_decode($bytes,true,32,JSON_THROW_ON_ERROR);must(is_array($obj),'invalid_block_json');
    must(canonical($obj)."\n"===$bytes,'noncanonical_block');return $obj;
}
function cidpath(string $base,string $id,string $suffix='.json'): string {
    must(preg_match('/^sha256:[0-9a-f]{64}$/D',$id)===1,'bad_cid');
    return $base.'/'.substr($id,7).$suffix;
}
function mkdirsafe(string $dir): void {
    if(!is_dir($dir))must(mkdir($dir,0700,true)||is_dir($dir),'mkdir_failed');
    must(!is_link($dir),'unsafe_store_directory');
}
function writeonce(string $name,string $bytes): void {
    if(file_exists($name)){must(!is_link($name)&&is_file($name)&&file_get_contents($name)===$bytes,'existing_block_conflict');return;}
    $tmp=$name.'.tmp.'.bin2hex(random_bytes(12));
    $f=fopen($tmp,'xb');must($f!==false,'staging_failed');
    try{must(fwrite($f,$bytes)===strlen($bytes),'short_write');must(fflush($f),'flush_failed');if(function_exists('fsync'))must(fsync($f),'fsync_failed');}finally{fclose($f);}
    must(rename($tmp,$name),'rename_failed');chmod($name,0400);
}
function head(string $path): array {
    if(!file_exists($path))return ['events'=>0,'head'=>null];
    $a=readjson($path);must(isset($a['events'])&&array_key_exists('head',$a),'invalid_head');
    must(is_int($a['events'])&&$a['events']>=0&&$a['events']<=F_MAX,'invalid_head_count');
    if($a['events'])must(is_string($a['head'])&&preg_match('/^sha256:[0-9a-f]{64}$/D',$a['head'])===1,'invalid_head_digest');
    else must($a['head']===null,'invalid_empty_head');
    return $a;
}
function replacehead(string $path,array $next): void {
    $tmp=$path.'.tmp.'.bin2hex(random_bytes(12));$bytes=canonical($next)."\n";
    $f=fopen($tmp,'xb');must($f!==false,'head_stage_failed');
    try{must(fwrite($f,$bytes)===strlen($bytes),'head_short_write');must(fflush($f),'head_flush_failed');if(function_exists('fsync'))must(fsync($f),'head_fsync_failed');}finally{fclose($f);}
    must(rename($tmp,$path),'head_commit_failed');
}
function native(string $mode,string $grant,string $effect,string $root): array {
    $exe=dirname(__DIR__).'/forge-grant';must(is_file($exe),'missing_native_verifier');
    $pipes=[];$proc=proc_open([$exe,$mode,$grant,$effect,$root],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,null,['PATH'=>'/usr/bin:/bin']);
    must(is_resource($proc),'native_launch_failed');fclose($pipes[0]);$out=stream_get_contents($pipes[1]);fclose($pipes[1]);$err=stream_get_contents($pipes[2]);fclose($pipes[2]);
    $code=proc_close($proc);if($code!==0)reject('grant_or_signature_invalid',trim((string)$err));
    $v=json_decode((string)$out,true,8,JSON_THROW_ON_ERROR);
    must(is_array($v)&&($v['verified']??false)===true&&($v['schema']??'')==='forge.grant.verification.v1','native_result_invalid');return $v;
}
function history(string $dir): array {
    $h=head($dir.'/HEAD.json');$seen=[];$cur=$h['head'];$n=0;
    while($cur!==null){
        must(!isset($seen[$cur])&&$n<F_MAX,'source_history_invalid');$seen[$cur]=true;
        $row=readjson(cidpath($dir.'/blocks',$cur));
        must(($row['digest']??null)===$cur&&isset($row['body']),'source_cid_mismatch');
        must('sha256:'.hash('sha256',"FORGE/OMISSION/V3\n".canonical($row['body']))===$cur,'source_hash_invalid');
        $cur=$row['body']['parent_hash']??null;$n++;
    }
    must($n===$h['events'],'source_history_length_invalid');return [$h,$seen];
}
function effects(string $dir): array {
    $h=head($dir.'/effects/HEAD.json');$n=0;$cur=$h['head'];$used=[];$records=[];
    while($cur!==null){
        must($n<F_MAX,'effect_chain_too_long');
        $row=readjson(cidpath($dir.'/effects/blocks',$cur));
        must(($row['digest']??null)===$cur&&isset($row['body']),'effect_block_mismatch');
        must('sha256:'.hash('sha256',F_DOMAIN.canonical($row['body']))===$cur,'effect_hash_invalid');
        $body=$row['body'];must(($body['schema']??null)==='forge.effect.v1','effect_schema_invalid');
        must(!isset($used[$body['nonce']]),'double_spent_nonce_in_history');$used[$body['nonce']]=true;
        $records[]=$body;$cur=$body['parent']??null;$n++;
    }
    must($n===$h['events'],'effect_chain_length_invalid');return [$h,$used,$records];
}
function lockstore(string $dir,callable $cb): mixed {
    mkdirsafe($dir);mkdirsafe($dir.'/blocks');mkdirsafe($dir.'/effects');mkdirsafe($dir.'/effects/blocks');mkdirsafe($dir.'/effects/auth');
    $f=fopen($dir.'/LOCK','c');must($f!==false&&flock($f,LOCK_EX),'lock_failed');
    try{return $cb();}finally{flock($f,LOCK_UN);fclose($f);}
}
function pinnedRoot(string $dir): string {
    $path=$dir.'/effects/TRUST_ROOT';
    must(is_file($path)&&!is_link($path),'root_not_initialized');
    $value=file_get_contents($path);
    must($value!==false&&preg_match('/^[0-9a-f]{64}\n$/D',$value)===1,'root_pin_invalid');
    return substr($value,0,64);
}
function initRoot(string $dir,string $root): void {
    must(preg_match('/^[0-9a-f]{64}$/D',$root)===1,'invalid_root_key');
    $result=lockstore($dir,static function()use($dir,$root){
        writeonce($dir.'/effects/TRUST_ROOT',$root."\n");
        return ['schema'=>'forge.trust.v1','status'=>'pinned','root_ed25519'=>$root];
    });echo canonical($result)."\n";
}
function execute(string $grant,string $effect,string $dir): void {
    $res=lockstore($dir,static function() use($dir,$grant,$effect){
        $root=pinnedRoot($dir);
        $v=native('verify',$grant,$effect,$root);
        [$source,$known]=history($dir);[$head,$used]=effects($dir);
        must($source['head']!==null&&$v['target']===$source['head'],'source_head_mismatch');
        must(isset($known[$v['from']])&&isset($known[$v['to']]),'relation_endpoint_not_in_history');
        must(!isset($used[$v['nonce']]),'nonce_already_consumed');
        must($head['events']<F_MAX,'effect_limit_exceeded');
        $gb=file_get_contents($grant);$eb=file_get_contents($effect);
        must($gb!==false&&$eb!==false&&strlen($gb)<4096&&strlen($eb)<4096,'invalid_auth_document');
        $body=['schema'=>'forge.effect.v1','kind'=>'relation.assert','grant'=>$v['grant'],'request'=>$v['request'],'subject'=>$v['subject'],'nonce'=>$v['nonce'],'source_head'=>$v['target'],'from'=>$v['from'],'to'=>$v['to'],'parent'=>$head['head'],'seq'=>$head['events']+1];
        $digest='sha256:'.hash('sha256',F_DOMAIN.canonical($body));
        writeonce(cidpath($dir.'/effects/auth',$v['grant'],'.fg'),$gb);
        writeonce(cidpath($dir.'/effects/auth',$v['request'],'.fe'),$eb);
        writeonce(cidpath($dir.'/effects/blocks',$digest),canonical(['body'=>$body,'digest'=>$digest])."\n");
        replacehead($dir.'/effects/HEAD.json',['events'=>$body['seq'],'head'=>$digest]);
        return ['schema'=>'forge.effect.receipt.v1','status'=>'admitted','committed'=>true,'effect'=>$digest,'nonce'=>$v['nonce'],'grant'=>$v['grant'],'source_head'=>$v['target'],'seq'=>$body['seq'],'signature_verification'=>'native-ed25519'];
    });echo canonical($res)."\n";
}
function audit(string $dir): void {
    $r=lockstore($dir,static function()use($dir){
        $root=pinnedRoot($dir);
        [$source,$known]=history($dir);[$head,$used,$records]=effects($dir);
        foreach($records as $b){
            must(isset($known[$b['source_head']])&&isset($known[$b['from']])&&isset($known[$b['to']]),'orphaned_source_reference');
            $v=native('verify-history',cidpath($dir.'/effects/auth',$b['grant'],'.fg'),cidpath($dir.'/effects/auth',$b['request'],'.fe'),$root);
            must($v['nonce']===$b['nonce']&&$v['request']===$b['request']&&$v['grant']===$b['grant']&&$v['target']===$b['source_head']&&$v['from']===$b['from']&&$v['to']===$b['to'],'receipt_authorization_mismatch');
        }
        return ['schema'=>'forge.effect.audit.v1','verified'=>true,'effects'=>$head['events'],'unique_nonces'=>count($used),'head'=>$head['head'],'root_pinned'=>true];
    });echo canonical($r)."\n";
}

try {
    if($argc===4&&$argv[1]==='init-root')initRoot($argv[2],$argv[3]);
    elseif($argc===5&&$argv[1]==='become')execute($argv[2],$argv[3],$argv[4]);
    elseif($argc===3&&$argv[1]==='audit')audit($argv[2]);
    else reject('usage','init-root <store> <root_hex> | become <grant.fg> <request.fe> <store> | audit <store>');
}catch(Throwable $e){reject('internal_or_input_error',$e->getMessage());}
