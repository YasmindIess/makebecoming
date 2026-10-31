#!/usr/bin/env php
<?php
/**
 * Chapter 8: local, append-only read-only autonomous proposal records.
 * Never issues grants, consumes authorization nonces, or commits effects.
 * SOURCE observations MUST be the verified existing local Forge store.
 */
declare(strict_types=1);
umask(0077);
const P_DOMAIN = "FORGE/PROPOSAL/V1\n";
const SOURCE_DOMAIN = "FORGE/OMISSION/V3\n";
const P_LIMIT = 250;
function abort_plan(string $why): never {fwrite(STDERR,"FORGE PROPOSAL REJECTED: $why\n");exit(2);}
function need_plan(bool $ok,string $why): void {if(!$ok)abort_plan($why);}
function iscid(mixed $v): bool {return is_string($v)&&preg_match('/^sha256:[0-9a-f]{64}$/D',$v)===1;}
function canonical_plan(mixed $v): string {
    if($v===null)return 'null';
    if(is_bool($v))return $v?'true':'false';
    if(is_int($v))return (string)$v;
    if(is_string($v))return json_encode($v,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
    need_plan(is_array($v),'unsupported source type');
    if(array_is_list($v))return '['.implode(',',array_map('canonical_plan',$v)).']';
    ksort($v,SORT_STRING);$parts=[];
    foreach($v as $k=>$item){need_plan(is_string($k)&&preg_match('/^[a-z0-9_]+$/D',$k)===1,'unsupported record field');$parts[]=canonical_plan($k).':'.canonical_plan($item);}
    return '{'.implode(',',$parts).'}';
}
function read_plan_json(string $file): array {
    need_plan(is_file($file)&&!is_link($file),'missing or unsafe record');
    $bytes=file_get_contents($file);need_plan($bytes!==false&&strlen($bytes)<100000,'record oversized');
    $v=json_decode($bytes,true,32,JSON_THROW_ON_ERROR);need_plan(is_array($v),'record invalid');
    return $v;
}
function immutable_plan(string $path,string $bytes): void {
    if(file_exists($path)){need_plan(!is_link($path)&&file_get_contents($path)===$bytes,'immutable block conflict');return;}
    $tmp=$path.'.tmp.'.bin2hex(random_bytes(10));$f=fopen($tmp,'xb');need_plan($f!==false,'stage error');
    try{need_plan(fwrite($f,$bytes)===strlen($bytes),'short write');need_plan(fflush($f),'flush failed');if(function_exists('fsync'))need_plan(fsync($f),'fsync failed');}finally{fclose($f);}
    need_plan(rename($tmp,$path),'rename failed');chmod($path,0400);
}
function update_plan_head(string $path,array $head): void {
    $tmp=$path.'.tmp.'.bin2hex(random_bytes(10));$raw=canonical_plan($head)."\n";
    $f=fopen($tmp,'xb');need_plan($f!==false,'head stage error');
    try{need_plan(fwrite($f,$raw)===strlen($raw),'head write failed');need_plan(fflush($f),'head flush failed');if(function_exists('fsync'))need_plan(fsync($f),'head fsync failed');}finally{fclose($f);}
    need_plan(rename($tmp,$path),'head replace failed');
}
function walk_source(string $store): array {
    $h=read_plan_json($store.'/HEAD.json');need_plan(isset($h['events'],$h['head'])&&iscid($h['head'])&&is_int($h['events'])&&$h['events']>=2&&$h['events']<=P_LIMIT,'invalid source head');
    $rows=[];$cur=$h['head'];$seen=[];
    while($cur!==null){
        need_plan(iscid($cur)&&!isset($seen[$cur])&&count($rows)<P_LIMIT,'bad source parent');$seen[$cur]=true;
        $r=read_plan_json($store.'/blocks/'.substr($cur,7).'.json');
        need_plan(($r['digest']??null)===$cur&&is_array($r['body']??null),'source CID mismatch');
        need_plan('sha256:'.hash('sha256',SOURCE_DOMAIN.canonical_plan($r['body']))===$cur,'source content modified');
        $rows[]=$r;$cur=$r['body']['parent_hash']??null;
    }
    need_plan(count($rows)===$h['events'],'source length mismatch');$rows=array_reverse($rows);
    foreach($rows as $i=>$row)need_plan(($row['body']['seq']??null)===$i+1,'source sequence invalid');
    return [$h,$rows];
}
function walk_proposals(string $store): array {
    $path=$store.'/proposals/HEAD.json';
    if(!is_file($path))return [['count'=>0,'head'=>null],[]];
    $h=read_plan_json($path);need_plan(is_int($h['count']??null)&&$h['count']>=0&&$h['count']<=P_LIMIT,'proposal head invalid');
    $records=[];$cur=$h['head']??null;$used=[];
    while($cur!==null){
        need_plan(iscid($cur)&&!isset($used[$cur])&&count($records)<P_LIMIT,'proposal cycle');$used[$cur]=true;
        $row=read_plan_json($store.'/proposals/records/'.substr($cur,7).'.json');
        need_plan('sha256:'.hash('sha256',P_DOMAIN.canonical_plan($row))===$cur,'proposal chain tampered');
        $proposal=$row['proposal']??null;need_plan(iscid($proposal),'proposal reference invalid');
         $block_path=$store.'/proposals/blocks/'.substr($proposal,7).'.json';
        need_plan(is_file($block_path)&&!is_link($block_path),'missing proposal block');
        $raw=file_get_contents($block_path);
        need_plan(is_string($raw)&&strlen($raw)<100000,'invalid proposal block');
        need_plan('sha256:'.hash('sha256',P_DOMAIN.$raw)===$proposal,'proposal block tampered');
        $plan=json_decode($raw,true,32,JSON_THROW_ON_ERROR);
        need_plan(($plan['source_head']??null)===$row['source_head']&&($plan['reconciliation']['authorized']??null)===false&&($plan['reconciliation']['effect_committed']??null)===false,'proposal policy mismatch');
        $records[]=$row;$cur=$row['parent']??null;
    }
    need_plan(count($records)===$h['count'],'proposal chain length mismatch');return [$h,$records];
}
function run_native_plan(array $rows): string {
    $temp=tempnam(sys_get_temp_dir(),'forge-plan-');need_plan(is_string($temp),'cannot stage source');
    try{
        $bytes='';foreach($rows as $r)$bytes.=canonical_plan($r)."\n";
        need_plan(file_put_contents($temp,$bytes)===strlen($bytes),'cannot write staging records');
        $exe=dirname(__DIR__).'/forge-kernel';need_plan(is_executable($exe),'forge-kernel not built');
        $proc=proc_open([$exe,'minima',$temp],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,null,['PATH'=>'/usr/bin:/bin']);
        need_plan(is_resource($proc),'native planner unavailable');fclose($pipes[0]);$out=stream_get_contents($pipes[1]);fclose($pipes[1]);$err=stream_get_contents($pipes[2]);fclose($pipes[2]);
        need_plan(proc_close($proc)===0,'native planner rejected source: '.trim((string)$err));
        $p=json_decode((string)$out,true,32,JSON_THROW_ON_ERROR);
        need_plan(($p['schema']??null)==='forge.confluence.v1'&&($p['reconciliation']['authorized']??null)===false&&($p['reconciliation']['effect_committed']??null)===false,'unsafe planner result');
        return (string)$out;
    }finally{unlink($temp);}
}
function run_proposal(string $store,string $command): void {
    need_plan(is_dir($store)&&!is_link($store),'local evidence store missing');
    $lock=fopen($store.'/LOCK','c');need_plan($lock!==false&&flock($lock,LOCK_EX),'cannot lock store');
    try{
        [$h,$rows]=walk_source($store);[$ph,$records]=walk_proposals($store);
        if($command==='audit'){
            echo canonical_plan(['schema'=>'forge.proposal.audit.v1','verified'=>true,'proposals'=>$ph['count'],'head'=>$ph['head'],'source_head'=>$h['head'],'effects_created_by_planner'=>0])."\n";
            return;
        }
        need_plan($command==='plan','unknown command');
        $out=run_native_plan($rows);$p=json_decode($out,true,32,JSON_THROW_ON_ERROR);
        need_plan($p['source_head']===$h['head'],'source changed during planning');
        $proposal='sha256:'.hash('sha256',P_DOMAIN.$out);
        if($records&&($records[0]['source_head']??null)===$h['head']){
            need_plan(($records[0]['proposal']??null)===$proposal,'non-deterministic plan for current head');
            echo canonical_plan(['schema'=>'forge.proposal.receipt.v1','status'=>'already-proposed','new_records'=>0,'proposal'=>$proposal,'source_head'=>$h['head'],'effect_committed'=>false])."\n";return;
        }
        need_plan($ph['count']<P_LIMIT,'proposal limit reached');
        foreach(['proposals','proposals/blocks','proposals/records'] as $dir){$path=$store.'/'.$dir;if(!is_dir($path))need_plan(mkdir($path,0700,true),'mkdir failed');need_plan(!is_link($path),'unsafe proposal directory');}
        immutable_plan($store.'/proposals/blocks/'.substr($proposal,7).'.json',$out);
        $rec=['schema'=>'forge.proposal.record.v1','seq'=>$ph['count']+1,'source_head'=>$h['head'],'proposal'=>$proposal,'parent'=>$ph['head']];
        $id='sha256:'.hash('sha256',P_DOMAIN.canonical_plan($rec));
        immutable_plan($store.'/proposals/records/'.substr($id,7).'.json',canonical_plan($rec)."\n");
        update_plan_head($store.'/proposals/HEAD.json',['count'=>$ph['count']+1,'head'=>$id]);
        echo canonical_plan(['schema'=>'forge.proposal.receipt.v1','status'=>'proposed','new_records'=>1,'proposal'=>$proposal,'record'=>$id,'source_head'=>$h['head'],'candidate'=>$p['reconciliation']['candidate'],'effect_committed'=>false])."\n";
    }finally{flock($lock,LOCK_UN);fclose($lock);}
}
try{need_plan($argc===3,'Usage: forge-proposals.php plan|audit <local-store>');run_proposal($argv[2],$argv[1]);}
catch(Throwable $e){abort_plan($e->getMessage());}