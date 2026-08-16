<?php
function a($s){$p=parse_url($s);return $p&&isset($p['scheme'],$p['host'])&&in_array(strtolower($p['scheme']),['http','https'],true)&&strtolower(rtrim($p['host'],'.'))!=='flag.thjcc';}
function b($s){if(!a($s))throw new Exception();$c=stream_context_create(['http'=>['follow_location'=>false,'timeout'=>3,'ignore_errors'=>true]]);$h=@get_headers($s,false,$c);$n=null;foreach($h?:[] as $v)if(preg_match('/^Location:/i',$v)){$n=trim(substr($v,strpos($v,':')+1));break;}if($n!==null&&!a($n))throw new Exception();$c=stream_context_create(['http'=>['timeout'=>3,'ignore_errors'=>true]]);$x=@file_get_contents($s,false,$c);if($x===false)throw new Exception();return $x;}
header('Content-Type: text/plain');try{echo b($_GET['u']??'');}catch(Throwable $e){http_response_code(400);echo 'error';}
