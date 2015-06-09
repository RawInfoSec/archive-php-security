<?php

	// security.inc.php
	// 20100426 Kevin Creechan kev@silicon-vision.com
	//	
	// Not every site runs under the protection of Mod_Security or the likes.  PHP's security.inc should be placed near the top of your stack for every page load, as long as a session is started and a database is available for token storage, the rest of the page load will be protected and tokenized.
	//
	// How it works:
	// 
	// 		- start session, start DB connect, then load security.inc
	//		- For any front-end jQuery calls to back-end functionality that you want protected, use a SetToken call to create a token for that particular link.
	//			eg: $mytoken=setToken("thelockname",0);
	//		- For any back-end functionality called from front-end jQuery calls, use a RequireToken call to ensure the appropriate SetToken has been sent from the server.
	//			eg: requireToken("thelockname", $mytoken);
	//		- I have included a Permission checking system as well which looks up a permissions table to see whether or not the user is even allowed. You would have to adjust these functions to your own needs or simply don't use them :)
	// 
	// 
	//		This include file will also:
	//			1) Sanitizing ALL POST and GET arrays before any other code gets to deal with them
	//			2) Blocks known bad user-agents belonging to stock-compilations of widely used vulnerability scanners
	//	
	//		**MUST HAVE 1) session started, 
	//				and 2) SQL connection established
	//	
	//	
	// You can test this system by passing it:
	//		?id=test<>''`/-0x22-\|+UNION()@--*2^~
	// 
	// output should be:
	//		test\'\'`/-22-\\| ()@*2^~
	//
	// Usage
	//	
	// 		setToken("thelockname", duration)
	// 			- duration is in minutes, but is 5 seconds when set to 0
	//			- run from a php file which is about to call a jQuery POST command, (returned value should be sent as a token to the black box)
	//
	//		requireToken("thelockname", token)
	//			- run by a blackbox, gets passed the token via POST request and returns a value
	//			- also checks that the passed key exists in the session variable for this particular lock
	//			- first cleans out expired keys before doing anything else
	//			- returns 0 (=key NOT found), or 1 (=key found)
	//
	//			
	
	// this starts things up.
	security_init();
	
	//  Disabled the permission checker as it is an additional system.
	//$permcheck=requirePerms($requiredPerms,$perm_storeId,$perm_exittype);
	
	
	// ----------------------------------------------------------------------------------------------------------------
	// ----------------------------------------------------------------------------------------------------------------
	// ----------------------------------------------------------------------------------------------------------------
	// ----------------------------------------------------------------------------------------------------------------
	// ----------------------------------------------------------------------------------------------------------------	

	
	// First and foremost, since Junior dev's forget to, lets force sanitize all POST and GET data before they get a chance to work with it.
	function security_init(){
		user_agent_filter();
		if ($_GET) { $_GET=sanitize_global($_GET); }
		if ($_POST) { $_POST=sanitize_global($_POST); }
	}

	// this won't block private scanners or existing ones that have their UA tampered with, but will cover low-hanging-fruit
	function user_agent_filter() { 
		$forbidden_ua_strings=array('/Nikto/i','/sqlmap/i','/Havij/i','/libwww-perl/i');  // list of malicious scanners
		$ua = $_SERVER['HTTP_USER_AGENT'];
		$uam=(preg_replace($forbidden_ua_strings,'',$ua));
		if ($ua!=$uam) {
			echo "WARNING: Fatal Error: 'SECURITY-UAF-001', contact administrator.";
			exit(); // kill the output right here… these user agents are known vulnerability scanners
		}
	}
	
	// this will clean up POST and GET variables BEFORE any other code can run
	function sanitize_global($var) { 
		foreach($var as $key => $val) {
			
			// first check if the server has magic_quotes enabled, and only addslashes if it is not. This prevents double addslashes!
				if (!get_magic_quotes_gpc()) {		
					$var[$key]=addslashes($var[$key]);
				}		
			
			// the next line is a no-brainer….
				if (is_string($var[$key])) {
					$var[$key]=strip_tags($var[$key], ENT_QUOTES);		
				}
			
			// kill some extra stuff that may not be caught at the server level (for instance, if a website is moved to another host with no or badly configured mod_security setup.
				$forbidden_global_strings=array('/0x/i','/UNION/i','/--/','/%/i');
				$var[$key]=preg_replace($forbidden_global_strings, '', $var[$key]);
			
			}
		return $var;
	}
	
	// search array for a string
	function grep_array($input, $search_value, $strict = false){
		$tmpkeys = array();
		$keys = array_keys($input);
		foreach ($keys as $k)
		{
			if ($strict && strpos($k, $search_value) !== FALSE)
				$tmpkeys[] = $k;
			elseif (!$strict && stripos($k, $search_value) !== FALSE)
				$tmpkeys[] = $k;
		}
		return $tmpkeys;
	}
	
	function setToken($lock,$duration=0) {	
		// clean out expired tokens
		$sql="DELETE from security_tokens WHERE expires<".time().";";
		$result=mysql_query($sql);
		// now set up the token stuff...
		$session=session_id();
		$salt='82c00d1bd7s6f4445b3e7e144bfc5x04c70f27fa8cat0bcd936c6en53c8f18e5867a'.$session;
		
		$rndpart=MD5(substr(MD5(date('Y-m-d H:i:s')),rand(1,5),rand(15,20)));
		$token=MD5($salt.$rndpart);
		if ($duration==0) { $expires=time()+5; } else { $expires=time()+($duration*60); }
		$sql="INSERT INTO security_tokens (token, expires, lockid, sessionid) VALUES ('$token','$expires','$lock','$session');";
		$result=mysql_query($sql);
		if (mysql_errno()==0) { $_SESSION['sec_'.$lock]=$token; return $token; } else { return 0; }
	}
	
	function requireToken($lock, $token) {
		// clean out expired tokens
		$sql="DELETE from security_tokens WHERE expires<".time().";";
		$result=mysql_query($sql);
		// now see if the token actually exists for this session
		$session=session_id();
		$sql="SELECT token FROM security_tokens WHERE expires>".time()." AND sessionid='$session' AND lockid='$lock' AND token='$token';";
		$result=mysql_query($sql);
		$token=mysql_fetch_object($result)->token;
		if ($_SESSION['sec_'.$lock]==$token AND mysql_num_rows($result)>=1) { return 1; } else { return 0; }
	}
	
	
	// getPermArray simply returns an array of permissions that the currently logged in user has.
	// This can be used for more in-depth permission checking and validation that the umbrella function requirePerms() covers.
	//
	function getPermArray(){
		$userId=$_SESSION['idUser'];
		$permarray=array();
		$sql="SELECT idPermission, PermissionDefinition.idPermissionType, isAdmin, PermissionDefinition.value FROM Permissions JOIN PermissionDefinition ON Permissions.idPermissionType=PermissionDefinition.idPermissionType WHERE idUser=".$userId.";";
		$result=mysql_query($sql);
		$rows=mysql_num_rows($result);
		for ($i = 0; $i < $rows; $i++){
			$data = mysql_fetch_object($result);
			$permarray[$data->idPermission]['PermissionDefinition']=$data->PermissionDefinition;
			$permarray[$data->idPermission]['idPermissionType']=$data->idPermissionType;
			$permarray[$data->idPermission]['isAdmin']=$data->isAdmin;
			$permarray[$data->idPermission]['value']=$data->value;
		}
		return $permarray;
	}
	
	
	// requirePerms() will ensure that the currently logged-in user has the permissions for performing a requested task
	// this function is called by part of the Security Init script at bottom of this file.
	// The function may also be called on demand and allows an exit-type to be set so as to allow custom code in a page
	// to do further permission checking.
	// 
	// The default return value is TRUE if requested permission is available for the user.
	// The default return value is FALSE if requested permission is missing for the user and the exit-type is set to 5.
	// Most other exit types do not return a value and deal with killing the request themselves.
	// 
	// exit types are as follows:
	//		0 (default) - Clean exit with no output (useful for killing getlists and getimages without
	//						throwing an errors in the JSON data interpretation. 
	// 		1			- send a script tag back with a comment explaining the permission failure (INFO feedback)
	//		2			- send back a jSON 'answer=0'
	//		3			- send back a jSON 'errors=1'
	//		4			- throw the user back to their dash board
	//		5			- return FALSE to the $permcheck variable used to call requireperms
	//
	function requirePerms($permlist, $storeId=0, $exittype=0) {
		$userId=$_SESSION['idUser'];
		// if no array is passed, don't check for any permission items
		if (is_array($permlist)) {
			$killattempt=0;
			
			if (isset($_SESSION['idUser'])) {		
				foreach ($permlist as $value) {
					$sql="SELECT * FROM Permissions JOIN PermissionDefinition ON Permissions.idPermissionType=PermissionDefinition.idPermissionType WHERE idUser=".$userId." AND PermissionDefinition.value='".$value."' ".$additionalcheck.";";
					$result=mysql_query($sql);
						if (!$rows=mysql_num_rows($result)) {
							$killattempt=1;
						}
				}
			} else {
				$killattempt=1;
			}
			
			if($killattempt==1){
				switch ($exittype){
					case 0:
						exit();
						break;
					case 1:
						echo "<script>// Error : Permission failure.</script>";
						exit();
						break;
					case 2:
						$item['answer']=0;
						echo json_encode($item);
						exit();
						break;
					case 3:
						$item['errors']=1;
						echo json_encode($item);
						exit();
						break;			
					case 4:
						echo "<script>window.location='/dashboard.php';</script>";
						exit();
						break;
					case 5:
						return false;
						break;
					default:
						exit();
						break;
				}
			}else{
				return true;
			}
		}
	}

?>