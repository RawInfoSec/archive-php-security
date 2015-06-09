#OLD CODE.  Please do not implement!
## This is for archival purposes only. Tokens have become a web standard and are available in many MVC's
### Feel free to use the other features, such as auto-sanitization of POST/GET vars, or the blocking of many scanning tools etc.

# security.inc.php
#### 20100426 Kevin Creechan kev@silicon-vision.com
###### 20150609 Kevin Creechan is now kevin@rawinfosec.com
	
Not every site runs under the protection of Mod_Security or the likes.  PHP's security.inc should be placed near the top of your stack for every page load, as long as a session is started and a database is available for token storage, the rest of the page load will be protected and tokenized.

#### How it works:

		- start session, start DB connect, then load security.inc
		- all POST & GET variables automagically sanitized
		- all scanner-type user-agents are blocked
		- For any front-end jQuery calls to back-end functionality that you want protected, use a SetToken call to create a token for that particular link.
			eg: $mytoken=setToken("thelockname",0);
		- For any back-end functionality called from front-end jQuery calls, use a RequireToken call to ensure the appropriate SetToken has been sent from the server.
			eg: requireToken("thelockname", $mytoken);
		- I have included a Permission checking system as well which looks up a permissions table to see whether or not the user is even allowed. You would have to adjust these functions to your own needs or simply don't use them :)


#### This include file will also:
	1) Sanitizing ALL POST and GET arrays before any other code gets to deal with them
	2) Blocks known bad user-agents belonging to stock-compilations of widely used vulnerability scanners
	
### MUST HAVE 

1) session started, 
2) SQL connection established
	
	
### You can test this system by passing it:
		?id=test<>''`/-0x22-\|+UNION()@--*2^~
###output should be:
		test\'\'`/-22-\\| ()@*2^~

### Usage
	
#####		setToken("thelockname", duration)
			- duration is in minutes, but is 5 seconds when set to 0
			- run from a php file which is about to call a jQuery POST command, (returned value should be sent as a token to the black box)

#####		requireToken("thelockname", token)
			- run by a blackbox, gets passed the token via POST request and returns a value
			- also checks that the passed key exists in the session variable for this particular lock
			- first cleans out expired keys before doing anything else
			- returns 0 (=key NOT found), or 1 (=key found)

	
