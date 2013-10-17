#!/usr/bin/python

## 2012-03-07 : pam_transmission-bt_auth.py v0.3

## NOTES:
##  - A PAM module to authenticate against transmission-daemon settings.json files

## REQUIRES:
##  - python-simplejson
##  - libpam-python

## CLI USAGE:
##  - ./pam_transmission-bt_auth.py jsmith MyPassword

## PAM USAGE:
##  account  required  pam_python.so  /usr/local/sbin/pam_transmission-bt_auth.py  dir_home=/home  log_level=0
##  auth     required  pam_python.so  /usr/local/sbin/pam_transmission-bt_auth.py  dir_home=/home  group_name=debian-transmission  log_level=0


## DEFAULTS:
DIR_HOME = "/home"  # e.g.: "/home/jdoe/info/settings.json"
GROUP_NAME = "debian-transmission"
LOG_LEVEL = 0


## "auth"
def pam_sm_authenticate( pamh, flags, argv ):
	set_globals( argv )
	
	do_log( 9, "pam_sm_authenticate()" )
	
	try:
		username = pamh.get_user( None )
	except pamh.exception, e:
		do_log( 5, "ERROR: could not obtain username" )
		return e.pam_result
	
	if not get_user_base_dir( username ):
		do_log( 5, "ERR: invalid username: %s" % username )
		return pamh.PAM_USER_UNKNOWN
	
	try:
		x = pamh.conversation( pamh.Message( pamh.PAM_PROMPT_ECHO_OFF, "Password: " ) )
		password = x.resp
	except pamh.exception, e:
		do_log( 5, "ERR: PAM password error" )
		return e.pam_result
		
	if not password:
		do_log( 5, "ERR: blank password" )
		return pamh.PAM_AUTH_ERR
	
	if auth_user( username, password ):
		do_log( 5, "LOGIN: %s" % username )
		return pamh.PAM_SUCCESS
	
	do_log( 5, "ERR: invalid password" )
	return pamh.PAM_AUTH_ERR # FIXME: return more specific error?


## "auth"
def pam_sm_setcred( pamh, flags, argv ):
	set_globals( argv )
	
	do_log( 9, "pam_sm_setcred()" )
	
	import os
	try:
		username = pamh.get_user( None )
	except pamh.exception, e:
		return e.pam_result
	
	path_user_base_dir = get_user_base_dir( username )
	path_user_home = os.path.join( path_user_base_dir, "downloads" )
	if not os.path.isdir( path_user_home ):
		return pamh.PAM_USER_UNKNOWN
	
	global GROUP_NAME
	try:
		import grp
		gid = grp.getgrnam( GROUP_NAME )[2]
	except:
		do_log( 1, "ERROR: invalid group name: %s" % GROUP_NAME )
		return pamh.PAM_SYSTEM_ERR
	os.setgroups( [ gid ] )
	
	return pamh.PAM_SUCCESS


## "account"
def pam_sm_acct_mgmt( pamh, flags, argv ):
	set_globals( argv )
	
	do_log( 9, "pam_sm_acct_mgmt()" )
	
	try:
		username = pamh.get_user( None )
	except pamh.exception, e:
		return e.pam_result
	if get_user_base_dir( username ):
		return pamh.PAM_SUCCESS
	
	return pamh.PAM_USER_UNKNOWN


## "session"
##def pam_sm_open_session( pamh, flags, argv ):
##	set_globals( argv )
##	do_log( 5, "pam_sm_open_session()" )
##	return pamh.PAM_SYSTEM_ERR
##	return pamh.PAM_SUCCESS
##	pamh.PAM_USER_UNKNOWN ?


## "session"
##def pam_sm_close_session( pamh, flags, argv ):
##	set_globals( argv )
##	do_log( 5, "pam_sm_close_session()" )
##	return pamh.PAM_SYSTEM_ERR
##	return pamh.PAM_SUCCESS


## "password"
##def pam_sm_chauthtok( pamh, flags, argv ):
##	set_globals( argv )
##	do_log( 5, "pam_sm_chauthtok()" )
##	return pamh.PAM_AUTHTOK_ERR
##	return pamh.PAM_SUCCESS


## log to syslog ..
def do_log( level, s ):
	if level >= LOG_LEVEL:
		return
	import syslog
	syslog.openlog( logoption=syslog.LOG_PID, facility=syslog.LOG_AUTH )
	syslog.syslog( "pam_transmission-bt_auth.py(%d): %s\n" % ( level, s ) )


## set global variables from pam args ..
def set_globals( argv ):
	for arg in argv[ 1: ]:
		if arg.startswith( "log_level=" ):
			global LOG_LEVEL
			LOG_LEVEL = int( arg[ len( "log_level=" ) : ] )
		elif arg.startswith( "dir_home=" ):
			global DIR_HOME
			DIR_HOME = arg[ len( "dir_home=" ) : ]
		elif arg.startswith( "group_name=" ):
			global GROUP_NAME
			GROUP_NAME = arg[ len( "group_name=" ) : ]


## return transmission-daemon base dir  (aka: is valid user?)
def get_user_base_dir( username ):
	do_log( 9, "get_user_base_dir()" )
	
	import re
	if not re.match( "^[a-zA-Z0-9]{3,128}$", username ):
		do_log( 4, "ERROR: username contained invalid characters: %s" % username )
		return False
	
	import os
	global DIR_HOME
	path_user_base_dir = os.path.join( DIR_HOME, username )
	if not os.path.isdir( path_user_base_dir ):
		return False
	
	if os.path.isfile( os.path.join( path_user_base_dir, "disable_ftp" ) ):
		do_log( 4, "ERROR: FTP disabled for user: %s" % username )
		return False
	
	return path_user_base_dir


## do actual auth
def auth_user( username, password ):
	do_log( 9, "auth_user()" )
	
	import os
	path_user_base_dir = get_user_base_dir( username )
	if not path_user_base_dir:
		do_log( 5, "ERROR: missing user base dir: %s" % path_user_base_dir )
		return False
	
	path_settings = os.path.join( path_user_base_dir, "info/settings.json" )
	if not os.path.isfile( path_settings ):
		do_log( 5, "ERROR: missing user settings file: %s" % path_settings )
		return False
	
	try:
		import simplejson
		fp = open( path_settings, 'r' )
		json = simplejson.load( fp )
		fp.close()
		if json[ "rpc-username" ] != username:
			do_log( 5, "ERROR: username mismatch: %s != %s" ( json[ "rpc-username" ], username ) )
			return False
		return verify_password( json[ "rpc-password" ], password )
	except:
		do_log( 5, "ERROR: auth_user() json exception" )
		pass
	
	do_log( 5, "ERROR: auth_user() end" )
	return False


## hashed/cleartext password comparison
def verify_password( pass_token, pass_clear ):
	do_log( 9, "verify_password()" )
	
	if pass_token[0] == "{":
		# hashed password
		import hashlib
		h = hashlib.sha1( pass_clear )
		h.update( pass_token[-8:] ) # trailing 8-byte salt hex
		return pass_token[1:-8] == h.hexdigest()
	else:
		# cleartext password
		return pass_token == pass_clear


def main():
	import os
	import sys
	
	if len( sys.argv ) != 3:
		sys.stderr.write( "Usage: %s <username> <password>\n" % sys.argv[ 0 ] )
		sys.exit( 2 )
	
	if auth_user( sys.argv[1], sys.argv[2] ):
		print "success"
		sys.exit( 0 )
	else:
		print "failed"
		sys.exit( 1 )


if __name__ == '__main__':
	main()
