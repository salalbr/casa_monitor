#!/usr/bin/python

''' casa_monitor.py - Tool for querying ATS server and validating auth token '''

__author__ = 'Maer Melo'
__license__ = 'Apache License, Version 2.0'
__version__ = '0.1'
__email__ = 'salalbr@gmail.com'

import sys, urllib2, os, re, base64
from time import strftime, localtime

def parse_conf(conf_file):
  if os.path.isfile(conf_file):
    f = open(conf_file, 'rU')
    options = {}
    for line in f.readlines():
      if line[0] == '/' or line[0] == '#' or line[0] == '\n':
        pass
      else:
        property, value = line.split('=')
        if property == 'server':
          if 'server' not in options.keys():
            options['server'] = []
          options['server'].append(value.rstrip())
        else:
          options[property] = value.rstrip()
    f.close()
    return options

def watcher(options, polling=300):
  from time import sleep
  if 'polling_time' in options.keys(): polling = float(options['polling_time'])
  while(1):
    num_of_servers = len(options['server'])
    for i in range(num_of_servers):
      params = { 'server': options['server'][i],\
                 'port': options['port'],\
                 'realm': options['realm'],\
                 'username': options['username'],\
                 'password': options['password'] }
      (sts, token) = check_authpolicy(params)
      if sts == False:
        logger( { 'server': params['server'], 'status': 'unavailable', 'error': 'AuthPolicy' } )
      else:
        (sts, session_token) = check_sessiontoken(params)
        if sts == False:
          logger( { 'server': params['server'], 'status': 'unavailable', 'error': 'SessionToken' } )
        else:
          params['sessiontoken'] = session_token
          (sts, token) = check_authtoken(params)
          if sts == False:
            logger( { 'server': params['server'], 'status': 'unavailable', 'error': 'AuthToken' } )
          else:
            logger( { 'server': params['server'], 'status': 'available' } )
    sleep(polling)
      
def logger(result, log_file='monitor_casa.log'):
  f = open(log_file, 'a+b')
  if result['status'] == 'unavailable':
    print '[ ' + strftime("%d %b %Y %H:%M:%S", localtime()) + ' ]  [ ' + result['server'] + ' is '\
          + result['status'] + ': Error while getting ' + result['error'] + ' ]'
    f.write('[ ' + strftime("%d %b %Y %H:%M:%S", localtime()) + ' ]  [ ' + result['server'] + ' is '\
          + result['status'] + ': Error while getting ' + result['error'] + ' ]\n')
  else:
    f.write('[ ' + strftime("%d %b %Y %H:%M:%S", localtime()) + ' ]  [ ' + result['server'] + ' is '\
          + result['status'] + ' ]\n')
  '''
  f.write('[ ' + strftime("%d %b %Y %H:%M:%S", localtime()) + ' ]  [ ' + server + ' is ' + result + ' ]\n')
  if result == 'unavailable':
    print '[ ' + strftime("%d %b %Y %H:%M:%S", localtime()) + ' ]  [ ' + server + ' is ' + result + ' ]'
  '''
  
def check_authpolicy(options):
  url = 'https://' + options['server'] + ':' + options['port']  + '/CasaAuthTokenSvc/Rpc?method=GetAuthPolicy'
  rpc_call = '<?xml version="1.0" encoding="ISO-8859-1"?>\n<get_auth_policy_req>\n<service>com.novell.zenworks.'\
             + options['realm'] + '</service>\n<host>localhost</host>\n</get_auth_policy_req>'
  request =  urllib2.Request(url, rpc_call)
  request.add_header('Content-Type', 'text/xml')
  try:
    auth_policy_out = urllib2.urlopen(request).read()
    auth_policy = re.findall(r'<auth_policy>(.+)<\/auth_policy>', auth_policy_out)[0]
    auth_policy = base64.b64decode(auth_policy)
    if '<mechanism>PwdAuthenticate</mechanism>' in auth_policy:
      return (True, auth_policy)
  except urllib2.URLError, e:
    return (False, None)
  
def check_sessiontoken(options):
  url = 'https://' + options['server'] + ':' + options['port']  + '/CasaAuthTokenSvc/Rpc?method=Authenticate'
  rpc_call = '<?xml version="1.0" encoding="ISO-8859-1"?>\n<auth_req>\n<realm>'\
             + options['realm'] + '</realm>\n<mechanism>PwdAuthenticate</mechanism>\n<auth_mech_token>'\
             + generate_mech_token(options) + '</auth_mech_token>\n</auth_req>'
  request =  urllib2.Request(url, rpc_call)
  request.add_header('Content-Type', 'text/xml')
  try:
    session_token_out = urllib2.urlopen(request).read()
    session_token = re.findall(r'<\/lifetime>(.+)<\/session_token>', session_token_out)[0]
    session_token = base64.b64decode(session_token)
    if all(item in session_token_out for item in ['OK', '200', 'lifetime', '<auth_resp>']):
      return (True, session_token)
  except urllib2.URLError, e:
    return (False, None)
  
def check_authtoken(options):
  if 'sessiontoken' not in options.keys():
    return (False, None)
  url = 'https://' + options['server'] + ':' + options['port']  + '/CasaAuthTokenSvc/Rpc?method=GetAuthToken'
  rpc_call = '<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<get_auth_tok_req>\n<service>com.novell.zenworks.'\
             + options['realm'] + '</service>\n<host>localhost</host>\n<session_token>'\
             + base64.b64encode(options['sessiontoken']) + '</session_token>\n</get_auth_tok_req>'
  request =  urllib2.Request(url, rpc_call)
  request.add_header('Content-Type', 'text/xml')
  try:
    auth_token_out = urllib2.urlopen(request).read()
    auth_token = re.findall(r'<\/lifetime>(.+)<\/auth_token>', auth_token_out)[0]
    auth_token = base64.b64decode(auth_token)
    if all(item in auth_token_out for item in ['OK', '200', 'lifetime', '<get_auth_tok_resp>']):
      return (True, auth_token)
  except urllib2.URLError, e:
    return (False, None)
  
def generate_mech_token(options):
  credentials = str.encode(options['username'] + '\r\n' + options['password'] + '\r\n')
  mech_token = base64.b64encode(credentials)
  return mech_token
  
def main():
  args = sys.argv[1:]
  if not len(args):
    print 'casa_monitor.py - usage:\n _____(standalone mode): monitor_casa.py <ip_address/hostname> <port> <realm> <username> <password> [--verbose]'
    print ' _____(monitoring mode): monitor_casa.py --conf <conf_file>'
  elif args[0] == '--conf':
    options = parse_conf(args[1])
    watcher(options)
  else:
    options = { 'server': args[0],
                'port': args[1],
                'realm': args[2],
                'username': args[3],
                'password': args[4] }
    if '--verbose' in args: options['verbose'] = True

    # Get Auth Policy    
    (sts_auth_policy, auth_policy) = check_authpolicy(options)
    if sts_auth_policy == True:
      print '[ ' + strftime("%d %b %Y %H:%M:%S", localtime()) + ' ]  [ ' + options['server'] + ' / GetAuthPolicy: success ]'
      if 'verbose' in options.keys():
        print auth_policy, '\n'
    else:
      print '[ ' + strftime("%d %b %Y %H:%M:%S", localtime()) + ' ]  [ ' + options['server'] + ' / GetAuthPolicy: failed ]'
      return 1
    
    # Get Session Token
    (sts_session_token, session_token) = check_sessiontoken(options)
    if sts_session_token == True:
      options['sessiontoken'] = session_token
      print '[ ' + strftime("%d %b %Y %H:%M:%S", localtime()) + ' ]  [ ' + options['server'] + ' / GetSessionToken: success ]'
      if 'verbose' in options.keys():
        print session_token, '\n'
    else:
      print '[ ' + strftime("%d %b %Y %H:%M:%S", localtime()) + ' ]  [ ' + options['server'] + ' / GetAuthPolicy: failed ]'
      return 1
    
    # Get Auth Token
    (sts_auth_token, auth_token) = check_authtoken(options)
    if sts_auth_token == True:
      print '[ ' + strftime("%d %b %Y %H:%M:%S", localtime()) + ' ]  [ ' + options['server'] + ' / GetAuthToken: success ]'
      if 'verbose' in options.keys():
        print auth_token, '\n'
    else:
      print '[ ' + strftime("%d %b %Y %H:%M:%S", localtime()) + ' ]  [ ' + options['server'] + ' / GetAuthToken: failed ]'
      return 1

if __name__ == '__main__':
  main()
