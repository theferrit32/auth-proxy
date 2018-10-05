import re
import json
import uuid
import os
import base64
from flask import Flask, request, make_response, session
import requests


import logging

# These two lines enable debugging at httplib level (requests->urllib3->http.client)
# You will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
# The only thing missing will be the response.body which is not logged.

try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client
http_client.HTTPConnection.debuglevel = 1
# You must initialize logging, otherwise you'll not see debug output.
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

# Configs only loaded at startup
#TODO jsonschema would be better
required_configs_strings = [
    'auth_service_key',
    'default_proxy_destination',
    'whitelist',
    'validate_url',
    'auth_url'
]
with open('config.json') as f:
    config = json.load(f)
    for s in required_configs_strings:
        if s not in config:
            raise RuntimeError('config.json must have field [{}]'.format(s))
app = Flask(__name__, static_url_path='/static/')
if config.get('secret_key', None):
    app.secret_key = config['secret_key'].encode('utf-8')
else:
    app.secret_key = base64.b64encode(os.urandom(24))
auth_service_key = config['auth_service_key']
whitelist = config['whitelist']
if os.getenv('OAUTH_WHITELIST'):
    whitelist = os.getenv('OAUTH_WHITELIST')
    try:
        whitelist = json.loads(whitelist)
    except json.JSONDecodeError as e:
        whitelist = [whitelist]
# due to pivot constraint, convert any instances of %at% to @
for w in whitelist.copy():
    whitelist.remove(w)
    whitelist.append(w.replace('%at%', '@').lower())

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
def index(path):
    print('\n\nindex path: ' + str(path))
    
    if 'Authorization' in request.headers:
        print('authorization header found')
        m = re.match(r'^Bearer\W+(\w+)', request.headers['Authorization'])
        if m:
            token = m.group(1)
        else:
            return ('Invalid authorization', 401)
    elif 'access_token' in request.args:
        token = request.args.get('access_token')
        #print('access_token was in request params: [{}]'.format(token))
    elif 'sess_token' in session:
        #print('token was in request cookies')
        token = str(session['sess_token'])
        if isinstance(token, bytes): # sometimes needed
            token = token.decode('utf-8')
        return do_proxy(path)
    else:
        return do_reauth()
        #return ('Missing authorization', 401)
    session['sess_token'] = token
    validate_url = config['validate_url'].format(token=token)
    print('validating token with url: [{}]'.format(validate_url))
    resp = requests.get(validate_url)
    if resp.status_code >= 300:
        return (
            'Status {} returned from auth service '.format(resp.status_code),
            500
        )
    body = json.loads(resp.content.decode('utf-8'))
    
    if body.get('active', False) == True:
        # check response user against whitelist
        fields_to_check = ['user_name', 'username', 'email']
        for field in fields_to_check:
            if field in body and body[field].lower() in whitelist:
                ret = do_proxy(path)
                return ret
    else:
        print('token validation to [{}] failed, returned status [{}]: {}'.format(
            validate_url, resp.status_code, body
        ))
        return do_reauth()
    print('user was not whitelisted, response: {}'.format(body))
    return do_reauth()

def do_reauth():
    auth_url = config['auth_url']
    auth_url += '&return_to=' + request.url
    resp = requests.get(auth_url, headers={
        'Authorization': 'Basic ' + auth_service_key
    })
    body = json.loads(resp.content.decode('utf-8'))
    redirect_url = body['authorization_url']
    print('redirecting to login: ' + redirect_url)
    return ('Redirecting to login', 302, {'Location': redirect_url})

# returns make_response('content', status_code)
# doesn't forward any client headers to destination, but does 
# forward Content-Type back to client from destination
def do_proxy(path=None):
    method = request.method
    allow_redirects = False
    if path and path[0] != '/':
        path = '/' + path
    PROXY_DESTINATION = config['default_proxy_destination']
    if path:
        PROXY_DESTINATION += path
    print('requesting proxied file: ' + str(PROXY_DESTINATION))
    #TODO handle request methods other than GET
    req_headers = {}
    to_forward = ['content-type', 'location', 'cookie']
    for k,v in request.headers:
        if k.lower() in to_forward:
            print('request header: [{}: {}]'.format(k, v))
            req_headers[k] = v
    if method == 'GET':
        print('doing GET: ' + PROXY_DESTINATION)
        resp = requests.get(
            PROXY_DESTINATION,
            headers=req_headers,
            allow_redirects=allow_redirects,
            params=request.args,
            cookies=request.cookies)
    elif method == 'POST':
        print('doing POST: ' + PROXY_DESTINATION)
        print('post data: ' + str(request.form))
        print('post args: ' + str(request.args))
        resp = requests.post(
            PROXY_DESTINATION,
            headers=req_headers,
            allow_redirects=allow_redirects,
            params=request.args,
            data=request.form,
            cookies=request.cookies)
    elif method == 'PUT':
        print('doing PUT: ' + PROXY_DESTINATION)
        print(str(vars(request)))
        for val in request.form:
            print('put data val: ' + str(val))
        #print('put data: ' + str(request.form))
        print('put args: ' + str(request.args))
        #print('put cookies: ' + str(request.cookies))
        resp = requests.put(
            PROXY_DESTINATION,
            headers=req_headers,
            allow_redirects=allow_redirects,
            params=request.args,
            data=request.form,
            #cookies=request.cookies
        )
    elif method == 'DELETE':
        resp = requests.delete(PROXY_DESTINATION,
            headers=req_headers,
            allow_redirects=allow_redirects,
            params=request.args,
            #cookies=request.cookies
        )
    else:
        raise RuntimeError('Invalid proxy request method')
    # construct response
    ret = make_response(resp.content, resp.status_code)
    #print('response cookies: ' + str(resp.cookies))
    for c in resp.cookies:
        print('response cookie [{}: {}]'.format(c.name, c.value))
        ret.set_cookie(c.name, c.value)
    #headers = {}
    #for h_key in resp.headers:
    #    headers[h_key.lower()] = resp.headers[h_key]
    # list of response headers from destination to forward back to requester
    #to_forward = ['Content-Type', 'Location', 'Cookie']
    #for h in to_forward:
    #    if h.lower() in headers:
    #        print('setting response header [{}={}]'.format(h, headers[h.lower()]))
    #        ret.headers[h] = headers[h.lower()]
    for h_key in resp.headers:
       ret.headers[h_key] = resp.headers[h_key]
    return ret


if __name__ == '__main__':
    app.run(port=int(config.get('flask_port', 5000)))
