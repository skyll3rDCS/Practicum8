from flask import Flask, jsonify, abort,  request
import binascii
import json
import os
import hashlib
import datetime
from hashlib import sha256
users = []
app = Flask(__name__)

try:
    with open('users.json', 'r') as js_file:
        users = json.load(js_file)
except FileNotFoundError:
    with open('users.json', 'w') as js_file:
        json.dump(users, js_file)

def js_load(users):
    with open('users.json', 'w') as js_file:
        json.dump(users, js_file)
        
def hasher(password, salt=None):
    if salt == None:
        salt = sha256(os.urandom(70)).hexdigest().encode('ascii')
        key = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 80000)
        key = binascii.hexlify(key)
        return (salt + key).decode('ascii'), salt.decode('ascii')
    else:
        salt = salt.encode('ascii')
        new_key = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 80000)
        new_key = binascii.hexlify(new_key)
        return (salt + new_key).decode('ascii')

def create(inf):
    try:
        tu = hasher(inf['password'])
        new_user = {
            'login':inf['login'],
            'password':tu[0],
            'salt':tu[1],
            'regDate': datetime.datetime.now().isoformat()
        }
        users.append(new_user)
        js_load(users)
        return {
            'result': True,
            'reason': 'User registered in the system'
        }, 201
    except:
        abort(400)

def check_login(login):
    for i in range(len(users)):
        if users[i]['login'] == login:
            return False
    return True

@app.route('/user/reg', methods=['POST'])
def create_users():
    ifuser = request.get_json()
    if check_login(ifuser['login']):
        return create(ifuser)
    else:
        return {
            'result':False,
            'reason':'this login is already in use'
        }
def check_pass(inf):
    login = inf['login']
    password = inf['password']
    list_ch = list(filter(lambda x: x['login'] == login, users))
    pass_check = list_ch[0]['password']
    salt_check = list_ch[0]['salt']
    new_pass = hasher(password, salt_check)
    if pass_check == new_pass:
        return True
    else:
        return False
@app.route('/users/<string:login_user>', methods=['GET'])
def by_login(login_user):
    by_user = list(filter(lambda x: x['login'] == login_user, users))
    if len(by_user) == 0:
        abort(404)
    return jsonify({'users': by_user[0]})
@app.route('/user', methods=['POST', 'GET'])
def log_and_get_users():
    if request.method == 'POST':
        ifuser = request.get_json()
        if not check_login(ifuser['login']):
            if check_pass(ifuser):
                return {
                'result': True,
                'reason': 'successful authentification'
            }
            else:
                return {
                'result': False,
                'reason': 'another password'
            }

        else:
            return {
                'result': False,
                'reason': 'user does not exists'
            }
    elif request.method == 'GET':
        return jsonify({"users": users})

@app.route('/')
def user_data():
    return 'User data storage system'

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False)

