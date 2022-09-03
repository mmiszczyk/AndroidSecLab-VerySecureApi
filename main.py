import os

from flask import Flask, jsonify, request
from flasgger import Swagger, LazyJSONEncoder
import jwt
import datetime
import functools
import subprocess
import sys

app = Flask(__name__)
app.config['SECRET_KEY'] = 'verysecurekey'
app.config['SWAGGER'] = {'openapi': '3.0.0'}
swagger = Swagger(app, template={
    "securityDefinitions": {
        "bearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "name": "Authorization",
            "in": "header"
        }
    }
})

users = {
    'admin': {'name': 'Admin', 'mail': 'ad@m.in', 'password': 'admin1', 'isadmin': True},
    'test': {'name': 'Test Account', 'mail': 'test@example.org', 'password': 'test1234', 'isadmin': False},
    'jkowalski': {'name': 'Jan Kowalski', 'mail': 'jkowalski@example.org', 'password': 'k0walski;JAN', 'isadmin': False}
}


def auth_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = request.headers["Authorization"].split(" ")[1]
        except KeyError:
            return {
                       'error': 'Authentication error',
                       'msg': 'You must log in to use this function'
                   }, 401
        try:
            data = jwt.decode(token, options={"verify_signature": False})
            if data['login'] not in users:
                return {
                           'error': 'Authentication error',
                           'msg': 'Invalid user account'
                       }, 401
            if datetime.datetime.fromisoformat(data['valid_until']) < datetime.datetime.now():
                return {
                           'error': 'Authentication error',
                           'msg': 'Token validity expired'
                       }, 401
            return f(data['login'], data['isadmin'])
        except Exception as e:
            return {
                       'error': 'Unknown error during authentication',
                       'msg': str(e)
                   }, 500

    return decorated


@app.route("/login", methods=["POST"])
def login():
    """
    Log in to the application.
    ---
    consumes:
      - application/json
    definitions:
        Logindata:
            type: object
            required:
                - login
                - password
            properties:
                login:
                    type: string
                password:
                    type: string
    requestBody:
         description: Login and password
         required: true
         content:
            application/json:
                schema:
                    $ref: '#/definitions/Logindata'
    responses:
        200:
            description: A valid JWT token
        401:
            description: Unauthorized error (wrong login or password)
        500:
            description: Unknown error
    """
    try:
        data = request.json
        userlogin = data['login']
        password = data['password']
        try:
            usr = users[userlogin]
            validity = datetime.datetime.now() + datetime.timedelta(hours=1)
            if usr['password'] != password:
                raise KeyError('Wrong password')
            # return {
            #
            #     'token': jwt.encode({
            #         "login": userlogin,
            #         "isadmin": usr['isadmin'],
            #         "valid_until": validity.isoformat()
            #     }, app.config['SECRET_KEY'])
            # }, 200
            return jwt.encode({"login": userlogin,
                               "isadmin": usr['isadmin'],
                               "valid_until": validity.isoformat()
                               }, app.config['SECRET_KEY']), 200
        except KeyError as ke:
            return {
                       'error': 'Login error',
                       'msg': 'Incorrect login or password'
                   }, 401

    except Exception as e:
        return {
                   'error': 'Unknown error',
                   'msg': str(e)
               }, 500


@app.route('/users', methods=['GET'])
@auth_required
def allusers(_, __):
    """
    Get data of all users
    ---
    security:
      - bearerAuth: []
    responses:
        200:
            description: List of users and their properties
    """
    return jsonify(users)


@app.route('/users/<string:loginparam>', methods=['GET', 'PUT'])
@auth_required
def user(userlogin, isadmin):
    """
    Get or set data of user
    ---
    security:
      - bearerAuth: []
    definitions:
        User:
            type: object
            example: {"mail": "new@ma.il", "passowrd": "newpass"}
            properties:
                name:
                    type: string
                mail:
                    type: string
                password:
                    type: string
                isadmin:
                    type: boolean
    requestBody:
         description: New user data
         content:
            application/json:
                schema:
                    $ref: '#/definitions/User'
    parameters:
        - in: path
          name: loginparam
          schema:
            type: string
          required: true
    responses:
        200:
            description: User data object
            schema:
                $ref: '#/definitions/User'
    """
    try:
        loginparam = request.view_args['loginparam']
        if loginparam != userlogin and not isadmin:
            return {
                       'error': 'Forbidden',
                       'msg': "Attempt to access other user's data"
                   }, 403
        if request.method == 'PUT':
            for k in request.json:
                if k in users[loginparam]:
                    users[loginparam][k] = request.json[k]
        return users[loginparam], 200
    except Exception as e:
        return {
            'error': 'Unknown error',
            'msg': str(e)
        }
    pass


@app.route("/debug/nettest", methods=['GET', 'POST'])
@auth_required
def network_test(_, __):
    """
    Test network connectivity
    ---
    security:
      - bearerAuth: []
    definitions:
        Ping:
            type: object
            properties:
                addr:
                    type: string
                    default: google.com
    requestBody:
         description: Server to ping
         content:
            application/json:
                schema:
                    $ref: '#/definitions/User'
    responses:
        200:
            description: Ping output
    """
    cmd = "ping " if sys.platform == "win32" else "ping -c 4 "
    to_ping = "google.com"
    try:
        to_ping = request.json['addr']
    except:
        pass
    # return subprocess.check_output(cmd + to_ping, shell=True), 200
    os.system(cmd + to_ping + " > out.txt")
    with open("out.txt", 'r') as f:
        return f.read(), 200


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
