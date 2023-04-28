import configparser
import argparse
import json
import os
import traceback
import random
import string
import jwt
import time
import requests
from urllib.parse import urlencode
import pprint

from flask import Flask, request, redirect, session, render_template


app = Flask(__name__)
app.secret_key = os.urandom(32)

pp = pprint.PrettyPrinter(indent=2)


def generate_state(length):
    generator = random.SystemRandom()
    characters = string.ascii_letters + string.digits
    return ''.join(generator.choice(characters) for i in range(length))


def parse():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-c",
        "--config",
        help="The config section from duo.conf to use",
        default="duo",
        metavar=''
    )

    return parser.parse_known_args()[0]


config = configparser.ConfigParser()
config.read("duo.conf")
config_section = parse().config
duo_failmode = config[config_section]['failmode']


client_id = config[config_section]['client_id']
client_secret = config[config_section]['client_secret']
host = config[config_section]['api_hostname']
redirect_uri = config[config_section]['redirect_uri']
duo_certs = config[config_section].get('duo_certs', None)


@app.route("/", methods=['GET'])
def login():
    return render_template("login.html", message="This is a demo")


@app.route("/", methods=['POST'])
def login_post():
    """
    respond to HTTP POST with 2FA as long as health check passes
    """
    username = request.form.get('username')
    password = request.form.get('password')

    # Check user's first factor.
    # (In a production application, actually verify that the password is correct)
    if password is None or password == "":
        return render_template("login.html",
                               message="Missing password")

    try:
        health_check_endpoint = f"https://{host}/oauth/v1/health_check"
        jwt_args = {
            'iss': client_id,
            'sub': client_id,
            'aud': health_check_endpoint,
            'exp': time.time() + 300,
            'jti': generate_state(36)
        }
        all_args = {
            'client_assertion': jwt.encode(jwt_args,
                                           client_secret,
                                           algorithm='HS512'),
            'client_id': client_id
        }
        try:
            response = requests.post(health_check_endpoint,
                                     data=all_args,
                                     verify=False)
            res = json.loads(response.content)
            pp.pprint(response.request.url)
            pp.pprint(response.request.headers)
            pp.pprint(response.request.body)
            pp.pprint(response.json())
            if res['stat'] != 'OK':
                raise Exception(res)
        except Exception as e:
            print(e)

    except Exception as e:
        traceback.print_exc()
        if duo_failmode.upper() == "OPEN":
            # If we're failing open errors in 2FA still allow for success
            return render_template("success.html",
                                   message="Login 'Successful', but 2FA Not Performed. Confirm Duo client/secret/host values are correct")
        else:
            # Otherwise the login fails and redirect user to the login page
            return render_template("login.html",
                                   message="2FA Unavailable. Confirm Duo client/secret/host values are correct")

    # Generate random string to act as a state for the exchange
    state = generate_state(36)
    session['state'] = state
    session['username'] = username
    authorize_endpoint = f"https://{host}/oauth/v1/authorize"

    jwt_args = {
        'scope': 'openid',
        'redirect_uri': redirect_uri,
        'client_id': client_id,
        'iss': client_id,
        'aud': f"https://{host}",
        'exp': time.time() + 300,
        'state': state,
        'response_type': 'code',
        'duo_uname': username,
        'use_duo_code_attribute': True,
    }

    request_jwt = jwt.encode(jwt_args,
                             client_secret,
                             algorithm='HS512')
    all_args = {
        'response_type': 'code',
        'client_id': client_id,
        'request': request_jwt,
    }

    query_string = urlencode(all_args)
    authorization_uri = f"{authorize_endpoint}?{query_string}"
    pp.pprint(authorization_uri)

    # Redirect to prompt URI which will redirect to the client's redirect URI
    # after 2FA
    return redirect(authorization_uri)


# This route URL must match the redirect_uri passed to the duo client
@app.route("/duo-callback")
def duo_callback():
    # Get state to verify consistency and originality
    state = request.args.get('state')

    # Get authorization token to trade for 2FA
    duoCode = request.args.get('duo_code')

    if 'state' in session and 'username' in session:
        saved_state = session['state']
        username = session['username']
    else:
        # For flask, if url used to get to login.html is not localhost,
        # (ex: 127.0.0.1) then the sessions will be different
        # and the localhost session does not have the state
        return render_template("login.html",
                               message="No saved state please login again")

    # Ensure nonce matches from initial request
    if state != saved_state:
        return render_template("login.html",
                               message="Duo state does not match saved state")

    token_endpoint = f"https://{host}/oauth/v1/token"
    jwt_args = {
        'iss': client_id,
        'sub': client_id,
        'aud': token_endpoint,
        'exp': time.time() + 300,
        'jti': generate_state(36)
    }
    all_args = {
        'grant_type': 'authorization_code',
        'code': duoCode,
        'redirect_uri': redirect_uri,
        'client_id': client_id,
        'client_assertion_type': "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        'client_assertion': jwt.encode(jwt_args,
                                       client_secret,
                                       algorithm='HS512')
    }
    try:
        # user_agent = ("duo_universal_python/{version} "
        #               "python/{python_version} {os_name}").format(version=__version__,
        #                                                           python_version=platform.python_version(),
        #                                                           os_name=platform.platform())
        # headers={"user-agent":
        #                                               user_agent}
        response = requests.post(token_endpoint,
                                 params=all_args,
                                 verify=False)
        pp.pprint(response.request.url)
        pp.pprint(response.request.headers)
        pp.pprint(response.request.body)
        pp.pprint(response.json())
    except Exception as e:
        print(e)

    if response.status_code != 200:
        error_message = json.loads(response.content)
        print(error_message)

    try:
        decoded_token = jwt.decode(
            response.json()['id_token'],
            client_secret,
            audience=client_id,
            issuer=token_endpoint,
            # leeway=60,
            algorithms=["HS512"],
            # options={
            #     'require': ['exp', 'iat'],
            #     'verify_iat': True
            # },
        )
        pp.pprint(decoded_token)
    except Exception as e:
        raise print(e)

    if 'preferred_username' not in decoded_token or not decoded_token['preferred_username'] == username:
        raise print(f"err Username")
    # Exchange happened successfully so render success page
    return render_template("success.html",
                           message=json.dumps(decoded_token, indent=2, sort_keys=True))


if __name__ == '__main__':
    app.run(host="localhost", port=8080)
