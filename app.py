import secrets
from datetime import datetime, timedelta

from gevent import monkey
from itsdangerous import URLSafeTimedSerializer

monkey.patch_all()

import hashlib
import os
import random
import sqlite3
import time
import jwt
import requests
import urllib, json, urllib.request

from time import time
from functools import wraps
from secrets import token_hex
from threading import Thread

from flask import Flask, render_template, redirect, url_for, flash, session, make_response, send_from_directory, request
from flask_sock import Sock
from flask_socketio import SocketIO

from gevent import pywsgi
from selenium import webdriver

from config_general import config
from config_chat import chat_history_dict, standard_responses, common_questions_and_answers
from config_secrets import PRIVATE_KEY

app = Flask(__name__)
app.config.from_object(config)
session_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])  

sock = Sock(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', transports=['websocket'])
websocketauth_token = token_hex(64)
invalid_tokens = set()

JKU_URL =  'https://18.141.13.209/keys/jwks.json'   
EXPECTED_DOMAIN = 'https://18.141.13.209'           
JWT_TOKEN_NAME = "jwt_token"


def get_is_admin_from_database(username):
    conn = sqlite3.connect(config.DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT admin_status FROM users WHERE username = ?", (username,))
    is_admin = cursor.fetchone()

    conn.close()

    if is_admin:
        return is_admin[0]  
    else:
        return False


def get_user_info(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get(JWT_TOKEN_NAME)

        if token:
            try:
                header = jwt.get_unverified_header(token)
                kid = header['kid']
                JKU_URL = header['jku']

                response = requests.get(JKU_URL, verify=False)
                JWKS = response.json()

                for key in JWKS['keys']:
                    if key['kid'] == kid:
                        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))

                payload = jwt.decode(token, public_key, algorithms=['RS256'])
                username = payload.get('username')

                is_admin = get_is_admin_from_database(username)
                return f(username, is_admin, *args, **kwargs)

            except jwt.ExpiredSignatureError:
                flash('Token expired. Please log in again.', 'danger')
            except jwt.InvalidTokenError:
                flash('Invalid token. Please log in again.', 'danger')

        return f(None, None, *args, **kwargs)
    return decorated


def sign_in_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        jwt_token = request.cookies.get(JWT_TOKEN_NAME)

        if not jwt_token:
            flash('Sign in required.', 'danger')
            return redirect(url_for('login'))

        try:
            header = jwt.get_unverified_header(jwt_token)
            kid = header['kid']
            JKU_URL = header['jku']

            response = requests.get(JKU_URL, verify=False)
            JWKS = response.json()

            for key in JWKS['keys']:
                if key['kid'] == kid:
                    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))

            payload = jwt.decode(jwt_token, public_key, algorithms=['RS256'])
            username = payload.get('username')

            if not username:
                flash('Sign in required.', 'danger')
                return redirect(url_for('login'))

        except jwt.ExpiredSignatureError:
            flash('Token expired. Please log in again.', 'danger')
            return redirect(url_for('login'))
        except jwt.InvalidTokenError:
            flash('Invalid token. Please log in again.', 'danger')
            return redirect(url_for('login'))

        return f(*args, **kwargs)

    return decorated


def hash_password(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    hashed_password = sha256.hexdigest()
    return hashed_password


def get_user_data(username, password):
    conn = sqlite3.connect(config.DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT id, username, password, admin_status FROM users WHERE username = ?", (username,))
    user_data = cursor.fetchone()

    if user_data:
        user_id, stored_username, stored_password, admin_status = user_data

        if stored_password == hash_password(password):
            conn.close()
            return user_id, stored_username, admin_status

    conn.close()
    return None  


@app.route('/login', methods=['GET', 'POST'])
@get_user_info
def login(username, is_admin):
    if request.method == 'POST':
        username = request.form['USERNAME']
        password = request.form['PASSWORD']

        user_data = get_user_data(username, password)

        if user_data:
            user_id, user_name, is_admin = user_data[0], user_data[1], user_data[2]

            current_time = int(time())
            exp = current_time + 3600

            token_header = {
                'alg': 'RS256',
                'typ': 'JWT',
                'jku': JKU_URL,
                'kid': '324-23234324-544535-1320214'
            }

            token_payload = {
                'iat': current_time,
                'username': user_name,
                'exp': exp,
            }

            token = jwt.encode(token_payload, PRIVATE_KEY, algorithm='RS256', headers=token_header)

            response = make_response(redirect(url_for('welcome')))
            response.set_cookie(JWT_TOKEN_NAME, token)
            flash('Login successful', 'success')

            return response

        else:
            flash('Login failed. Please check your username and password.', 'danger')

    return render_template('login.html', current_page="login", username=username, is_admin=is_admin)


@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('welcome')))
    response.delete_cookie(JWT_TOKEN_NAME)

    flash('Logout successful', 'success')
    return response


class Bot(Thread):
    def __init__(self, url):
        Thread.__init__(self)
        self.url = url

    def run(self):
        driver = webdriver.Firefox(options=config.SELENIUM_OPTIONS)
        driver.get(self.url)
        time.sleep(3)
        driver.quit()


def bob_reply():
    return random.choice(standard_responses)


@app.route('/websocketauth')
def websocketauth():
    if request.remote_addr == "127.0.0.1":
        resp = make_response("authenticated")
        resp.set_cookie("websocketauth", websocketauth_token, httponly=True)
    else:
        resp = make_response("unauthenticated")
    return resp


@sock.route('/quote')
def echo_socket(ws):
    print('/quote', flush=True)
    while True:
        message = ws.receive()
        print(message)
        try:
            try:
                cookie = dict(i.split('=') for i in ws.environ['HTTP_COOKIE'].split('; '))
            except Exception as e:
                print('cookie error:', e, flush=True)
                cookie = {}
            if cookie.get('websocketauth') == websocketauth_token:
                ws.send(f"{chat_history_dict}")
            else:
                for qa_pair in common_questions_and_answers:
                    question = qa_pair["question"]
                    answer = qa_pair["answer"]
                    ws.send(f"Q: {question}\nA: {answer}")
            break
        except Exception as e:
            print('error:', e, flush=True)
            break


def generate_session_id():
    session_id = None
    while session_id is None or session_id in session:
        session_id = secrets.token_hex(16)
    session[session_id] = {}
    return session_id


session_start_times = {}
session_timeout = 1800  

@app.route('/chat', methods=['GET', 'POST'])
@get_user_info
def chat(username, is_admin):
    if request.method == 'POST':
        if request.form.get('content'):
            content = request.form.get('content')
            if content.startswith("http"):
                thread_a = Bot(content)
                thread_a.start()
            else:
                session_id = session.get('_id')

                session_start_times[session_id] = datetime.now()

                chat_history = chat_history_dict.get(session_id, [])
                chat_history.append({"user": "You", "message": content})

                reply = bob_reply()
                chat_history.append({"user": "Bob", "message": reply})

                chat_history_dict[session_id] = chat_history

    if '_id' not in session:
        session['_id'] = generate_session_id()

    session_id = session.get('_id')

    if session_id in session_start_times:
        session_start_time = session_start_times[session_id]
        if datetime.now() - session_start_time > timedelta(seconds=session_timeout):
            del chat_history_dict[session_id]
            del session_start_times[session_id]
            flash('Your chat session has timed out.', 'warning')

    chat_history = chat_history_dict.get(session_id, [])

    return render_template("chat.html", chat_history=chat_history, session_id=session_id,
                           username=username, is_admin=is_admin)


@socketio.on('chat_message')
def handle_message(message):
    session_id = session.get('_id')

    chat_history = chat_history_dict.get(session_id, [])
    chat_history.append({"user": "You", "message": message})

    reply = bob_reply()
    chat_history.append({"user": "Bob", "message": reply})

    chat_history_dict[session_id] = chat_history

    socketio.emit('chat_message', reply, broadcast=True)


@app.route('/commonly_asked_questions')
@get_user_info
def commonly_asked_questions(username, is_admin):
    return render_template('commonly_asked_questions.html', username=username, is_admin=is_admin)


def get_potatoes_data(search_query=None, order_by=None):
    conn = sqlite3.connect(config.DATABASE_PATH)
    cursor = conn.cursor()

    sql_query = "SELECT * FROM potatoes WHERE 1"
    sql_params = []

    if search_query:
        sql_query += " AND name LIKE ?"
        sql_params.append('%' + search_query + '%')

    if order_by:
        allowed_order_fields = ['name', 'color', 'origin', 'price']
        if any(item in order_by for item in allowed_order_fields):
            sql_query += f" ORDER BY {order_by}"
        else:
            flash('Invalid filter field', 'danger')

    cursor.execute(sql_query, sql_params)
    rows = cursor.fetchall()
    conn.close()
    return rows


@app.route('/potato_database', methods=['GET', 'POST'])
@get_user_info
@sign_in_required
def potato_database(username, is_admin):
    search_query = request.args.get('search')
    order_by = request.args.get('filter')

    potatoes_data = get_potatoes_data(search_query, order_by)

    if not potatoes_data:
        message = "No results found."
    else:
        message = None

    return render_template('potato_database.html', potatoes=potatoes_data, message=message,
                           current_page="potato_database", username=username, is_admin=is_admin)


@app.route('/keys/jwks.json')
def jwks_key():
    src_folder = os.path.dirname(os.path.abspath(__file__))
    key_path = os.path.join(src_folder, 'keys/jwks.json')
    with open(key_path, "r") as file1:
        data = file1.read()
    return data


@app.route('/images/database_img/<filename>')
def serve_image(filename):
    return send_from_directory('images/database_img', filename)


@app.route('/')
@get_user_info
def welcome(username, is_admin):
    return render_template('index.html', current_page="home", username=username, is_admin=is_admin)


@app.route('/about_us')
@get_user_info
def about_us(username, is_admin):
    return render_template('about_us.html', current_page="about_us", username=username, is_admin=is_admin)


@app.route("/promotion", methods=['GET'])
@get_user_info
def redirecting(username, is_admin):
    if 'url' in request.args:
        url = request.args["url"]
        return redirect(url)
    else:
        return render_template('index.html', current_page="home", username=username, is_admin=is_admin)


def check_admin_status(token, expected_domain):
    if token:
        try:
            header = jwt.get_unverified_header(token)
            kid = header['kid']
            JKU_URL = header['jku']

            if not JKU_URL.startswith(expected_domain):
                return 'Invalid JKU URL. Access denied.', None, None

            response = requests.get(JKU_URL, verify=False)
            JWKS = response.json()

            for key in JWKS['keys']:
                if key['kid'] == kid:
                    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))

            payload = jwt.decode(token, public_key, algorithms=['RS256'])
            is_admin = payload.get('is_admin')

            if is_admin == 1:
                return 'Authenticated.', json.dumps(payload, indent=4), JWKS
            else:
                return 'Access denied. You are not authorized.', None, JWKS

        except jwt.ExpiredSignatureError:
            return 'Token expired. Please log in again.', None, None
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.', None, None

    return 'Token not found. Please log in.', None, None


@app.route('/admin_page', methods=['GET'])
@get_user_info
@sign_in_required
def admin_page(username, is_admin):
    status_message, payload, jwks = check_admin_status(request.cookies.get(JWT_TOKEN_NAME), EXPECTED_DOMAIN)

    if is_admin == 1:
        return render_template('admin_page.html', current_page="admin_page", username=username, is_admin=is_admin)
    else:
        flash(status_message, 'danger')
        return redirect(url_for('welcome'))


@app.route('/connectivitytester', methods=['GET', 'POST'])
@get_user_info
@sign_in_required
def connectivitytester(username, is_admin):
    if not is_admin:
        flash('Access denied. You are not authorized.', 'danger')
        return redirect(url_for('welcome'))

    if request.method == 'POST':
        if 'url' in request.args:
            url = request.args["url"]
            urls = ['127.0.0.1', '0.0.0.0']
            if url not in urls:
                data = json.dumps(request.json).encode('utf-8')
                req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
                req.add_header('Content-Length', len(data))
                try:
                    resp = urllib.request.urlopen(req)
                    return resp.read()
                except Exception as e:
                    return str(e)
            else:
                return render_template('index.html', current_page="home")
        else:
            return render_template('index.html', current_page="home")
    else:
        if 'url' in request.args:
            url = request.args["url"]
            urls = ['127.0.0.1', '0.0.0.0']
            if url not in urls:
                try:
                    return urllib.request.urlopen(url).read()  
                except Exception as e:
                    return str(e)
            else:
                return render_template('index.html', current_page="home")


@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(500)
def error_handler(error):
    error_code = getattr(error, 'code', 500)
    error_message = getattr(error, 'name', 'Internal Server Error')
    return render_template('error.html', error_code=error_code, error_message=error_message), error_code


if __name__ == '__main__':
    try:
        print("Web Server Starting ... ", flush=True)
        server = pywsgi.WSGIServer(("0.0.0.0", 8080), app)
        server.serve_forever()
    except Exception as e:
        print('Error:', e, flush=True)
