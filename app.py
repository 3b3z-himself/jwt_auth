from flask import Flask, request, jsonify, make_response, render_template, session, redirect, url_for
import jwt
from datetime import datetime, timedelta
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = '7499d35cb2c846f5a141d5324f43c722'


def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'Alert!': 'Token is missing!'}), 401  # Return 401 for Unauthorized
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'])
            kwargs['username'] = payload['user']
            kwargs['expiration_time'] = payload['expiration']
        except jwt.ExpiredSignatureError:
            return jsonify({'Alert!': 'Token has expired!'}), 401
        except jwt.DecodeError:
            return jsonify({'Alert!': 'Invalid Token!'}), 401
        return func(*args, **kwargs)  # Process the function if the token is valid
    return decorated





@app.route('/', methods=['get'])
def home():
    if session.get('logged_in') and session.get('expiration_time'):
        expiration_time_str = session.get('expiration_time')
        expiration_time = datetime.strptime(expiration_time_str, '%Y-%m-%d %H:%M:%S.%f')

        if expiration_time > datetime.utcnow():
            return render_template('index.html', username=session.get('username'))
        else:
            print('Token has expired')
            session.clear()
            # return redirect(url_for('login'))
            return render_template('login.html')
    else:
        # return render_template('index.html', username = session.get('username'))
        return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))
#for public
@app.route('/public')
def public():
    return 'For Public'
#for authticated
@app.route('/auth')
@token_required
def auth():
    return render_template('index.html', username=session.get('username'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if username and password == '123456':
        session['logged_in'] = True
        session['username'] = username
        expiration_time = str(datetime.utcnow() + timedelta(seconds=15))
        session['expiration_time'] = expiration_time
        token_payload = {'user': username, 'expiration': expiration_time}
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
        return render_template('index.html', username = session.get('username'))
    else:
        return make_response('Unable to verify', 403, {'WWW-Authenticate': 'Basic realm="Authentication Failed!"'})

if __name__ == "__main__":
    app.run(debug=True)
