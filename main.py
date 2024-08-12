from flask import Flask, request, redirect, url_for, render_template, session
from flask_dance.contrib.google import make_google_blueprint, google
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'fee5a7e4-61c8-4255-bac8-1ee27469f19a'  # Change this to a random secret key

# MySQL configurations
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'ihatenyp1234'
app.config['MYSQL_DB'] = 'pythonlogin'
app.config['MYSQL_PORT'] = 3306

blueprint = make_google_blueprint(
    client_id="15998136336-hgnkta6j00istjbbrdl36hgefuep6t9u.apps.googleusercontent.com",
    client_secret="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",
    scope=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"],
    redirect_to="google_login"
)
app.register_blueprint(blueprint, url_prefix="/login")

# Initialize MySQL and Bcrypt
mysql = MySQL(app)
bcrypt = Bcrypt(app)

class MySQLStorage:
    def __init__(self, connection, user_id):
        self.connection = connection
        self.user_id = user_id

    def get(self, google_id):
        cursor = self.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM oauth_tokens WHERE google_id = %s AND user_id = %s', (google_id, self.user_id))
        token = cursor.fetchone()
        if token:
            return {
                "access_token": token['access_token'],
                "refresh_token": token['refresh_token'],
                "token_type": token['token_type'],
                "expires_in": token['expires_in']
            }
        return None

    def set(self, google_id, token):
        cursor = self.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO oauth_tokens (google_id, access_token, refresh_token, token_type, expires_in, user_id) VALUES (%s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE access_token = %s, refresh_token = %s, token_type = %s, expires_in = %s',
                       (google_id, token['access_token'], token.get('refresh_token'), token.get('token_type'), token.get('expires_in'), self.user_id,
                        token['access_token'], token.get('refresh_token'), token.get('token_type'), token.get('expires_in')))
        self.connection.commit()

    def delete(self, google_id):
        cursor = self.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('DELETE FROM oauth_tokens WHERE google_id = %s AND user_id = %s', (google_id, self.user_id))
        self.connection.commit()

@app.route('/MyWebApp/', methods=['GET', 'POST'])
def login():
    # Check if user is already logged in
    if 'loggedin' in session:
        return redirect(url_for('home'))

    # Google OAuth
    if google.authorized:
        try:
            resp = google.get("/oauth2/v2/userinfo")
            resp.raise_for_status()  # Raises HTTPError for bad responses
            google_info = resp.json()
            google_id = google_info["id"]
            email = google_info["email"]
            username = google_info.get("name", "Google User")
        except AssertionError:
            msg = 'Failed to retrieve user information from Google. Please try again.'
            return render_template('index.html', msg=msg)
        except Exception as e:
            msg = f'An unexpected error occurred: {str(e)}'
            return render_template('index.html', msg=msg)

        # Check if the user already exists in the `google` table
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM google WHERE google_id = %s', (google_id,))
        google_account = cursor.fetchone()

        if google_account:
            # Load related account data from `accounts` table
            cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
            account = cursor.fetchone()
            if account:
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                session['email'] = account['email']
                session['google_id'] = google_account['google_id']
                session['role_id'] = account['role_id']
                return redirect(url_for('home'))
        else:
            return redirect(url_for('register'))

        if account is None:
            msg = 'Incorrect username/password!'
            return render_template('index.html', msg=msg)

    # Standard login
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        user_hashpwd = account['password'] if account else None
        if account and bcrypt.check_password_hash(user_hashpwd, password):
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']

            encrypted_email = account['email'].encode()
            file = open('symmetric.key', 'rb')
            key = file.read()
            file.close()
            f = Fernet(key)
            decrypted_email = f.decrypt(encrypted_email)

            return 'Logged in successfully! My email: ' + decrypted_email.decode()
        else:
            msg = 'Incorrect username/password!'
    return render_template('index.html', msg=msg)

@app.route('/logout/google')
def google_logout():
    token = blueprint.token["access_token"]
    resp = google.post(
        "https://accounts.google.com/o/oauth2/revoke",
        params={"token": token},
        headers={"content-type": "application/x-www-form-urlencoded"}
    )
    assert resp.ok, resp.text
    logout()  # Flask-Login's logout
    return redirect(url_for('login'))

@app.route('/MyWebApp/logout')
def logout():
    # Remove all session data
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    session.pop('email', None)
    session.pop('google_id', None)
    session.pop('role_id', None)
    clear_session()
    # Also log out from Google if logged in via Google
    if google.authorized:
        token = blueprint.token["access_token"]
        resp = google.post('https://accounts.google.com/o/oauth2/revoke',
                           params={'token': token},
                           headers={'content-type': 'application/x-www-form-urlencoded'})
        assert resp.ok, resp.text

    return redirect(url_for('login'))

@app.route('/MyWebApp/register', methods=['GET', 'POST'])
def register():
    msg = ''

    if google.authorized:
        resp = google.get("/oauth2/v2/userinfo")
        resp.raise_for_status()
        assert resp.ok, resp.text
        google_info = resp.json()
        google_id = google_info["id"]
        email = google_info["email"]
        username = google_info.get("name", "Google User")
        picture = google_info.get("picture", None)

        # Check if the user already exists in the `google` table
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM google WHERE google_id = %s OR email = %s', (google_id, email))
        google_account = cursor.fetchone()

        if google_account:
            msg = 'Account already exists! Please log in.'
            return redirect(url_for('login'))

        # Insert Google user data into `google` table
        cursor.execute('INSERT INTO google (username, email, google_id, role_id) VALUES (%s, %s, %s, %s)',
                       (username, email, google_id, 1))
        mysql.connection.commit()

        # Insert related data into `accounts` table
        cursor.execute('INSERT INTO accounts (username, email, role_id) VALUES (%s, %s, %s)',
                       (username, email, 1))
        mysql.connection.commit()

        session['loggedin'] = True
        session['id'] = cursor.lastrowid
        session['username'] = username
        session['email'] = email
        session['google_id'] = google_id
        session['role_id'] = 1

        return redirect(url_for('home'))

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Check if the user already exists in the `accounts` table
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s OR email = %s', (username, email))
        account = cursor.fetchone()

        if account:
            msg = 'Account already exists!'
        else:
            hashpwd = bcrypt.generate_password_hash(password)
            key = Fernet.generate_key()

            with open("symmetric.key", "wb") as fo:
                fo.write(key)

            f = Fernet(key)
            encrypted_email = f.encrypt(email.encode())

            # Insert the new user into the `accounts` table
            cursor.execute('INSERT INTO accounts (username, password, email, role_id) VALUES (%s, %s, %s, %s)',
                           (username, hashpwd, encrypted_email, 1))
            mysql.connection.commit()
            msg = 'You have successfully registered!'
            return redirect(url_for('login'))

    elif request.method == 'POST':
        msg = 'Please fill out the form!'

    return render_template('register.html', msg=msg)

@app.route('/MyWebApp/home')
def home():
    # Check if user is logged in
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/MyWebApp/profile')
def profile():
    # Check if user is logged in
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        return render_template('profile.html', account=account)
    return redirect(url_for('login'))

@app.route('/google_login')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))
    resp = google.get("/oauth2/v2/userinfo")
    google_info = resp.json()
    google_id = google_info["id"]
    email = google_info["email"]
    name = google_info.get("name", "No Name")
    picture = google_info.get("picture", None)

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM google WHERE google_id = %s', (google_id,))
    google_account = cursor.fetchone()

    if google_account:
        session['loggedin'] = True
        session['id'] = google_account['id']
        session['username'] = google_account['username']
        return redirect(url_for('home'))
    else:
        msg = 'Google account not registered. Please sign up using Google.'
        return render_template('index.html', msg=msg)

@app.route("/login/callback")
def callback():
    google.authorized_response()
    token = google.token
    session['google_token'] = (token['access_token'], '')
    return redirect(url_for('home'))

@app.route('/clear-session')
def clear_session():
    session.clear()
    return 'Session cleared!'


if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')

