import sqlite3
import hashlib
import os
from flask import Flask, render_template_string, redirect, url_for, request, session, flash
from jinja2 import DictLoader

app = Flask(__name__)
app.secret_key = "super_secret_session_key"

def init_db():
    """Initialize SQLite database and users table."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def hash_password(password):
    """Securely hash password using SHA-256 with a random salt."""
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ':' + pwd_hash.hex()

def verify_password(stored_password, provided_password):
    """Verify stored password against provided password."""
    try:
        salt_hex, pwd_hash_hex = stored_password.split(':')
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(pwd_hash_hex)
        new_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        return new_hash == stored_hash
    except Exception:
        return False

# --- Embedded HTML Templates ---
BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Login System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-5" style="max-width: 500px;">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

REGISTER_TEMPLATE = '''
{% extends "base" %}
{% block content %}
<div class="card shadow p-4">
    <h3 class="text-center mb-3">Register</h3>
    <form method="POST">
        <div class="mb-3">
            <label class="form-label">Username</label>
            <input type="text" name="username" class="form-control" required>
        </div>
        <div class="mb-3">
            <label class="form-label">Password</label>
            <input type="password" name="password" class="form-control" required>
        </div>
        <button type="submit" class="btn btn-primary w-100">Register</button>
    </form>
    <p class="text-center mt-3">Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
</div>
{% endblock %}
'''

LOGIN_TEMPLATE = '''
{% extends "base" %}
{% block content %}
<div class="card shadow p-4">
    <h3 class="text-center mb-3">Secure Login</h3>
    <form method="POST">
        <div class="mb-3">
            <label class="form-label">Username</label>
            <input type="text" name="username" class="form-control" required>
        </div>
        <div class="mb-3">
            <label class="form-label">Password</label>
            <input type="password" name="password" class="form-control" required>
        </div>
        <button type="submit" class="btn btn-success w-100">Login</button>
    </form>
    <p class="text-center mt-3">Don't have an account? <a href="{{ url_for('register') }}">Register here</a></p>
</div>
{% endblock %}
'''

DASHBOARD_TEMPLATE = '''
{% extends "base" %}
{% block content %}
<div class="card shadow p-4 text-center">
    <h2>Welcome, {{ username }}!</h2>
    <p class="text-muted">You have successfully logged into the secure dashboard.</p>
    <hr>
    <a href="{{ url_for('logout') }}" class="btn btn-danger w-100">Logout</a>
</div>
{% endblock %}
'''

app.jinja_loader = DictLoader({
    "base": BASE_TEMPLATE,
    "register": REGISTER_TEMPLATE,
    "login": LOGIN_TEMPLATE,
    "dashboard": DASHBOARD_TEMPLATE
})

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        if not username or not password:
            flash("All fields are required!", "danger")
            return redirect(url_for('register'))
            
        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return redirect(url_for('register'))

        hashed_password = hash_password(password)

        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists. Choose a different one.", "danger")
            
    return render_template_string(REGISTER_TEMPLATE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and verify_password(user[0], password):
            session['username'] = username
            flash("Logged in successfully!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.", "danger")

    return render_template_string(LOGIN_TEMPLATE)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template_string(DASHBOARD_TEMPLATE, username=session['username'])
    flash("Please log in to access the dashboard.", "warning")
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)