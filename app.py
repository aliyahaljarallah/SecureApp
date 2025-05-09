import os
from flask import Flask, render_template, request, redirect, url_for, session 
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from sqlalchemy import text
import html

app = Flask(__name__)
app.secret_key = 'your_secret_key'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'database.db')
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), default='user')

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return '❌ Username already exists. Please choose a different one.'

        # Secure version
        # bcrypt Selected for secure password storage because it is widely trusted and slows down bruteforce attacks.
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Vulnerable version 
        # sql = text(f"INSERT INTO user (username, password) VALUES ('{username}', '{password}')")
        # db.session.execute(sql)
        # db.session.commit()

        return '✅ Registration successful! You can now <a href="/login">login</a>.'

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Secure version
        # This ensures that even if the database is compromised, the original passwords cannot be easily retrieved.
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode(), user.password.encode()):
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            return '❌ Invalid username or password.'

        # Vulnerable version
        # sql = text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'")
        # result = db.session.execute(sql)
        # row = result.fetchone()
        # if row:
        #     session['username'] = row[1]
        #     session['role'] = row[3]
        #     return redirect(url_for('dashboard'))
        # else:
        #     return '❌ Invalid username or password.'

    return render_template('login.html')

comments = []

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        content = request.form['content']

       # Vulnerable version
        comments.append(content)

        # Secure version
        # Used to sanitize comments to mitigate XSS vulnerabilities.
        # sanitized = html.escape(content)
        # comments.append(sanitized)


    return render_template('dashboard.html', username=session['username'], role=session['role'], comments=comments)

@app.route('/admin')
def admin():
    # Vulnerable version
    # return render_template('admin.html', username=session.get('username'), role=session.get('role'), users=[])

    # Secure version
     if 'username' not in session:
         return redirect(url_for('login'))
    
     if session.get('role') != 'admin':
         return '❌ Access denied. You are not an admin.', 403
    
     users = User.query.all()
     return render_template('admin.html', users=users)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))
# self-signed SSL certificates for encrypted HTTPS communication.
# It encrypts all data between the client and server, protecting against eavesdropping and man in the middle attacks.
