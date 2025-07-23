# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os # To access environment variables

app = Flask(__name__)

# --- Database Configuration ---
# It's best practice to load sensitive info from environment variables
# For local development, you can set them directly or use a .env file
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'postgresql://postgres_user:your_rds_password@your_rds_endpoint:5432/cloudnationdb'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Suppress warning

# --- Secret Key for Sessions ---
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_super_secret_key_here') # IMPORTANT: Change this in production!

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- Database Model for User ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False) # Store hashed password

    def __repr__(self):
        return f'<User {self.username}>'

# --- Flask Routes ---

@app.route('/')
def login_page():
    """
    Renders the login page.
    If the user is already logged in (session has 'logged_in'), redirects to the dashboard.
    """
    if 'logged_in' in session and session['logged_in']:
        return redirect(url_for('dashboard'))
    return render_template('login.html', error_message=None)

@app.route('/login', methods=['POST'])
def login():
    """
    Handles the login form submission.
    Authenticates user against the database.
    """
    login_id = request.form.get('loginId')
    password = request.form.get('password')

    user = User.query.filter_by(username=login_id).first()

    if user and bcrypt.check_password_hash(user.password_hash, password):
        session['logged_in'] = True
        session['username'] = user.username # Store actual username from DB
        return redirect(url_for('dashboard'))
    else:
        return render_template('login.html', error_message='Invalid Login ID or Password.')

@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
    """
    Handles user registration.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('signup.html', error_message='Username and password are required.')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('signup.html', error_message='Username already exists. Please choose a different one.')

        # Hash the password before storing
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password_hash=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            session['logged_in'] = True
            session['username'] = new_user.username
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            return render_template('signup.html', error_message=f'An error occurred during registration: {e}')

    return render_template('signup.html', error_message=None)


@app.route('/dashboard')
def dashboard():
    """
    Renders the dashboard page.
    Requires the user to be logged in. If not, redirects to the login page.
    """
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login_page'))
    current_username = session.get('username', 'Guest')
    return render_template('dashboard.html', username=current_username)

@app.route('/logout')
def logout():
    """
    Logs out the user by clearing the session and redirects to the login page.
    """
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login_page'))

if __name__ == '__main__':
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
    # Run the Flask application in debug mode.
    # Set debug=False for production environments.
    app.run(debug=True, host='0.0.0.0') # Listen on all interfaces for EC2 deployment
