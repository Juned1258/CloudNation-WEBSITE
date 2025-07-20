# app.py
from flask import Flask, render_template, request, redirect, url_for, session

from dotenv import load_dotenv
import os

load_dotenv()  # take environment variables from .env

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
# ...existing code...

app = Flask(__name__)


@app.route('/')
def login_page():
    """
    Renders the login page.
    If the user is already logged in (session has 'logged_in'), redirects to the dashboard.
    Explicitly pass error_message=None to ensure no error message is displayed on initial load.
    """
    if 'logged_in' in session and session['logged_in']:
        return redirect(url_for('dashboard'))
    return render_template('login.html', error_message=None) # Ensure no error message on initial load

@app.route('/login', methods=['POST'])
def login():
    """
    Handles the login form submission.
    Performs a basic, simulated authentication.
    """
    login_id = request.form.get('loginId')
    password = request.form.get('password')

    # --- Simulated Authentication ---
    # In a real application, you would connect to a database, hash passwords,
    # and securely verify credentials.
    # For this demo, any non-empty loginId and password will be considered valid.
    if login_id and password:
        session['logged_in'] = True
        # Removed session['username'] as it's no longer used in dashboard.html
        return redirect(url_for('dashboard'))
    else:
        # If authentication fails, render login page with an error message
        return render_template('login.html', error_message='Invalid Login ID or Password.')

@app.route('/dashboard')
def dashboard():
    """
    Renders the dashboard page.
    Requires the user to be logged in. If not, redirects to the login page.
    """
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login_page'))
    # No longer passing username to the template
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    """
    Logs out the user by clearing the session and redirects to the login page.
    """
    session.pop('logged_in', None)
    session.pop('username', None) # Still good practice to pop if it existed
    return redirect(url_for('login_page'))

if __name__ == '__main__':
    # Run the Flask application in debug mode.
    # Set debug=False for production environments.
    app.run(debug=True)
