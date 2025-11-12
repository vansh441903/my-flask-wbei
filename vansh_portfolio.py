from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
import random
import string
import requests  # ✅ used for SendGrid API

app = Flask(__name__)
app.secret_key = 'myverysecretkey1234567890'

DB_PATH = os.path.join(os.getcwd(), 'users.db')

# Initialize database (run once)
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# -------- EMAIL (SendGrid) ----------

def send_email_via_sendgrid(to_email, subject, content_text):
    """Send email via SendGrid HTTP API using environment variables."""
    api_key = os.getenv("SENDGRID_API_KEY")
    sender = os.getenv("SENDER_EMAIL")

    if not api_key or not sender:
        print("⚠️ SendGrid API key or SENDER_EMAIL not set.")
        print("Email content for debug:", content_text)
        return False

     from_name = "Vansh Portfolio"
    content_text += "\n\n--\nThis message was sent automatically by Vansh Portfolio."

    url = "https://api.sendgrid.com/v3/mail/send"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    data = {
        "personalizations": [{"to": [{"email": to_email}], "subject": subject}],
        "from": {"email": sender},
        "content": [{"type": "text/plain", "value": content_text}]
    }

    try:
        resp = requests.post(url, headers=headers, json=data, timeout=10)
        if resp.status_code in (200, 202):
            return True
        else:
            print("SendGrid error:", resp.status_code, resp.text)
            return False
    except Exception as e:
        print("Exception sending email:", e)
        return False


def send_verification_email(to_email, code):
    subject = "Your Verification Code"
    body = f"Your verification code is: {code}"
    return send_email_via_sendgrid(to_email, subject, body)

# -------- ROUTES -----------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/skills')
def skills():
    return render_template('skills.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        message = request.form.get('message', '').strip()

        if not name or not email or not message:
            flash('All fields are required.')
            return redirect(url_for('contact'))

        subject = "New Contact Form Submission"
        body = f"Name: {name}\nEmail: {email}\nMessage:\n{message}"

        owner_email = os.getenv("SENDER_EMAIL")
        if not owner_email:
            flash("Server email not configured. Please contact site owner directly.")
            return redirect(url_for('contact'))

        success = send_email_via_sendgrid(owner_email, subject, body)
        if success:
            flash("Message sent successfully!")
        else:
            flash("Error sending message. Try again later.")
        return redirect(url_for('contact'))

    return render_template('contact_us.html')

@app.route('/pricing')
def pricing():
    if 'user' not in session:
        flash("Please log in to view premium pricing plans.")
        return redirect(url_for('login'))
    return render_template('pricing.html')

@app.route('/payment')
def payment():
    if 'user' not in session:
        flash("Please log in to make a payment.")
        return redirect(url_for('login'))
    return render_template('payment.html')

# -------- SIGNUP + EMAIL VERIFICATION --------

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not username or not email or not password:
            flash("All fields are required.")
            return redirect(url_for('signup'))

        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return redirect(url_for('signup'))

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            flash("Username already exists.")
            return redirect(url_for('signup'))

        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        if c.fetchone():
            conn.close()
            flash("Email already registered.")
            return redirect(url_for('signup'))

        conn.close()

        verification_code = ''.join(random.choices(string.digits, k=6))
        session['signup_data'] = {
            'username': username,
            'email': email,
            'password': password,
            'verification_code': verification_code
        }

        sent = send_verification_email(email, verification_code)
        if sent:
            flash("Verification code sent to your email.")
            return redirect(url_for('verify_code'))
        else:
            print("Verification code (not emailed):", verification_code)
            flash("Could not send verification email. Try again later.")
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    signup_data = session.get('signup_data')
    if not signup_data:
        flash("Please start signup again.")
        return redirect(url_for('signup'))

    if request.method == 'POST':
        input_code = request.form.get('code', '').strip()
        if not input_code:
            flash("Please enter the verification code.")
            return redirect(url_for('verify_code'))

        if input_code == signup_data.get('verification_code'):
            hashed_password = generate_password_hash(signup_data.get('password'))
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            try:
                c.execute(
                    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (signup_data.get('username'), signup_data.get('email'), hashed_password)
                )
                conn.commit()
            except sqlite3.IntegrityError:
                flash("Username or Email already exists.")
                conn.close()
                return redirect(url_for('signup'))
            conn.close()

            session.pop('signup_data', None)
            flash("Signup successful! Please log in.")
            return redirect(url_for('login'))
        else:
            flash("Incorrect code. Try again.")
            return redirect(url_for('verify_code'))

    return render_template('verify_code.html')

# -------- LOGIN -----------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash("All fields are required.")
            return redirect(url_for('login'))

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session['user'] = user[1]
            flash("Login successful!")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash("Please log in to access your dashboard.")
        return redirect(url_for('login'))

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT AVG(rating) FROM ratings")
    avg_rating = c.fetchone()[0]
    avg_rating = round(avg_rating, 2) if avg_rating else "No ratings yet"

    c.execute("SELECT username, rating FROM ratings ORDER BY id DESC LIMIT 5")
    recent_ratings = c.fetchall()
    conn.close()

    return render_template('dashboard.html', avg_rating=avg_rating, recent_ratings=recent_ratings)

@app.route('/rate', methods=['POST'])
def rate():
    if 'user' not in session:
        flash("Please log in to rate.")
        return redirect(url_for('login'))

    rating = request.form.get('rating', '')
    if not rating.isdigit() or int(rating) < 1 or int(rating) > 5:
        flash("Rating must be between 1 and 5.")
        return redirect(url_for('dashboard'))

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO ratings (username, rating) VALUES (?, ?)", (session['user'], int(rating)))
    conn.commit()
    conn.close()

    flash("Thank you for your rating!")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out successfully.")
    return redirect(url_for('index'))

# -------- POLICIES & SUPPORT ----------

@app.route('/privacy')
def privacy_policy():
    return render_template('privacy_and_policy.html')

@app.route('/shipping')
def shipping_policy():
    return render_template('shipping.html')

@app.route('/refund')
def refund_policy():
    return render_template('refund_policy.html')

@app.route('/help_and_support')
def help_and_support():
    return render_template('help_and_support.html')

@app.route('/help_and_support/delete_account', methods=['GET', 'POST'])
def help_and_support_delete_account():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()

        if not username or not email:
            flash("Both fields are required.")
            return redirect(url_for('help_and_support_delete_account'))

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND email = ?", (username, email))
        user = c.fetchone()
        conn.close()

        if not user:
            flash("User not found.")
            return redirect(url_for('help_and_support_delete_account'))

        verification_code = ''.join(random.choices(string.digits, k=6))
        session['delete_account_data'] = {
            'username': username,
            'email': email,
            'verification_code': verification_code
        }

        sent = send_verification_email(email, verification_code)
        if sent:
            flash("Verification code sent. Please check your email.")
            return redirect(url_for('help_and_support_verify_delete_code'))
        else:
            print("Delete-account verification code (not emailed):", verification_code)
            flash("Could not send verification email. Try again later.")
            return redirect(url_for('help_and_support_delete_account'))

    return render_template('help_and_support_delete_account.html')

@app.route('/help_and_support/verify_delete_code', methods=['GET', 'POST'])
def help_and_support_verify_delete_code():
    data = session.get('delete_account_data')
    if not data:
        flash("Please start the deletion process again.")
        return redirect(url_for('help_and_support_delete_account'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        if not code:
            flash("Enter the verification code.")
            return redirect(url_for('help_and_support_verify_delete_code'))

        if code == data.get('verification_code'):
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("DELETE FROM users WHERE username = ? AND email = ?", (data.get('username'), data.get('email')))
            conn.commit()
            conn.close()
            session.pop('delete_account_data', None)
            flash("Account deleted successfully.")
            return redirect(url_for('index'))
        else:
            flash("Incorrect verification code.")
            return redirect(url_for('help_and_support_verify_delete_code'))

    return render_template('verify_code.html')  # ✅ Correct template

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

