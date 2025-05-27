from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
import ssl
import os

app = Flask(__name__)
app.secret_key = 'myverysecretkey1234567890'

DB_PATH = os.path.join(os.getcwd(), 'users.db')

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
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

# Home routes
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
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        if not name or not email or not message:
            flash('All fields are required.')
            return redirect(url_for('contact'))

        sender_email = "vanshaggarwal076@gmail.com"
        receiver_email = "vanshaggarwal076@gmail.com"
        app_password = "rrtw ebep evpb hhip"

        subject = "New Contact Form Submission"
        body = f"Name: {name}\nEmail: {email}\nMessage:\n{message}"
        email_text = f"Subject: {subject}\n\n{body}"

        context = ssl.create_default_context()
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
                server.login(sender_email, app_password)
                server.sendmail(sender_email, receiver_email, email_text)
            flash("Message sent successfully!")
        except Exception as e:
            flash(f"Error sending message: {e}")
        return redirect(url_for('contact'))

    return render_template('contact.html')

@app.route('/pricing')
def pricing():
    if 'user' not in session:
        flash("Please log in to view premium pricing plans.")
        return redirect(url_for('login'))
    return render_template('pricing.html')

@app.route('/payment')
def payment():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('payment.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not username or not email or not password:
            flash("All fields are required.")
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                      (username, email, hashed_password))
            conn.commit()
            conn.close()
            flash("Signup successful! Please log in.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists.")
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash("All fields are required.")
            return redirect(url_for('login'))

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session['user'] = user[1]  # Keeps user signed in
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

    rating = request.form.get('rating')
    if not rating or not rating.isdigit() or int(rating) < 1 or int(rating) > 5:
        flash("Please provide a valid rating between 1 and 5.")
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

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
