from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import mysql.connector

app = Flask(__name__)

# MySQL Configurations
# mysql root password = NewPassword123!
DB_CONFIG = {
    "host": "localhost",
    "user": "amul",
    "password": "YourSecurePassword",
    "database": "Booking_System"
}

app.config['SECRET_KEY'] = 'your_secret_key_here'  

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Function to establish a database connection
def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)


# User Model
class User(UserMixin):
    def __init__(self, id, username, email,role):
        self.id = id
        self.username = username
        self.email = email


# @login_manager.user_loader
# def load_user(user_id):
#     conn = get_db_connection()
#     cur = conn.cursor(dictionary=True)
#     cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
#     user = cur.fetchone()
#     cur.close()
#     conn.close()
    
#     return User(user['id'], user['username'], user['email'],user['role']) if user else None
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, username, email, role FROM users WHERE id = %s", (user_id,)) # Select role
    user = cur.fetchone()
    cur.close()
    conn.close()
    if user:
        return User(user['id'], user['username'], user['email'], user['role']) # Include role
    return None

# Home Page
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/book", methods=['GET', 'POST'])
def book():
    if request.method == 'POST':
        travel_type = request.form.get('travel-type')
        from_location = request.form.get('from')
        to_location = request.form.get('to')
        departure_date = request.form.get('departure')
        return_date = request.form.get('return')
        adults = request.form.get('adults')
        children = request.form.get('children')
        class_type = request.form.get('class_type')

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            cur.execute(
                "INSERT INTO bookings (travel_type, from_location, to_location, departure_date, return_date, adults, children, class_type, user_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (travel_type, from_location, to_location, departure_date, return_date, adults, children, class_type, current_user.id)
            )
            conn.commit()
            flash("Booking successful!", "success")
        except mysql.connector.Error as err:
            flash(f"Error: {err}", "danger")
        finally:
            cur.close()
            conn.close()
        return redirect(url_for('book'))

    return render_template("booking_form.html")

@app.route("/booking_history")
@login_required
def booking_history():
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    # Get the current user's username from session or login
    username = current_user.username  # Assuming `username` is in current_user

    # Query to join users and bookings on user_id (assuming a relationship)
    cur.execute("""
        SELECT b.* FROM bookings b
        JOIN users u ON u.id = b.user_id
        WHERE u.username = %s
    """, (username,))
    
    bookings = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("booking_history.html", bookings=bookings)



@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            # Check if the username already exists
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            existing_user = cur.fetchone()

            if existing_user:
                flash("Username already taken! Please choose a different one.", "danger")
                return redirect(url_for('signup'))

            # Insert new user if the username is unique
            cur.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                        (username, email, hashed_password))
            conn.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for('login'))
        
        except mysql.connector.IntegrityError:
            flash("An error occurred. Please try again.", "danger")
            return redirect(url_for('signup'))

        finally:
            cur.close()
            conn.close()

    return render_template('signup.html')


# @app.route("/signin", methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form.get('username')  
#         password = request.form.get('password')

#         if not username or not password:
#             flash("Username and password are required!", "danger")
#             return render_template('login.html')

#         conn = get_db_connection()
#         cur = conn.cursor(dictionary=True)
#         cur.execute("SELECT * FROM users WHERE username = %s", (username,))
#         user = cur.fetchone()
#         cur.close()
#         conn.close()

#         if user and bcrypt.check_password_hash(user['password_hash'], password):
#             user_obj = User(user['id'], user['username'], user['email'])
#             login_user(user_obj)
#             flash("Login successful!", "success")
#             if current_user.role == 'admin':
#                 return render_template('signup.html')
#             else:
#                 return render_template("dashboard.html")
#         else:
#             flash("Invalid username or password", "danger")

#     return render_template('login.html')

@app.route("/signin", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash("Username and password are required!", "danger")
            return render_template('login.html')

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, username, email, password_hash, role FROM users WHERE username = %s", (username,)) # added role to the select statement
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and bcrypt.check_password_hash(user['password_hash'], password):
            user_obj = User(user['id'], user['username'], user['email'], user['role'])
            login_user(user_obj)
            flash("Login successful!", "success")
            if user_obj.role == 'admin':
                return redirect(url_for('signup'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "danger")

    return render_template('login.html')

# Dashboard (Protected)
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template('dashboard.html')


# Logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for('login'))

# User Profile Route
@app.route("/profile")
@login_required
def profile():
    return render_template("user_profile.html", current_user=current_user)

if __name__ == "__main__":
    app.run(debug=True)

