import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///reviews.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
def home():

    return render_template("home.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # Check registration criteria if request method is POST
    if request.method == "POST":
        # Makes sure that a username was entered
        if not request.form.get("username"):
            return apology("Please enter a username.")

        # Makes sure that a password was entered
        elif not request.form.get("password"):
            return apology("Please enter a password.")

        # Makes sure the confirmation password was entered
        elif not request.form.get("confirmation"):
            return apology("Please confirm your password.")

        # Makes sure both passwords match
        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("Oh no! Your passwords did not match.")

        # Insert new user into table of existing users
        hash = generate_password_hash(request.form.get("password"))
        try:
            new_user = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)",
                                  username=request.form.get("username"), hash=hash)
        except ValueError:
            return apology("That username has already been taken. Try another one.")

        # Remember the user that just logged in
        session["user_id"] = new_user

        # Return user to homepage
        return redirect("/")

    # Display form to user if method is GET
    else:
        return render_template("register.html")

@app.route("/about", methods=["GET", "POST"])
def about():
    return render_template("about.html")

@app.route("/restaurants", methods=["GET", "POST"])
def restaurants():

    restaurants = db.execute("SELECT * FROM reviews")
    if request.method == "POST":
        return redirect("/")
    else:
        return render_template("restaurants.html", restaurants=restaurants)


@app.route("/Life Alive", methods=["GET", "POST"])
def LifeAlive():
     if request.method == "POST":
        return redirect("/")
     else:
        return render_template("Life Alive.html")

@app.route("/Veggie Grill", methods=["GET", "POST"])
def VeggieGrill():
     if request.method == "POST":
        return redirect("/")
     else:
        return render_template("Veggie Grill.html")
