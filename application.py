import os
import re
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # PROCESSING and OUTPUT - Gets rows from SQL table 'purchases' from the current user
    # Gets current username
    row = db.execute("SELECT username from users where id = ?", session["user_id"])
    username = row[0]["username"]

    # PROCESSING - Checks if user already has any remaining shares. If there are no shares, then only display CASH with user's remaining cash
    query = "SELECT symbol, company, sum(shares) as shares, price, sum(total) as total from purchases where username = ? group by symbol"
    rows = db.execute(query, username)

    # If user purchased shares, then render template passing in rows and the usd function to format price and total fields
    empty = True
    if len(rows) != 0:
        empty = False

    # Pass in user's rows and cash. If empty is false, then rows will be displayed. If empty is true, then cash will only be displayed.
    # Also pass in user's grand total (total price of stocks + cash)
    row = db.execute("SELECT cash from users where username = ?", username)
    cash = row[0]["cash"]

    row = db.execute("SELECT sum(total) as total from purchases where username = ?", username)
    total = row[0]["total"]

    # If total doesn't exist, then set grandTotal to be equal to cash amount
    if total == None:
        grandTotal = cash
    # Otherwise, grandTotal is total + cash
    else:
        grandTotal = float(total) + float(cash)

    return render_template("index.html", rows=rows, cash=cash, usd=usd, empty=empty, grandTotal=grandTotal)


# buy() - Allows users to buy shares of stock
@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # if request method is GET, return the buy web page form
    if request.method == "GET":
        return render_template("buy.html")

    # Otherwise, continue the purchase process and relay message at the end
    # INPUT/PROCESSING - checks if symbol is not found or is empty
    symbol = request.form.get("symbol")
    if not symbol or lookup(symbol.upper()) == None:
        return apology("Symbol is empty or does not exist", 403)
    symbol = symbol.upper()

    # INPUT/PROCESSING - checks if shares empty and if shares is not an integer
    if not request.form.get("shares"):
        return apology("Must input number of shares")\

    try:
        shares = int(request.form.get("shares"))
    except ValueError:
        return apology("Must input a number")

    # checks if shares is not positive
    if shares <= 0:
        return apology("Must input a positive value")

    # PROCESSING - Compares the price of the stock * the number of shares to the amount of cash the user has left
    # if price is greater than cash remaining, then render an apology
    stockQuotes = lookup(symbol)
    price = stockQuotes["price"]
    totalPrice = price * shares
    userRow = db.execute("SELECT * from users where id = ?", session["user_id"])
    userCash = float(userRow[0]["cash"])

    if totalPrice > userCash:
        return apology("Can't afford the number of shares", 403)

    # INPUT - current user's name, the comapny of the given symbol, current time which is then converted to a time format
    userName = userRow[0]["username"]
    company = stockQuotes["name"]
    timeNow = datetime.now()
    timeNow = timeNow.strftime("%Y-%m-%d %H:%M:%S")

    # PROCESSING - Checks if user already purchased the product before. If so: shares, price, time, and total will be updated
    # If not, then the new symbol along with its information will be added to the 'purchases' table
    symbolRows = db.execute("SELECT * from purchases where symbol = ? and username = ?", symbol, userName)
    if len(symbolRows) > 0:
        db.execute("UPDATE purchases set shares = shares + ? where symbol = ? and username = ?", shares, symbol, userName)
        db.execute("UPDATE purchases set price = ? where symbol = ? and username = ?", price, symbol, userName)
        db.execute("UPDATE purchases set total = shares * price where symbol = ? and username = ?", symbol, userName)
        db.execute("UPDATE purchases set time = ? where symbol = ? and username = ?", timeNow, symbol, userName)
    else:
        query = "INSERT into purchases (username, symbol, company, shares, price, total, time) VALUES (?, ?, ?, ?, ?, ?, ?)"
        db.execute(query, userName, symbol, company, shares, price, totalPrice, timeNow)

    # UPDATES cash for user in users table
    newCash = userCash - totalPrice
    query = "UPDATE users SET cash = ? where username = ?"
    db.execute(query, newCash, userName)

    # INPUT - Inserts corresponding information into history table: username, symbol, shares, price, transaction (time)
    db.execute("INSERT into history VALUES (?, ?, ?, ?, ?)", userName, symbol, shares, price, timeNow)

    # redirects to main index page with relay message
    flash("Bought!")
    return redirect("/")

# history() - Displays contents from the 'history' table onto the history.html file
@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Gets username
    row = db.execute("SELECT username from users where id = ?", session["user_id"])
    username = row[0]["username"]

    # RETURNS rows from 'history' table for the current user
    historyRows = db.execute("SELECT * from history where username = ?", username)

    # SENDS to history.html the historyRows variable to be displayed along with the usd function
    return render_template("history.html", historyRows=historyRows, usd=usd)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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


# quote() - Allows users to lookup information regarding a particular stock symbol. After user inputs a symbol, return render_template("quoted.html")
# to return information regarding the given symbol
@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "GET":
        return render_template("quote.html")
    else:
        # Calls on lookup function to return stock quotes of given symbol
        symbol = request.form.get("symbol").upper()
        stockQuotes = lookup(symbol)

        # If stockQuotes aren't found, return an apology
        if stockQuotes == None:
            return apology("Can't find item you're looking for")

        # Otherwise, return rendered template of quoted.html which shows the price of the stock you're looking for
        companyName = stockQuotes["name"]
        stockPrice = stockQuotes["price"]

        #OUTPUT - Passes to quoted.html the companyName, price, and symbol for output
        return render_template("quoted.html", company=companyName,
                                price=usd(stockPrice), symbol=symbol)


# register() - allows users to register for an account. Checks for valid inputs. Redirects to index page once registered
@app.route("/register", methods=["GET", "POST"])
def register():
    # Forget any user_id
    session.clear()

    # if request method is GET, then just return the register.html page
    if request.method == "GET":
        return render_template("register.html")
    # Otherwise, check for user inputs and register new user
    else:
        #INPUT - variables correspond to user input
        userName = request.form.get("username")
        passWord = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # PROCESSING - checks if username exists or is empty, returns apology if
        # either of these conditions are true
        query = "Select * from users where username = ?"
        userNameRow = db.execute(query, userName)

        if len(userNameRow) == 1 or not userName:
            return apology("Must provide username or username exists", 403)

        # PROCESSING - checks if password or confirmation are empty or don't match
        # returns apology if either of these conditions are true
        if not passWord or not confirmation:
            return apology("Must fill in password fields", 403)

        if passWord != confirmation:
            return apology("Passwords do not match", 403)

        if not IsValid(passWord):
            return apology("Password requirements not met", 403)


        hashedPassword = generate_password_hash(passWord)
        db.execute("INSERT into users (username, hash) VALUES (?, ?)", userName, hashedPassword)

        # PROCESSING - Creates session using new user's id
        query = "Select * from users where username = ?"
        rows = db.execute(query, userName)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        return redirect("/")


# sell() - Allows current user to sell shares. Will validate for current stocks in hold, and the number of shares that the user
# desires to sell. Will update cash for user. RETURNS redirect to index
@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # INPUT & PROCESSING - Gets username and the symbol rows that the user already has from purchases table
    row = db.execute("SELECT username from users where id = ?", session["user_id"])
    username = row[0]["username"]
    symbolRows = db.execute("SELECT symbol from purchases where username = ? group by symbol having sum(shares) > 0", username)

    # OUTPUT - If request method is GET, then display symbol rows for the symbols custom selector
    if request.method == "GET":
        return render_template("sell.html", symbolRows=symbolRows)

    # Check for stock input (if not selected or the user doesn't own any shares of the given symbol)
    symbol = request.form.get("symbol")
    if not symbol or len(symbolRows) == 0:
        return apology("Select a symbol or you have no stocks left", 403)

    symbol = symbol.upper() # update symbol to upper case

    # PROCESSING - Error check shares if it's empty, not an integer, if it's not positive, or if user can't afford that many shares
    if not request.form.get("shares"):
        return apology("Can't leave shares empty")

    try:
        sharesInput = int(request.form.get("shares"))
    except ValueError:
        return apology("Must input a number")

    if sharesInput <= 0:
        return apology("Must input a positive value")

    # get number of shares of the particular symbol that user inputted to sell and checks whether input is larger than actual shares left
    sharesRow = db.execute("Select sum(shares) as shares from purchases where username = ? and symbol = ?", username, symbol)
    actualShares = int(sharesRow[0]["shares"])
    if actualShares < sharesInput:
        return apology("Not enough shares to sell")

    # Gets shares remaining. Gets new updated price of given symbol using lookup(). And calculates totalPrice
    sharesRemaining = actualShares - sharesInput
    stockQuotes = lookup(symbol)
    price = stockQuotes["price"]
    totalPrice = price * sharesInput

    # TIME for current transaction
    timeNow = datetime.now()
    timeNow = timeNow.strftime("%Y-%m-%d %H:%M:%S")

    # PROCESSING - If sharesRemaining is 0, then delete from the 'purchases' table where the symbol is
    # Otherwise, (in the 'purchases' table) update shares to be sharesRemaining, price to be current price, total (shares * price), and time
    if sharesRemaining == 0:
        db.execute("DELETE from purchases where username = ? and symbol = ?", username, symbol)
    else:
        db.execute("UPDATE purchases set shares = ?, price = ?, time = ? where username = ? and symbol = ?",
                    sharesRemaining, price, timeNow, username, symbol)
        db.execute("UPDATE purchases set total = shares * price where username = ? and symbol = ?", username, symbol)

    # UPDATE cash for the user table in 'users' so that totalPrice is added to it
    userCashRow = db.execute("SELECT cash from users where username = ?", username)
    userCash = userCashRow[0]["cash"]
    actualCash = userCash + totalPrice
    db.execute("UPDATE users set cash = ? where username = ?", actualCash, username)

    # INPUT - Inserts corresponding information into history table: username, symbol, shares (negative), price, transaction (time)
    db.execute("INSERT into history VALUES (?, ?, ?, ?, ?)", username, symbol, -sharesInput, price, timeNow)

    flash("Sold!")
    return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)

# Checks if password is valid
def IsValid(password):
    isValid = True

    # Checks for password validity
    # Length is at least 8. Contains a lowercase letter, an  uppercase letter, and a number. No spaces allowed
    while(isValid):
        if(len(password) < 8 or len(password) > 20):
            isValid = False
        elif not re.search("[a-z]", password):
            isValid = False
        elif not re.search("[A-Z]", password):
            isValid = False
        elif not re.search("[0-9]", password):
            isValid = False
        elif re.search(" ", password):
            isValid = False
        # password is valid
        else:
            break
    return isValid

# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
