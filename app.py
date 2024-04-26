import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, timestamp

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Inject global flask variable before each template is rendered
@app.context_processor
def inject_user_cash():
    if "user_id" in session:
        data = db.execute("SELECT cash, username, init_cash FROM users WHERE id=?", session["user_id"])

        try:
            return dict(user_cash=data[0]["cash"], username=data[0]["username"], user_initcash=data[0]["init_cash"])
        except:
            session.clear()
    else:
        return dict(user_cash=0, username="", user_initcash=0)


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Dynamically render a table summarizing for the user currently logged in:
    """
    - Which stocks the user owns
    - The numbers of shares owned
    - The current price of each stock
    - The total value of each holding.
    """

    # Initialize a table of dicts and acquire all owned stocks and their shares
    tabledata = []
    dbdata = db.execute("SELECT symbol, shares FROM ownership WHERE user_id=?", session["user_id"])
    totStocks = 0
    totShares = 0
    avgShare = 0.00
    totVal = 0.00

    if dbdata:
        for data in dbdata:
            sdata = lookup(data["symbol"])
            symbol = sdata["symbol"]
            shares = data["shares"]
            unitPrice = float(sdata["price"])
            totPrice = float(data["shares"]) * unitPrice
            stockData = {'symbol': symbol, 'shares': shares, 'unitPrice': usd(unitPrice), 'totVal': usd(totPrice)}
            tabledata.append(stockData)
            totStocks += 1
            totShares += data["shares"]
            totVal += totPrice
            avgShare += totPrice
        avgShare = avgShare / float(totShares)
        return render_template("index.html", tabledata=tabledata, totVal=usd(totVal), avgShare=usd(avgShare), totShares=totShares, totStocks=totStocks)
    else:
        return render_template("index.html", nostocks=1)



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        if request.form.get("symbol") == "":
            return render_template("buy.html", error="Invalid Stock")
        else:
            symbol = request.form.get("symbol")
            sdata = lookup(symbol)

            if sdata == None:
                return render_template("buy.html", error="Invalid Stock")
            else:
                if request.form.get("shares") == "":
                    amount = 1
                else:
                    if int(request.form.get("shares")) < 1:
                        return render_template("buy.html", error="No Stock Found")
                    amount = int(request.form.get("shares"))

                # Determine amount of money it would cost to purchase
                total =  amount * float(sdata["price"])


                # Display the purchase info before submitting to database
                if "verify" in request.form:
                    total = usd(total)
                    return render_template("buy.html", validstock=1, symbol=sdata["symbol"], total=total, shares=amount)

                # Verify user can afford purchase, alter cash amt, and store purchase data in db
                if "purchase" in request.form:
                    userdata = db.execute("SELECT * FROM users where id=?", session["user_id"])


                    # Verify user funds
                    if userdata[0]["cash"] < total:
                        return render_template("buy.html", error="Insufficient Funds")

                    # Store purchase data
                    EasternTime = timestamp()

                    # Store transaction history data
                    total = float(total)
                    db.execute("INSERT INTO transactions (user_id, symbol, unit_price, price, purchase_time, shares, type) VALUES (?, ?, ?, ?, ?, ?, ?)", session["user_id"], sdata["symbol"], sdata["price"], total, EasternTime, int(request.form.get("shares")), "Bought")

                    # Store ownership data
                    test = db.execute("SELECT shares FROM ownership WHERE symbol=? AND user_id=?", sdata["symbol"], session["user_id"])
                    # Append shares to get a total share count
                    if test:
                        updatedShares = int(test[0]["shares"]) + int(request.form.get("shares"))
                        db.execute("UPDATE ownership SET shares=? WHERE user_id = ? AND symbol = ?", updatedShares, session["user_id"], sdata["symbol"])
                    else:
                        updatedShares = int(request.form.get("shares"))
                        db.execute("INSERT INTO ownership (user_id, symbol, shares) VALUES (?, ?, ?)", session["user_id"], sdata["symbol"], updatedShares)
                    # Update user cash amount
                    updatedcash = float(userdata[0]["cash"]) - total
                    db.execute("UPDATE users SET cash = ? WHERE id = ?", updatedcash, session["user_id"])
                    return redirect("/")


    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Check for stocks in ownership
    confirm = db.execute("SELECT * FROM ownership WHERE user_id=?", session["user_id"])

    if confirm:
        data = db.execute("SELECT symbol, unit_price, shares, price, purchase_time, type FROM transactions WHERE user_id=? ORDER BY purchase_time DESC", session["user_id"])
        count = db.execute("SELECT COUNT(*) FROM transactions WHERE user_id=?", session["user_id"])

        return render_template("history.html", instances=data, total=count[0]["COUNT(*)"])
    else:
        return render_template("history.html", nostocks=1)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("login.html", error="Must provide Username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("login.html", error="Must provide Password")

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return render_template("login.html", error="Invalid Username and/or Password")

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # Check if the symbol form is empty, and display no stock found message
    if request.method == "POST":

        # Lookup stock symbol and get value
        symbol = request.form.get("symbol")
        sdata = lookup(symbol) # Get the value of the stock ticker
        if sdata == None:
            return render_template("quote.html", error="Invalid Ticker Symbol")
        else:
            symbol_value = usd(int(sdata["price"]))
            return render_template("quote.html", validstock=1, symbol=sdata["symbol"], sprice=symbol_value)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    # If the register form is submitted via POST
    if request.method == "POST":
        # Check for Username input
        if not request.form.get("username"):
            return render_template("register.html", error="Must provide username")

        # Check for password and confirmation
        if not request.form.get("password"):
            return render_template("register.html", error="Must provide a password")
        elif not request.form.get("confirmation"):
            return render_template("register.html", error="Must provide password confirmation")

        # Check if passwords match
        rpassword = request.form.get("password")
        rconfirmation = request.form.get("confirmation")
        if rpassword != rconfirmation:
            return render_template("register.html", error="Passwords must match")

        # Check if username is already in database
        user = request.form.get("username")
        user = user.strip()
        dbdata1 = db.execute("SELECT username FROM users WHERE username=?", user)
        dbuser = ""
        if dbdata1:
            dbuser = dbdata1[0]['username']
        if user == dbuser:
            return render_template("register.html", error="Username already taken")

        # If all checks passed, store username & hashed password in database
        # Hash password
        password = request.form.get("password")
        phash = generate_password_hash(password, method='pbkdf2', salt_length=16)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", user, phash)


        return render_template("register.html", registered=1)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # Dynamically populate the select form with databse info
    dbdata = db.execute("SELECT transaction_id, symbol, shares, unit_price FROM transactions WHERE user_id=?;", session["user_id"])
    ownershipData = db.execute("SELECT symbol, shares FROM ownership WHERE user_id=?", session["user_id"])

    # Remove duplicates out of database
    ulsymbols = []
    for symbols in ownershipData:
        ulsymbols.append(symbols["symbol"])

    ulsymbols = list(set(ulsymbols))
    # Check for no stock selected or user does not own any shares
    if request.method == "POST":

        # Check if no stock is submitted
        if request.form.get("symbol") == "":
            return render_template("sell.html", stocks=ulsymbols, error="No Stock Found")

        # Check for the input to range from 1 to MaxSharesOwned
        MaxSharesOwned = 0

        for shares in ownershipData:
            if shares["symbol"] == request.form.get("symbol"):
                shareAmt = int(shares["shares"])
                MaxSharesOwned = MaxSharesOwned + (shareAmt)


        # Check range 1 - max
        if float(request.form.get("shares")) < 1 or float(request.form.get("shares")) > MaxSharesOwned or float(request.form.get("shares")) % 1 != 0:
            return render_template("sell.html", stocks=ulsymbols, error="Invalid Amount of Shares")
        else:

            # Edit ownership shares, and update usercase
            # Multiply shares * the current price in the market
            shareAMT = request.form.get("shares")
            sdata = lookup(request.form.get("symbol"))
            dueBalance = float(shareAMT) * float(sdata["price"])
            db.execute("UPDATE users SET cash= cash + ? WHERE id=?", dueBalance, session["user_id"])

            print(MaxSharesOwned)
            MaxSharesOwned = MaxSharesOwned - int(request.form.get("shares"))
            print(MaxSharesOwned)

            # Calculate whether to delete outright from the database or subtract from shares
            if MaxSharesOwned == 0:
                db.execute("DELETE FROM ownership WHERE user_id=? AND symbol=?", session["user_id"], request.form.get("symbol"))
            else:
                db.execute("UPDATE ownership SET shares=? WHERE user_id=? AND symbol=?", MaxSharesOwned, session["user_id"], sdata["symbol"])

            time = timestamp()
            Total = float(sdata["price"]) * float(request.form.get("shares"))
            round(Total, 2)
            db.execute("INSERT INTO transactions (user_id, symbol, unit_price, shares, price, purchase_time, type) VALUES (?, ?, ?, ?, ?, ?, ?)", session["user_id"], sdata["symbol"], sdata["price"], int(request.form.get("shares")), Total, time, "Sold")
            return redirect("/")
    return render_template("sell.html", stocks=ulsymbols)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():

    if request.method == "POST":

        if "edit_udata" in request.form:
            user = request.form.get("username")
            current = request.form.get("currentpass")
            new = request.form.get("newpass")
            confirm = request.form.get("confirmpass")
            password = False
            username = False
            # Check for username in form request, and change the username
            if user != "":
                db.execute("UPDATE users SET username=? WHERE id=?", request.form.get("username"), session["user_id"])
                username = True
            # Check if all 3 password forms have data before making any changes
            if current and new and confirm != "":
                userdata = db.execute("SELECT * FROM users WHERE id=?", session["user_id"])
                # Check hash
                if not check_password_hash(userdata[0]["hash"], current):
                    return render_template("profile.html", perror="Invalid current Password")
                elif new != confirm:
                    return render_template("profile.html", perror="Passwords do not Match")
                else:
                    phash = generate_password_hash(new, method='pbkdf2', salt_length=16)
                    db.execute("UPDATE users SET hash=? WHERE id=?", phash, session["user_id"])
                    password = True
            if password and username:
                return render_template("profile.html", psuccess="Successfully changed Password", usuccess=f"Successfully changed to {user}")
            elif username:
                return render_template("profile.html", usuccess=f"Successfully changed to {user}")
            elif password:
                return render_template("profile.html", psuccess="Successfully changed Password")
        if "add$" in request.form:
            cash = request.form.get("cash")
            if cash == "" or cash == '0':
                return render_template("profile.html")
            cash = int(cash)

            if cash > 0:
                db.execute("UPDATE users SET cash = cash + ?, init_cash = init_cash + ? WHERE id=?", cash, cash, session["user_id"])
                return render_template("profile.html", cashsuccess=f"Successfully added {usd(cash)} to balance")
            else:
                return render_template("profile.html", casherror=f"Must be a Positive Number")


    return render_template("profile.html")
