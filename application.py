import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

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


@app.route("/")
@login_required
def index():
    #Selects the symbol info from db

    stock_symbols = db.execute("SELECT symbol FROM transactions WHERE u_id=:u_id GROUP BY symbol;", u_id=session['user_id'])
    grand_total = 0

    #selects the user data from users table


    if stock_symbols != []:
        stocks = []
        current_cash = db.execute("SELECT cash FROM users WHERE id = :user_id;", user_id=session['user_id'])

        for symbol in stock_symbols:
            symbol_data = lookup(symbol['symbol'])
            stock_shares = db.execute("SELECT SUM(quantity) FROM transactions WHERE u_id=:u_id AND symbol = :symbol;", \
            u_id=session['user_id'], symbol=symbol_data['symbol'])
            if stock_shares[0]['SUM(quantity)'] == 0:
                continue
            else:
                stock_info = {}

                stock_info['name'] = symbol_data['name']
                stock_info['symbol'] = symbol_data['symbol']
                stock_info['price'] = symbol_data['price']
                stock_info['shares'] = stock_shares[0]['SUM(quantity)']
                stock_info['total'] = stock_info['shares'] * stock_info['price']

                stocks.append(stock_info)

        for i in range(len(stocks)):
            grand_total += stocks[i]['total']
            grand_total += current_cash[0]['cash']

        for i in range(len(stocks)):
            stocks[i]['price'] = usd(stocks[i]['price'])
            stocks[i]['total'] = usd(stocks[i]['total'])

        return render_template("index.html", stocks=stocks, current_cash=usd(current_cash[0]['cash']), grand_total=usd(grand_total))

    else:
        current_cash = db.execute("SELECT cash FROM users WHERE id=:user_id;", user_id=session['user_id'])
        return render_template("index.html", current_cash=usd(current_cash[0]['cash']), grand_total = usd(current_cash[0]['cash']))

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # check if valid input
        try:
            symbol = lookup(request.form.get("symbol"))
            shares = int(request.form.get("shares"))
        except:
            return apology("enter some input")

        # if symbol is empty return apology
        if not symbol:
            return apology("enter a valid symbol")

        # if shares is empty
        if not shares or shares <= 0:
            return apology("enter the quantity of shares")

        # if can't afford to buy then error
        # get cash from db
        cashOnHand = db.execute("SELECT cash FROM users WHERE id=:user_id;", user_id=session["user_id"])
        cashOnHand = int(cashOnHand[0]['cash'])
        if (shares * symbol['price']) > cashOnHand:
            return apology("can't afford")
        else:
            db.execute("INSERT INTO transactions (symbol, quantity, price, u_id) VALUES (:symbol, :quantity, :price, :u_id);", \
            symbol=symbol['symbol'], quantity=shares, price=symbol['price'], u_id=session["user_id"])
            # update cash (define old_balance)
            db.execute("UPDATE users SET cash=cash-:total_price WHERE id=:user_id;", total_price=shares*symbol['price'], \
            user_id=session["user_id"])
            return redirect(url_for("index"))

    else:
        return render_template("buy.html")



@app.route("/history")
@login_required
def history():
     transactions= db.execute("SELECT symbol, quantity,time_stamp, price FROM transactions WHERE u_id=:u_id", u_id=session['user_id'])

     return render_template("history.html",transactions=transactions)



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

        flash("logged in")

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
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))
        if not quote:
            return apology("stock not found")
        else:
            return render_template("quoted.html",quote=quote)
    else:
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        elif not request.form.get("confirmation"):
            return apology("must provide password again")

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("your password doesn't match")


        # insert the user data into the database
        result = db.execute("INSERT INTO Users (username, hash) \
                             VALUES(:username, :hash)",  \
                             username=request.form.get("username"), \
                             hash=generate_password_hash(request.form.get("password")))

        if not result:
            return apology("Username already exists")


        session["user_id"] = result

        # Redirect user to home page

        flash("registerd")

        return redirect("/")



    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        # check if valid input
        try:
            symbol = lookup(request.form.get("symbol"))
            shares = int(request.form.get("shares"))
        except:
            return apology("enter some input")

        # if symbol is empty return apology
        if not symbol:
            return apology("enter a valid symbol")

        # if shares is empty
        if not shares or shares <= 0:
            return apology("enter the quantity of shares")

        stocks_held = db.execute("SELECT SUM(quantity) FROM transactions WHERE u_id=:u_id AND symbol=:symbol;",  u_id=session['user_id'], symbol=symbol['symbol'])

        if not stocks_held[0]['SUM(quantity)'] :
            return apology("you don't own this stock")

        # is shares less or = to the stocks held?
        if shares > stocks_held[0]['SUM(quantity)']:
            return apology("you don't own that many stocks")

        # enter a new transaction in transactions
            # ensure a sale is a negative number
        db.execute("INSERT INTO transactions (symbol, quantity, price, u_id) VALUES (:symbol, :quantity, :price, :u_id);", \
        symbol=symbol['symbol'], quantity=-shares, price=symbol['price'], u_id=session["user_id"])

        # update cash
        db.execute("UPDATE users SET cash = cash + :total_price  WHERE id = :user_id;", total_price=shares*symbol['price'], \
        user_id=session["user_id"])

        shares_total=stocks_held[0]['SUM(quantity)']-shares


        # if after decrement is zero, delete shares from portfolio
        if shares_total == 0:
            db.execute("DELETE FROM transactions \
                        WHERE u_id=:u_id AND symbol=:symbol", \
                        u_id=session["user_id"], \
                        symbol=symbol["symbol"])
        # otherwise, update portfolio shares count
        else:
            db.execute("UPDATE transactions SET quantity=:quantity \
                    WHERE u_id=:u_id AND symbol=:symbol", \
                    quantity=shares_total, u_id=session["user_id"], \
                    symbol=symbol["symbol"])

        return redirect(url_for('index'))

    else:
        return render_template("sell.html")


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
