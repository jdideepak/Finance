import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

# stuff I added

from datetime import datetime

# stuff I added ends here

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

    # 1) Pass cash value
    # 2) Pass symbol, company name, shares, current_price, total_handling

    # Extracting cash value
    cash = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])[0]["cash"]

    # 2)

    rowData = db.execute("SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id=:id GROUP BY symbol", id=session["user_id"])
    #print(rowData)

    sum_total = 0

    for dict_item in rowData:
        lookup_dict = lookup(dict_item["symbol"])
        dict_item["name"] = lookup_dict["name"]
        dict_item["current_stock_price"] = lookup_dict["price"]
        dict_item["holding"] = dict_item["current_stock_price"] * dict_item["total_shares"]
        sum_total += dict_item["holding"]
        dict_item["holding"] = usd(dict_item["holding"])
        dict_item["current_stock_price"] = usd(dict_item["current_stock_price"])

    #print(rowData)


    #symbol = rowData[0]["symbol"]

    #total_shares = rowData[0]["total_shares"]

    #lookup_dict = lookup(request.form.get("symbol"))
    #current_price = lookup_dict["price"]
    #company_name = lookup_dict["name"]

    #total_handling = total_shares * current_price

    sum_total = cash + sum_total

    return render_template("index.html", cash=usd(cash), stock_info=rowData, sum_total=usd(sum_total))
#    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        lookup_dict = lookup(request.form.get("symbol"))
        now = datetime.now()
        formatted_date = now.strftime('%Y-%m-%d %H:%M:%S')

        if not lookup_dict:
            return apology("stock symbol not found")

        #print(lookup_dict)

        shares = float(request.form.get("shares"))

        if shares <= 0:
            return apology("shares must be positive")

        query = db.execute("SELECT username FROM users WHERE id=:id", id=session["user_id"])
        #print(query[0]["username"])
        user_available_balance_raw = db.execute("SELECT cash FROM users WHERE username=:username", username=query[0]["username"])

        user_available_balance = float(user_available_balance_raw[0]["cash"])

        stock_price = float(lookup_dict["price"])
        stock_name = lookup_dict["name"]

        if shares * stock_price > user_available_balance :
            return apology("you don't have required balance for this transaction")

        # Error Checking is done successfully

        balance_left = user_available_balance - shares * stock_price

        db.execute("UPDATE users SET cash = :balance_left WHERE id = :user_id", balance_left=balance_left, user_id=session["user_id"])

        # if symbol already exists, update shares value
        query_symbol = db.execute("SELECT symbol FROM transactions WHERE user_id=:user_id", user_id=session["user_id"])
        print(query_symbol)

        current_stock_symbols = []
        for dict_item in query_symbol:
            current_stock_symbols.append(dict_item["symbol"])


        if request.form.get("symbol") in current_stock_symbols:
            new_shares = shares + db.execute("SELECT shares FROM transactions WHERE user_id=:user_id AND symbol=:symbol", user_id=session["user_id"], symbol=request.form.get("symbol"))[0]["shares"]
            db.execute("UPDATE transactions SET shares=:new_shares WHERE user_id=:user_id AND symbol=:symbol", new_shares=new_shares , user_id=session["user_id"], symbol=request.form.get("symbol").upper())

        # if symbol doesn't exists, insert a new value in table
        else:
            db.execute("INSERT INTO transactions ('symbol', 'user_id', 'shares', 'user_id') VALUES (:symbol, :user_id, :shares, :user_id)", symbol=request.form.get("symbol"), shares=shares, user_id=session["user_id"])

        db.execute("INSERT INTO history (symbol, user_id, shares, price, transacted) VALUES (:symbol, :user_id, :shares, :price, :transacted)", symbol=request.form.get("symbol"), user_id=session["user_id"], shares=shares, price=stock_price, transacted=formatted_date)

        flash("You successfully bought {} shares of {}.".format(round(shares), stock_name))
        return redirect("/")

    else :
        return render_template("buy.html")
#    return apology("TODO")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    get_user = session["user_id"]

    query = db.execute("SELECT * FROM history WHERE user_id=:user_id", user_id=get_user)
    #print(query)

    return render_template("history.html", transactions=query)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            # flash("You must provide username")
            # return redirect("/login")
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            # flash("You must provide password")
            # return redirect("/login")
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            # flash("Invalid username and/or password")
            # return redirect("/login")
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash("Welcome!")
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
        lookup_dict = lookup(request.form.get("symbol"))

        if not lookup_dict:
            #return apology("stock symbol not found")
            flash("Stock symbol not found, Google to find stock symbols like NFLX for Netflix")
            return render_template("/quote")


        stock_price = lookup_dict["price"]
        stock_name = lookup_dict["name"]
        return render_template("quoted.html", stock_price=stock_price, stock_name=stock_name, symbol=request.form.get("symbol"))

    else :
        return render_template("/quote.html")
#    return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    """If request method is GET, show form in register.html template"""
    if request.method == "GET":
        return render_template("register.html")

    else:

        # Apology if username is None
        if not request.form.get("username"):
            #return apology("username can't be empty")
            flash("Username can't be empty")
            return redirect("/register")


        # Apology if password or confirmation is None
        if not request.form.get("password") or not request.form.get("confirmation"):
            #return apology("must provide password and confirm password")
            flash("You must provide password and confirm password")
            return redirect("/register")

        if request.form.get("password") != request.form.get("confirmation"):
            #return apology("confirmation password doesn't match")
            flash("Oops! Your confirmation password doesn't match")
            return redirect("/register")


        # Process for checking if typed username already exists
        current_users = db.execute("SELECT (username) FROM users")
        #print(row)

        username_list = []

        for dict_item in current_users:
            for value in dict_item.values():
                username_list.append(value)

        #print(username_list)

        if request.form.get("username") in username_list:
            #return apology("username already taken")
            flash("Ahh! Username already taken")
            return redirect("/register")


        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=request.form.get("username"), hash=generate_password_hash(request.form.get("password")))

        flash('Successfully registered you can login now!')
        return render_template("login.html")
#   Successfully completed Register
#   return apology("TODO")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():

    """Sell shares of stock"""

    """Pass names of stocks that user owns to sell.html"""
    rowQuery = db.execute("SELECT symbol FROM transactions WHERE user_id=:user_id", user_id=session["user_id"])
    #print(rowQuery)

    stock_owned_by_user = []
    for item in rowQuery:
        stock_owned_by_user.append(item["symbol"])

    if request.method == "POST":
        if not request.form.get("symbol") or request.form.get("symbol") not in stock_owned_by_user:
            return apology("invalid stock symbol")

        row_shares = db.execute("SELECT shares FROM transactions WHERE user_id=:user_id AND symbol=:symbol", user_id=session["user_id"], symbol=request.form.get("symbol"))
        current_shares = row_shares[0]["shares"]

        entered_shares = float(request.form.get("shares"))

        if entered_shares <= 0 or entered_shares > current_shares:
            return apology("you can't withdraw these many shares")

        # Error checking done

        # TODO
        # 1) update cash in users after sell is processed
        # 2) update transactions with left shares

        # 1) update cash in users after sell is processed
        lookup_dict = lookup(request.form.get("symbol"))
        now = datetime.now()
        formatted_date = now.strftime('%Y-%m-%d %H:%M:%S')

        if not lookup_dict:
            return apology("stock symbol not found")

        old_cash = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])[0]["cash"]
        print(f"old cash is {old_cash}")

        share_price = lookup_dict["price"]
        share_name = lookup_dict["name"]
        cash_added = old_cash + share_price * entered_shares
        db.execute("UPDATE users SET cash = :cash_added WHERE id = :user_id", cash_added=cash_added, user_id=session["user_id"])

        new_shares = current_shares - entered_shares
        db.execute("UPDATE transactions SET shares=:shares WHERE user_id=:user_id AND symbol=:symbol", shares=new_shares, user_id=session["user_id"], symbol=request.form.get("symbol"))

        db.execute("INSERT INTO history (symbol, user_id, shares, price, transacted) VALUES (:symbol, :user_id, :shares, :price, :transacted)", symbol=request.form.get("symbol"), user_id=session["user_id"], shares=-entered_shares, price=share_price, transacted=formatted_date)

        flash("You successfully sold {} shares of {}.".format(round(entered_shares), share_name))
        return redirect("/")

    else:
        return render_template("sell.html", stocks=stock_owned_by_user)

#    return apology("TODO")

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        new_password_confirmation = request.form.get("new_password_confirmation")
        if not old_password or not new_password or not new_password_confirmation:
            flash("Please provide valid credentials")
            return redirect("/change_password")
        if new_password != new_password_confirmation:
            flash("New password and New password confimation doesn't match")
            return redirect("/change_password")

        old_hash = db.execute("SELECT hash FROM users WHERE id=:id", id=session["user_id"])[0]["hash"]
        # if generate_password_hash(old_password) != old_hash:
        #     flash("Your old password is incorrect")
        #     return redirect ("/change_password")
        if not check_password_hash(old_hash, old_password):
            flash("You old password is incorrect")
            return redirect("/change_password")

        if new_password == old_password:
            flash("Your new password must be different from your old password")
            return redirect ("/change_password")

        new_hash = generate_password_hash(new_password)
        db.execute("UPDATE users SET hash=:hash WHERE id=:id", hash=new_hash, id=session["user_id"])
        session.clear()
        return render_template("/change_password_successful.html")

    else:
        return render_template("change_password.html")

@app.route("/change_password_successful")
def change_password_successful():
    return render_template("/change_password_successful.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
