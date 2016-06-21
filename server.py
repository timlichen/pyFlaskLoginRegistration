from flask import Flask, render_template, redirect, request, session, flash
from mysqlconnection import MySQLConnector
import re
from flask.ext.bcrypt import Bcrypt
app = Flask(__name__)
app.secret_key = "yeeee"
bcrypt = Bcrypt(app)
mySql = MySQLConnector(app, 'login_registration')

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
number_check = re.compile(r'^[a-zA-Z]+$')

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    errFlag = False

    if not number_check.match(request.form['first_name']):
        flash("Only letters can be used in first name!")
        errFlag = False
    if not number_check.match(request.form['last_name']):
        flash("Only letters can be used in last name!")
        errFlag = True
    if len(request.form['email']) < 1:
        flash("Email cannot be blank!")
        errFlag = True
    if not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email Address!")
        errFlag = True
    if len(request.form['first_name']) < 1:
        flash("First name cannot be blank!")
        errFlag = True
    if len(request.form['last_name']) < 1:
        flash("Last name cannot be blank!")
        errFlag = True
    if len(request.form['password']) < 1:
        flash("Password cannot be blank!")
        errFlag = True
    if not request.form['password'] == request.form['cPassword']:
        flash("Passwords don't match!")
        errFlag = True

    if not errFlag:
        password = request.form['password']
        pw_hash = bcrypt.generate_password_hash(password)
        insert_query = "INSERT INTO users (email, first_name, last_name, password, created_at, updated_at) VALUES (:email, :first_name, :last_name, :password, NOW(), NOW())"
        q_data = {
            'email': request.form['email'],
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'password': pw_hash
        }
        mySql.query_db(insert_query, q_data)

        flash("Successfully Registered!")

    return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    errFlag = False
    if not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email Address!")
        errFlag = True

    if len(request.form['password']) < 1:
        flash("Password cannot be blank!")
        errFlag = True

    if not errFlag:
        password = request.form['password']
        login_query = "SELECT password from users WHERE email = :email LIMIT 1"
        data = {
            'email': request.form['email']
        }
        login_data = mySql.query_db(login_query, data)
        if len(login_data) == 1:
            if bcrypt.check_password_hash(login_data[0]['password'], password):
                flash("Successfully Logged In!")
                return redirect('/')
            else:
                flash("Failed to Login!")
                return redirect('/')
    else:
        return redirect('/')
app.run(debug=True)
