from flask import Flask, render_template, request, redirect, session, flash
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL
import datetime
import re
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key="keep it a secret"
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['POST'])
def register():
    is_valid = True
    email_is_good = EMAIL_REGEX.match(request.form['email'])
    if len(request.form['fname']) < 2:
        is_valid = False
        flash("Please enter first name")
    if len(request.form['lname']) <2:
        is_valid = False
        flash("Please enter last name")
    if email_is_good is None:
        is_valid = False
        flash("Email invalid")
    mysql = connectToMySQL('private_wall')
    unique_email_query = "SELECT COUNT(*) FROM user WHERE email = (%(em)s);"
    data = {
        'em': request.form['email']
    }    
    db_response = mysql.query_db(unique_email_query, data)
    if len(db_response)> 0:
        flash('Email already exists!') 
    if len(request.form['password']) < 8:
        is_valid = False
        flash("Enter valid passsword!")
    if (request.form['confirm_pass']) != (request.form['password']):
        is_valid = False
        flash("Passwords dont match!")
    if is_valid:
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        mysql = connectToMySQL('private_wall')
        query = "INSERT INTO `login_registration`.`users` (`first_name`, `last_name`, `email`,`password` ) VALUES (%(fn)s, %(ln)s, %(em)s, %(pw)s );"
        data = {
            'fn': request.form['fname'],
            'ln': request.form['lname'],
            'em': request.form['email'],
            'pw': pw_hash
        }
        db = mysql.query_db(query, data)
        session['uid'] = db
        session['username'] =  request.form['fname']
        return redirect('/wall')
    return redirect('/')

@app.route ('/login', methods=['POST'])
def login():
    email_is_good = EMAIL_REGEX.match(request.form['l_email'])
    if email_is_good is None:
        is_valid = False
        flash("Login Failed")
        return redirect('/')
    if request.form['l_email'] == "":
        flash("Login Failed")
        return redirect('/')
    mysql = connectToMySQL('private_wall')
    login_query = "SELECT * FROM user WHERE email=%(em)s;"
    login_data = {
        'em': request.form['l_email'],
    }
    login_d = mysql.query_db(login_query, login_data)
    userid = login_d[0]['user_id']
    is_valid = True
    x=bcrypt.check_password_hash(login_d[0]['password'], request.form['l_pass'])
    if x == False:
        flash("Login Failed")
        return redirect('/')
    if is_valid:
        session['uid'] = userid
        session['username'] =  login_d[0]['first_name']
        return redirect('/wall')
    return redirect('/')

@app.route('/wall')
def success():
    mysql = connectToMySQL('private_wall')
    wall_query = mysql.query_db("SELECT * FROM user;")
    userid = session['uid']
    mysql = connectToMySQL('private_wall')
    wall_query2 = mysql.query_db(f"SELECT * FROM message WHERE user_user_id = {userid}")
    mysql = connectToMySQL('private_wall')
    wall_query3 = mysql.query_db(f"SELECT * FROM message WHERE sent_message = {userid}")
    wall_query3 = len(wall_query3)
    if 'username' in session:
        return render_template('wall.html', messages=wall_query, messages2=wall_query2, message3=wall_query3)
    else: 
        return redirect('/')

@app.route('/sent', methods=["POST"])
def sent_message():
    mysql = connectToMySQL('private_wall')
    mess_query = "INSERT INTO message (text_message, sent_message, user_user_id) VALUES (%(tm)s, %(sm)s, %(uu)s);"
    mess_data = {
        'tm': request.form['don_mess'],
        'sm': session['uid'],
        'uu': request.form ['reciever']
    }
    mysql.query_db(mess_query, mess_data)
    return redirect('/wall')
    
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')



if __name__ =="__main__":
    app.run(debug=True)