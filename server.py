from flask import Flask, redirect, render_template, session, flash, request
from mysqlconnection import MySQLConnector
import flask_bcrypt
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

app = Flask(__name__)
bcrypt = flask_bcrypt.Bcrypt(app)
app.secret_key = "henlo"

mysql = MySQLConnector(app,'wall_db')

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/wall')
    return render_template('index.html')

@app.route('/register', methods=["POST"])
def register():
   #validate 
    valid = True
    form = request.form

    #first_name validation
    if form["first_name"] == "":
        valid = False
        flash("First name cannot be blank")

    elif not form["first_name"].isalpha():
        valid = False
        flash("First name must be alphabetical only")

    elif len(form["first_name"]) <= 2:
        valid = False
        flash("First name must be more than 2 characters")

    #last_name validation
    if form["last_name"] == "":
        valid = False
        flash("Last name cannot be blank")

    elif not form["last_name"].isalpha():
        valid = False
        flash("Last name must be alphabetical only")

    elif len(form["last_name"]) <= 2:
        valid = False
        flash("Last name must be more than 2 characters")

    #email validation
    if form["email"] == "":
        valid = False
        flash("Email cannot be blank")
    
    elif not EMAIL_REGEX.match(form['email']):
        valid = False
        flash("Not a valid email")

    #check if email already exists in db
    email_query = 'SELECT * FROM users WHERE email=:email'
    data = {
    'email': form['email']
    }
    user_list = mysql.query_db(email_query, data)

    if user_list:
        flash('Email already in use')
        return redirect('/')

    #password/confirm password validation
    if form["password"] == "":
        valid = False
        flash("Password cannot be blank")

    elif len(form["password"]) <= 8:
        valid = False
        flash("Password must be more than 8 characters")

    if form["confirm password"] == "":
        valid = False
        flash("Confirm password cannot be blank")

    if not form["password"] == form["confirm password"]:
        valid = False
        flash("confirm password does not match password")
    
    if not valid:
        return redirect('/')
    
    else:
        #bcrypt/pw hash
        pw_hash = bcrypt.generate_password_hash(form["password"])#--> values ":first_name", ":last_name", ":email" etc... are all made up variables. :spot_one, :spot_two...
        query = "INSERT INTO `wall_db`.`users` (`first_name`, `last_name`, `email`, `password`, `created_at`, `updated_at`) VALUES (:first_name, :last_name, :email, :password, NOW(), NOW());"
        data = {
            "first_name":form["first_name"],
            "last_name":form["last_name"],
            "email":form["email"],
            "password":pw_hash
        }
        mysql.query_db(query, data)    
        flash("You are now registered - Please login.")
        return redirect('/')

#login validation and bcrypt    
@app.route('/login',methods=["POST"])
def login():
    valid = True
    form = request.form
    #email validation
    if form["email"] == "":
        valid = False
        flash("Login email cannot be blank")
    
    elif not EMAIL_REGEX.match(form['email']):
        valid = False
        flash("Not a valid login email or password")

    if form["password"] == "":
        valid = False
        flash("Login password cannot be blank")

    if not valid:
        return redirect('/')

    else:
        query = "SELECT * FROM `wall_db`.`users` WHERE email = :email_data"
         #data: {"email_data" : form["email"]} 
        dbdata = mysql.query_db(query,{"email_data":form["email"]})  
        if len(dbdata) > 0: 
            user = dbdata[0] #this is the logged in user 
            if bcrypt.check_password_hash(user["password"], form["password"]):
                session["user_id"] = user["id"] #user["id"] will grab the SQL id in session 
                session["user_name"] = user["first_name"] #user[first_name] will grab the SQL "first_name" in session
                return redirect('/wall')
        
        flash("Incorrect login information")    
        return redirect('/')

@app.route('/message/create', methods=['POST'])
def create_message():
    form = request.form
    valid = True

    #message validation
    if len(form['message']) < 1:
        valid = False
        flash('You have not posted anything!')    
        return redirect('/wall')

    else:
        message_query = "INSERT INTO `messages` (`message`, `user_id`, `created_at`, `updated_at`) VALUES (:message, :user_id, NOW(), NOW())"
        data = {
            'message': form['message'],
            'user_id': session['user_id']
        }
        mysql.query_db(message_query, data)
        return redirect('/wall')

@app.route('/comments/create/<message_id>', methods=['POST'])
def create_comment(message_id):
    form = request.form
    valid = True

    if len(form['comment']) < 1:
        flash('You have not posted anything!')
        return redirect('/')

    comment_query = "INSERT INTO `comments` (`comment`, `user_id`, `message_id`, `created_at`, `updated_at`) VALUES (:comment, :user_id, :message_id, NOW(), NOW())"
    data = {
        'comment': request.form['comment'],
        'user_id': session['user_id'],
        'message_id': message_id
    }
    mysql.query_db(comment_query, data)
    return redirect('/wall')    



@app.route('/wall')
def wall():
    if not 'user_id' in session:
        return redirect('/')

    message_query = "SELECT users.first_name AS first, users.last_name AS last, messages.message AS message, messages.created_at AS created_at, messages.id AS id FROM messages JOIN users ON users.id = messages.user_id"
    messages = mysql.query_db(message_query)

    comment_query = "SELECT comments.comment AS comment, comments.message_id AS message_id, users.first_name AS first, users.last_name AS last, comments.created_at AS created_at FROM comments JOIN users ON users.id = comments.user_id"
    comments = mysql.query_db(comment_query)

    data = {
        'title': 'The Wall',
        'messages': messages,
        'comments': comments
    }

    return render_template('wall.html',data=data)        

@app.route('/logout')
def logout():
  session.clear() 
  return redirect('/')


app.run(debug=True)