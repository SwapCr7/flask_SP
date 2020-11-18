'''
Citation
https://github.com/PrettyPrinted/building_user_login_system/tree/master/finish
https://flask-login.readthedocs.io/en/latest/
https://flask.palletsprojects.com/en/1.1.x/patterns/fileuploads/
https://www.youtube.com/watch?v=8aTnmsDMldY
'''
import os
import sqlite3 as sql
from flask import Flask,render_template, url_for, flash, redirect, request, send_file, session,g
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_bootstrap import Bootstrap
from wtforms import StringField, IntegerField, SubmitField, SelectField,PasswordField,BooleanField
from wtforms.validators import DataRequired,InputRequired,Email,Length
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.fields.html5 import EmailField
from werkzeug.utils import secure_filename
import datetime

app = Flask(__name__)
bootstrap = Bootstrap(app)

# Configurations
app.config['SECRET_KEY'] = 'blah blah blah blah'

UPLOAD_DIRECTORY = r"C:\Users\Swapnil\Desktop\Files_download"
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

class Login(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField("Login")

class Register(FlaskForm):
    email = EmailField('email',validators=[Email(),InputRequired()])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    check_password = PasswordField('Confirm Password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField("Register")

# ROUTES!
@app.route('/',methods=['GET','POST'])
def index():
    form = Register()
    return render_template('index.html', form = form)

@app.route('/login',methods=['GET','POST'])
def login():
    form1 = Login()
    if form1.validate_on_submit():
        connection = sql.connect("./user.db")
        cursor = connection.cursor()
        query = "SELECT * FROM user_info WHERE username = '"+ form1.username.data+"'"
        cursor.execute(query)
        result = cursor.fetchall()
        if not result :
            return "No username registered"
        username = result[0][1]
        db_password = result[0][2]
        status = result[0][-1]
        password = form1.password.data
        if not username :
            return "Username not registered"
        if not check_password_hash(db_password,password) :
            return "Password is incorrect"
        if status == 'inactive' :
            return "Your account has not been activated"
        else :
            session['username'] = request.form['username']
            print(session['username'])
            return redirect(url_for('homepage'))
    return render_template('login.html', form1=form1)

@app.route('/register',methods=['GET','POST'])
def register():
    form2 = Register()
    if form2.password.data != form2.check_password.data :
        return "Password Doesn't match"
    if form2.validate_on_submit():
        connection = sql.connect("./user.db")
        cursor = connection.cursor()
        query = "SELECT username FROM user_info WHERE username = '"+ form2.username.data+"'"
        cursor.execute(query)
        username = cursor.fetchall()
        if username :
            return "Username Already taken"
        query = "SELECT email FROM user_info WHERE email = '"+form2.email.data+"'"
        cursor.execute(query)
        email = cursor.fetchall()
        if email :
            return "Email Already Registered"
        else:
            user_type = 'user'
            status = 'inactive'
            query = "INSERT INTO user_info (username,password,email,type,status) VALUES ('"+ form2.username.data +"', '"+ generate_password_hash(form2.password.data) +"', '"+ form2.email.data +"','"+user_type+"','"+status+"')"
            cursor.execute(query)
            connection.commit()
            connection.close()
            form = Login()
            flash("Successful Registeration")
            return redirect(url_for('login'))
    return render_template('register.html',form2 = form2)

@app.before_request
def before_request():
    g.user = None
    if 'username' in session :
        g.user = session['username']

@app.route('/homepage')
def homepage() :
    if g.user :
        username = g.user
        connection = sql.connect('./user.db')
        cursor = connection.cursor()
        query = "SELECT * FROM user_info where username = '"+username+"'"
        cursor.execute(query)
        result = cursor.fetchall()
        role = result[0][-2]
        return render_template('homepage.html', username=username, role=role)
    return redirect(url_for('index'))

@app.route('/upload_file',methods=['POST'])
def upload_file():
    file = request.files['addfile']
    f_name = secure_filename(file.filename)
    file.save(os.path.join('./static/' ,f_name))
    username = session['username']
    temp = str(datetime.datetime.now()).split(" ")
    date = temp[0]
    time = temp[1]
    connection = sql.connect("./user.db")
    cursor = connection.cursor()
    query = "INSERT INTO file_info (username,date,time,filename) VALUES ('"+username+"','"+date+"','"+time+"','"+f_name+"')"
    cursor.execute(query)
    connection.commit()
    connection.close()
    return redirect(url_for('homepage'))

@app.route('/view')
def view():
    username = session['username']
    connection = sql.connect('./user.db')
    cursor = connection.cursor()
    query = "SELECT * FROM file_info"
    cursor.execute(query)
    result = cursor.fetchall()
    if not result :
        return "NO FILES TO SHOW"
    else :
        return render_template('view.html', result=result)

@app.route('/view_specific')
def view_specific():
    username = session['username']
    connection = sql.connect('./user.db')
    cursor = connection.cursor()
    query = "SELECT * FROM file_info where username = '"+username+"'"
    cursor.execute(query)
    result = cursor.fetchall()
    if not result :
        return "NO FILES"
    else :
        return render_template('view_specific.html', result=result)

@app.route('/activation')
def activation():
    connection = sql.connect('./user.db')
    cursor = connection.cursor()
    query = "SELECT * FROM user_info where type ='user' and status ='inactive'"
    cursor.execute(query)
    result = cursor.fetchall()
    role = result[0][-2]
    status = result[0][-1]
    return render_template('activation.html', result= result)

@app.route('/active',methods=['GET','POST'])
def active():
    username = request.form['user']
    connection = sql.connect('./user.db')
    cursor = connection.cursor()
    query = "UPDATE user_info SET status = 'active' WHERE username ='"+username+"' "
    cursor.execute(query)
    connection.commit()
    connection.close()
    return redirect(url_for('homepage'))

@app.route('/logout')
def logout():
    if "username" in session:
        username = session["username"]
        flash("You have been logged out {}".format(username))
    session.pop("username",None)
    form = Register()
    return render_template('index.html', form=form)

app.run(debug=True)
