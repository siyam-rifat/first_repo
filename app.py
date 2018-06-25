from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
#from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import configparser

app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '123456'
app.config['MYSQL_DB'] = 'worldcup18'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# init MySQL
mysql = MySQL(app)

@app.route("/")
def home():
  return render_template("home.html")

class RegisterForm(Form):
  username = StringField('Username', [validators.Length(min=1,max=50)])  
  email = StringField('Email', [validators.Length(min=1,max=50)])  
  password = PasswordField('Password',
      [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match!')
      ])  
  confirm = PasswordField('Confirm Password')

@app.route("/register", methods=['GET','POST'])
def register():
  form = RegisterForm(request.form)
  if request.method == 'POST' and form.validate():
        username = form.username.data
        email = form.email.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # create Cursor
        cur = mysql.connection.cursor()

        # execute query
        cur.execute("INSERT INTO users(username, email, password) VALUES(%s, %s, %s)",
                    (username, email, password))

        # commit to DB
        mysql.connection.commit()

        # close connection
        cur.close()

        flash('Registration complete! You can Log In now.', 'success')

        return redirect(url_for('login'))

  return render_template("register.html", form=form)

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # get form fields
        username = request.form['username']
        password_candidate = request.form['password']

        # create cursor
        cur = mysql.connection.cursor()

        # get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']
            user_id = data['id']

            # compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Successful
                session['logged_in'] = True
                session['username'] = username
                session['user_id'] = user_id

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))

            else:
                error = 'Invalid Login'
                return render_template('login.html', error=error)

            # close connection
            cur.close()

        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')


# Check if user logged_in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, please login', 'danger')
            return redirect(url_for('login'))
    return wrap


# logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))  

#Test prediction
class PredictionForm(Form):
    pteamA = StringField('PTeamA', [validators.Length(min=1, max=2)])
    pteamB = StringField('PTeamB', [validators.Length(min=1, max=2)])    

#Dashboard
@app.route('/dashboard', methods=['GET','POST'])
@is_logged_in
def dashboard():
    # create cursor
    cur = mysql.connection.cursor()

    #Matches
    result = cur.execute("SELECT * from matches")

    matches = cur.fetchall()

    # close connection
    cur.close()   

    form = PredictionForm(request.form) 

    if request.method=='POST' and form.validate():
        pteamA = form.pteamA.data
        pteamB = form.pteamB.data

        # create Cursor
        cur = mysql.connection.cursor()

        # execute
        cur.execute("INSERT INTO predictions(user_id, pteamA_score, pteamB_score) VALUES(%s, %s, %s)",
                    (session['user_id'], pteamA, pteamB))

        # commit
        mysql.connection.commit()

        # close connection
        cur.close()

        flash('Predictions added successfully.', 'success')

        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', matches=matches, form=form)

#Test Point Table
@app.route('/testpointtable')
def testpointtable():

    cur = mysql.connection.cursor()

    result = cur.execute("SELECT * from demouser ORDER BY points DESC")

    table = cur.fetchall()

    cur.close() 

    return render_template('testpointtable.html', table=table)   

# entry point of the app
# the secret key should be in anothe file named "config.ini", which would not be committed, means
# it would not be added to the git, now your secret key is leaked to the git since its added, not a big deal,
# just keep this in mind before final deployment to web

if __name__ == "__main__" :
  config = configparser.ConfigParser()
  config.read('config.ini')
  app.secret_key = config['SETTINGS']['SECRET_KEY']
  app.run(debug=True)