from flask import Flask, flash, redirect, render_template, request, session, abort, url_for
import os, subprocess
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import InputRequired
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config.update(dict(
    SECRET_KEY="powerful secretkey",
    WTF_CSRF_SECRET_KEY="a csrf secret key"
))
db = SQLAlchemy(app)
bcrypt = Bcrypt()

class User(db.Model):
	user_id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), unique=True, nullable=False)
	# password = db.Column(db.String(20))
	pswd_hash = db.Column(db.String(128), nullable=False)
	# two_fa = db.Column(db.String(10), nullable=False)
	two_fa_hash = db.Column(db.String(128), nullable=False)

	# def __repr__(self):
	# 	return '<User %r>' % self.username


class RegistrationForm(FlaskForm):
	uname = StringField("username")
	pword = PasswordField("password")
	two_fa = PasswordField("two_factor_authentication", id='2fa')

class LoginForm(FlaskForm):
	uname = StringField("username")
	pword = PasswordField("password")
	two_fa = PasswordField("two_factor_authentication", id='2fa')

class SpellCheckForm(FlaskForm):
	inputtext = TextAreaField("inputtext")

@app.route("/")
def home():
	return redirect(url_for('spell_check'))

@app.route("/spell_check", methods=['POST', 'GET'])
def spell_check():
	if not session.get('logged_in'):
		return redirect(url_for('login'))

	else:

		form = SpellCheckForm()

		if request.method == 'POST':
			inputtext = request.form['inputtext']

			# print(inputtext)

			with open("test.txt",'w', encoding = 'utf-8') as f:
				f.write(inputtext)

			out = subprocess.check_output(["./a.out", "test.txt", "wordlist.txt"])
			
			# processed_output = ",".join(out.decode().split('\n'))
			processed_output = out.decode().replace('\n', ',')

			print(processed_output)

			os.remove("test.txt")

			return "<p id=textout>" + inputtext + "</p> </br> <p id=misspelled>" + processed_output\
					+"</p>"

		return render_template('spell_check.html', form = form)

@app.route('/register', methods=['POST', 'GET'])
def register():
	form = RegistrationForm()

	print (form.errors)

	if request.method == 'POST':
		uname = request.form['uname']
		pword = request.form['pword']
		two_fa = request.form['two_fa']

		if len(uname) < 20 and  len(two_fa) < 10:

			# Encrypt password and 2fa, store in dict
			pw_hash = bcrypt.generate_password_hash(pword, 12)
			two_fa_hash = bcrypt.generate_password_hash(two_fa, 12)

			register = User(username = uname, pswd_hash=pw_hash, two_fa_hash=two_fa_hash)
			db.session.add(register)
			db.session.commit()

			return " <a href=\"/login\" id=success >Registration Success, Please Login </a> <br> \
			 <a href = \"/register\" > Register another user </a>"

		else :
			return "<a href id=success >Registration Failure, Try again </a>"


	return render_template('register.html', form=form)


@app.route('/login', methods=['POST', 'GET'])
def login():

	form = LoginForm()

	if request.method == 'POST':

		uname = request.form['uname']
		pword = request.form['pword']
		two_fa = request.form['two_fa']
	
		# Validate username, password and 2fa
		user = User.query.filter_by(username=uname).first()
		
		pw_hash = user.pswd_hash
		two_fa_hash = user.two_fa_hash
		
		if bcrypt.check_password_hash(pw_hash, pword) and bcrypt.check_password_hash(two_fa_hash, two_fa) :
		
		# if login is not None:

		# if len(uname) < 5:
			session['logged_in'] = True
			return " <a href=\"/spell_check\" id=result >Login Success </a>"

		else:
			return " <a href=\"/login\" id=result >Login Failure </a>"
	
	return render_template('login.html', form=form)


@app.route("/logout")
def logout():
	session['logged_in'] = False
	return home()

if __name__ == "__main__":

	# app.config['SECRET_KEY'] = "someRandomSecretKeyHahahaha"
	db.create_all()
	app.run(debug=True, host='127.0.0.1', port=1337)