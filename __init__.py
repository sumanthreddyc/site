from flask import render_template, flash, redirect, url_for
from datetime import datetime

from flask_wtf import Form as FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Length, ValidationError

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask.ext.login import UserMixin
from flask_login import LoginManager, login_user, logout_user, current_user, login_required

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

followers = db.Table(
    'followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

class User(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), unique=True, nullable=False)
	password = db.Column(db.String(60), nullable=False)
followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')
	
def __repr__(self): 
	    return self.username

def is_authenticated(self):
	    return True

def is_active(self):
	    return True

def get_id(self):
	    return self.id    

def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

def is_following(self, user):
        return self.followed.filter(followers.c.followed_id == user.id).count() > 0


class RegistrationForm(FlaskForm):      
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class FollowForm(FlaskForm):
    submit = SubmitField('Follow')

class UnfollowForm(FlaskForm):
    submit = SubmitField('Unfollow')

@app.route("/")
def home():
    return render_template('home.html', current_user = current_user)


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        print(form)
        user = User(username = form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        print('Your account has been created! You are now able to login', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if(user is None):
            print('User not found')
            return render_template('login.html', title='Login', form=form)

        if(bcrypt.check_password_hash(user.password, form.password.data)):
            login_user(user, remember = True)
            print('You have been logged in!', 'success')
            return redirect(url_for('home'))
        else:
            print('Login Unsuccessful. Please check username and password', 'danger')

    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

users = User.query.all()

@app.route("/people", methods=['GET', 'POST'])
@login_required
def people():
    return render_template('people.html', current_user=current_user, users = users)

@app.route("/people/<user_id>", methods=['GET', 'POST'])
def user(user_id):
    form = FollowForm()
    user = User.query.get(user_id)  
    if form.validate_on_submit():
        follower = followers(follower_id = current_user.id, followed_id = user_id)
        db.session.add(follower)
        db.session.commit()
        return render_template('people.html', form=form)
    return render_template('follow.html', form = form, user = user) 

@app.route("/followers", methods=['GET', 'POST'])
@login_required
def followers():
    users = followers.query.filter_by(followed_id = current_user.id)
    return render_template('followers.html', current_user=current_user, users = users)
 
@app.route("/following", methods=['GET', 'POST'])
@login_required
def following():
    form = UnfollowForm()
    users = followers.query.filter_by(follower_id = current_user.id)
    return render_template('following.html', current_user=current_user, users = users, form = form)

if __name__ == '__main__':
    app.run(debug=True)
