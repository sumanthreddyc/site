from flask import render_template, flash, redirect, url_for, request
from datetime import datetime

from flask_wtf import Form as FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Length, ValidationError

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin

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


# Followers = db.Table(
#     'followers',
#     db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
#     db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
# )


class Followers(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


followed = db.relationship(
    'User', secondary=Followers,
    primaryjoin=(Followers.follower_id == id),
    secondaryjoin=(Followers.followed_id == id),
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


class Post(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    post = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)


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


class PostForm(FlaskForm):
    post = StringField('Post', validators=[DataRequired(), Length(min=2, max=200)])
    submit = SubmitField('Post')


@app.route("/")
def home():
    posts = Post.query.join(
        Followers, (Followers.followed_id == Post.user_id)).filter(
        Followers.follower_id == current_user.id)
    return render_template('home.html', current_user=current_user, posts=posts)


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        print(form)
        user = User(username=form.username.data, password=hashed_password)
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
        if (user is None):
            print('User not found')
            return render_template('login.html', title='Login', form=form)

        if (bcrypt.check_password_hash(user.password, form.password.data)):
            login_user(user, remember=True)
            print('You have been logged in!', 'success')
            return redirect(url_for('home'))
        else:
            print('Login Unsuccessful. Please check username and password', 'danger')

    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/people", methods=['GET', 'POST'])
@login_required
def people():
    users = User.query.all()
    return render_template('people.html', current_user=current_user, users=users)


@app.route("/people/<user_id>", methods=['GET', 'POST'])
@login_required
def user(user_id):
    form = FollowForm()
    user = User.query.get(user_id)
    if request.method == 'POST':
        follower = Followers(follower_id=current_user.id, followed_id=user_id)
        db.session.add(follower)
        db.session.commit()
        return render_template('people.html', form=form, user=user)
    return render_template('follow.html', form=form, user=user)


@app.route("/followers", methods=['GET', 'POST'])
@login_required
def follower():
    users = User.query.join(Followers, User.id == Followers.follower_id).filter(Followers.followed_id == current_user.id).all()
    return render_template('followers.html', users=users)


@app.route("/post", methods=['GET', 'POST'])
@login_required
def post():
    form = PostForm()
    if request.method == 'POST':
        post = Post(post=form.post.data, user_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        return render_template('home.html', form=form, user=user)
    return render_template('post.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
