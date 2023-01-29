# imports
from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.widgets.core import PasswordInput
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

# -------------------------------------------------------------------
# ---------------------------- SETUP --------------------------------
# -------------------------------------------------------------------
app = Flask(__name__)  # initial app
db = SQLAlchemy()  # initial sql engin
bcrypt = Bcrypt(app)  # initial flask_bcrypt

# setup database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'SECRET_KEY'  # setup secret key for flask_bcrypt

db.init_app(app)  # bind SQLAlchemy with main app

# Login manager
login_manager = LoginManager()  # initial login manager
login_manager.init_app(app)  # bind login manager with main app
login_manager.login_view = 'login'  # setup login form view


# -------------------------------------------------------------------
# ------------------------- DATABASE_MODELS -------------------------
# -------------------------------------------------------------------

class User(db.Model, UserMixin):  # User Model
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    tasks = db.relationship('Task', backref='user',
                            lazy=True)  # relation one to many


class Task(db.Model):  # Task Model
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey(
        'user.id'), nullable=False)  # ForeignKey for task owner


# -------------------------------------------------------------------
# ------------------------- RUN LOGIN MANAGER -----------------------
# -------------------------------------------------------------------

@login_manager.user_loader
def load_user(user_id):  # provide user credentials
    return User.query.get(int(user_id))

# -------------------------------------------------------------------
# ------------------------- VIEW FORM CLASSES -----------------------
# -------------------------------------------------------------------


class RegisterForm(FlaskForm):  # registration form
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=80)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):  # check if user is already registered
        existing_user_username = User.query.filter_by(
            username=username.data).first()  # get current user from database
        if existing_user_username:  # if user exists in database raise an error
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):  # login form
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=80)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


# -------------------------------------------------------------------
# ----------------------------- FORMS -------------------------------
# -------------------------------------------------------------------

class AddForm(FlaskForm):  # add new task form
    title = StringField(validators=[
        InputRequired(), Length(max=50)], render_kw={"placeholder": "title"})
    description = StringField(validators=[
        InputRequired(), Length(max=255)], render_kw={"placeholder": "description"})
    submit = SubmitField('Add')

# -------------------------------------------------------------------
# ---------------------------- ROUTES -------------------------------
# -------------------------------------------------------------------


@app.route('/')  # Home Page Route
def home():
    # un comment next tow lines to setup database for the first time
    # db.create_all()
    # db.session.commit()
    login_status = current_user.is_authenticated
    return render_template('home.html', login_status=login_status)


@app.route('/login', methods=['GET', 'POST'])  # Login Page Route
def login():
    login_status = current_user.is_authenticated
    form = LoginForm()
    if form.validate_on_submit():  # if user click submit button
        user = User.query.filter_by(
            username=form.username.data).first()  # get user from database
        if user:  # if user exists in database

            # check if user entered a valid password
            if bcrypt.check_password_hash(user.password, form.password.data):
                # utile function from flask_login to login user
                login_user(user)
                return redirect(url_for('dashboard'))
    # if user entered login path
    return render_template('login.html', form=form, login_status=login_status)


@ app.route('/register', methods=['GET', 'POST'])  # Register Page Route
def register():
    form = RegisterForm()
    login_status = current_user.is_authenticated

    if form.validate_on_submit():  # if user click submit button
        hashed_password = bcrypt.generate_password_hash(
            form.password.data)  # hash user password
        new_user = User(username=form.username.data,
                        password=hashed_password)  # generate user object
        db.session.add(new_user)  # add user object to database
        db.session.commit()  # save changes to database
        return redirect(url_for('login'))
    # if user entered register path
    return render_template('register.html', form=form, login_status=login_status)


@app.route('/logout', methods=['GET', 'POST'])  # Logout Route
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['GET', 'POST'])  # Dashboard Page Route
@login_required
def dashboard():
    user_id = current_user.id
    login_status = current_user.is_authenticated
    # get user's tasks from database
    tasks = Task.query.filter_by(user_id=user_id).all()
    return render_template('dashboard.html', login_status=login_status, results=tasks)


@ app.route('/add', methods=['GET', 'POST'])  # Add New Task Route
@login_required
def add():
    form = AddForm()
    login_status = current_user.is_authenticated
    user_id = current_user.id
    if form.validate_on_submit():  # if user click submit button
        title = form.title.data
        description = form.description.data
        record = Task(title=title, description=description,
                      user_id=user_id)  # create task object
        db.session.add(record)  # add task object to database
        db.session.commit()  # save changes to database
        return redirect(url_for('dashboard'))
    # if user entered add  path
    return render_template('add.html', form=form, login_status=login_status)


@app.route('/delete')  # Delete Task Route
@login_required
def delete():
    id = request.args.get('id')
    record = Task.query.get(id)  # get task from database
    if record:
        user_id = current_user.id
        if user_id == record.user_id:  # if task owned by user
            db.session.delete(record)  # delete task from database
            db.session.commit()  # save changes to database
    return redirect(url_for('dashboard'))


@ app.route('/update', methods=['GET', 'POST'])  # Update Task Route
@login_required
def update():
    form = AddForm()
    id = request.args.get('id')
    record = Task.query.get(id)  # get task from database
    login_status = current_user.is_authenticated
    user_id = current_user.id

    if form.validate_on_submit():  # if user click submit button
        title = form.title.data
        description = form.description.data
        record.title = title
        record.description = description
        db.session.commit()  # save changes to database
        return redirect(url_for('dashboard'))
    # if user entered Update  path
    if record:
        if user_id == record.user_id:  # if task owned by user
            return render_template('update.html',
                                   form=form, login_status=login_status, formData=record)
    return redirect(url_for('dashboard'))
