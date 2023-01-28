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
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------------------------------------------------------
# ------------------------- VIEW FORM CLASSES -----------------------
# -------------------------------------------------------------------


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=80)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):

    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=80)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


# -------------------------------------------------------------------
# ---------------------------- ROUTES -------------------------------
# -------------------------------------------------------------------

@app.route('/')  # Home Page Route
def home():
    # db.create_all()
    # db.session.commit()
    login_status = current_user.is_authenticated
    return render_template('home.html', login_status=login_status, title="TODO Man")


@app.route('/login', methods=['GET', 'POST'])  # Login Page Route
def login():
    login_status = current_user.is_authenticated
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form, login_status=login_status)


@ app.route('/register', methods=['GET', 'POST'])  # Register Page Route
def register():
    form = RegisterForm()
    login_status = current_user.is_authenticated

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form, login_status=login_status)


@app.route('/dashboard', methods=['GET', 'POST'])  # Dashboard Page Route
@login_required
def dashboard():
    user_id = current_user.id
    login_status = current_user.is_authenticated
    data = ""
    # data = Password.query.filter_by(user_id=user_id).all()
    # for d in data:
    #     d.password = cipher.decrypt(d.password)
    return render_template('dashboard.html', login_status=login_status, results=data)


@app.route('/logout', methods=['GET', 'POST'])  # Logout Route
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    form = AddForm()
    login_status = current_user.is_authenticated
    user_id = current_user.id
    if form.validate_on_submit():
        websiteName = form.website.data
        username = form.username.data
        enc_password = cipher.encrypt(form.password.data)
        record = Password(username=username, website=websiteName,
                          password=enc_password, user_id=user_id)
        db.session.add(record)
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template('add.html', form=form, login_status=login_status)


@app.route('/delete')
@login_required
def delete():
    id = request.args.get('id')
    record = Password.query.get(id)
    if record:
        user_id = current_user.id
        if user_id == record.user_id:
            db.session.delete(record)
            db.session.commit()
    return redirect(url_for('dashboard'))


@ app.route('/update', methods=['GET', 'POST'])
@login_required
def update():
    form = AddForm()
    id = request.args.get('id')
    record = Password.query.get(id)
    login_status = current_user.is_authenticated
    user_id = current_user.id

    if form.validate_on_submit():
        websiteName = form.website.data
        username = form.username.data
        enc_password = cipher.encrypt(form.password.data)
        record.website = websiteName
        record.username = username
        record.password = enc_password
        db.session.commit()
        return redirect(url_for('dashboard'))

    if record:
        user_id = current_user.id
        if user_id == record.user_id:
            record.password = cipher.decrypt(record.password)
            return render_template('update.html',
                                   form=form, login_status=login_status, formData=record)
    return redirect(url_for('dashboard'))
