import os
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy.orm import relationship
from wtforms import StringField, PasswordField, SubmitField, SelectField, DateField, BooleanField
from wtforms.validators import DataRequired
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required, login_user, logout_user, UserMixin
import gunicorn
from decouple import config
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SECRET_KEY'] = config['KEY']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)


# Note table
# class NoteData(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     color = db.Column(db.String(10), nullable=True)
#     title = db.Column(db.String(250), nullable=True)
#     subtitle = db.Column(db.String(500), nullable=True)
#     content = db.Column(db.String(500), nullable=True)
#     date = db.Column(db.DateTime, nullable=False)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    tasks = relationship('TaskData', back_populates='author')


class TaskData(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(1000), nullable=False)
    add_time = db.Column(db.DateTime, nullable=False)
    checked = db.Column(db.Boolean(), nullable=False, default=False)
    checked_time = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship('User', back_populates='tasks')


db.create_all()


# FORMS
class AddTask(FlaskForm):
    new_task = StringField('', validators=[DataRequired()], render_kw={"placeholder": "Place your Task here...", 'autofocus': True})


class AddUser(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')


class LoginUser(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# main route
@app.route('/', methods=['GET', 'POST'])
def index():
    task_form = AddTask()
    user_form = AddUser()
    print(session)

    # this code checks if user is authenticated then their data will be saved in db else it will be saved in session
    if current_user.is_authenticated:
        tasks = TaskData.query.filter_by(user_id=current_user.get_id()).order_by(TaskData.add_time).all()
        checked_tasks = TaskData.query.filter_by(user_id=current_user.get_id()).filter(TaskData.checked).\
            order_by(TaskData.checked_time.desc()).all()
    else:
        tasks = None
        checked_tasks = None

    if not current_user.is_authenticated:
        session.permanent = True
        if 'task' not in session:
            session['task'] = []
            i = 1
        elif len(session['task']) == 0:
            i = 1
        else:
            i = session['task'][0]['id'] + 1

    # adding task for session or DB
    if task_form.validate_on_submit():
        if request.method == 'POST':
            if current_user.is_authenticated:
                print('user is authenticated adding task')
                task = TaskData(task=request.form['new_task'], author=current_user, checked=False, checked_time=None,
                                add_time=datetime.datetime.now())
                db.session.add(task)
                db.session.commit()
                return redirect('/')
            else:
                # storing it on the session
                task_dict = {'task': request.form['new_task'],
                             'checked': False,
                             'id': i,
                             'checked_time': None,
                             'add_time':datetime.datetime.now()
                             }
                session['task'].insert(0, task_dict)
                return redirect('/')

    # Registering a user in DB
    if user_form.validate_on_submit():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            hashed_password = generate_password_hash(password=password, method='pbkdf2:sha256', salt_length=16)
            user = User(email=email.lower(), password=hashed_password)
            db_user = User.query.filter_by(email=email).first()
            if db_user:
                flash('User already exists. Please login')
                return redirect(url_for('login'))
            else:
                db.session.add(user)
                db.session.commit()
                login_user(user)
                for i in range(len(session['task'])):
                    task = TaskData(task=session['task'][i]['task'], checked=session['task'][i]['checked'],
                                    author=current_user, checked_time=None, add_time=datetime.datetime.now())
                    db.session.add(task)
                    db.session.commit()
            return redirect(url_for('index'))

    return render_template('index.html', add_task_form=task_form, task_list=session['task'], add_user_form=user_form,
                           tasks=tasks, checked_tasks=checked_tasks, current_user=current_user)


@app.route('/alltasks/<int:task_id>', methods=['GET', 'POST'])
def all_tasks(task_id):
    task_form = AddTask()

    if current_user.is_authenticated:
        tasks = TaskData.query.filter_by(user_id=current_user.get_id()).order_by(TaskData.add_time).all()
        checked_tasks = TaskData.query.filter_by(user_id=current_user.get_id()).filter_by(checked=TaskData.checked).\
            order_by(TaskData.checked_time.desc()).all()
    else:
        tasks = None
        checked_tasks = None

    # If user checks off the task, this code update the DB/session
    if request.method == "POST":
        if current_user.is_authenticated:
            task = TaskData.query.filter_by(id=task_id).first()
            task.checked = True
            task.checked_time = datetime.datetime.now()
            db.session.commit()
            return redirect('/')
        else:
            ind = [i for i, d in enumerate(session['task']) if d['id'] == task_id]
            task_index = ind[0]
            session['task'][task_index]['checked'] = True
            session['task'][task_index]['checked_time'] = datetime.datetime.now()
            session['task'].insert(0, session['task'].pop(task_index))
            return redirect(url_for('index'))
    return render_template('index.html', task_list=session['task'], add_task_form=task_form,
                           tasks=tasks, checked_tasks=checked_tasks, current_user=current_user)


@app.route('/delete/<int:task_id>', methods=['POST', 'GET'])
def delete(task_id):
    if current_user.is_authenticated:
        task = TaskData.query.filter_by(id=task_id).first()
        print(task)
        db.session.delete(task)
        db.session.commit()
        return redirect(url_for('index'))
    else:
        ind = [i for i, d in enumerate(session['task']) if d['id'] == task_id]
        task_index = ind[0]
        session['task'].pop(task_index)
        return redirect(url_for('index'))


# login user
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginUser()
    if form.validate_on_submit():
        email = form.email.data.lower()
        user = User.query.filter_by(email=email).first()
        if user:
            db_hashed_password = user.password
            password = check_password_hash(pwhash=db_hashed_password, password=form.password.data)
            if password:
                login_user(user=user)
                return redirect(url_for('index'))
            else:
                flash('Please check your password')
        else:
            flash('Email address does not exist')
    return render_template("login.html", form=form)


# logout user
@login_required
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)