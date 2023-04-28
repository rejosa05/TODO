from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth',__name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        #print(user)
        if user:
            if check_password_hash(user.password, password):
                #print(user.password)
                login_user(user, remember=True)
                flash("Login Successfully!!", category= 'success')
                return redirect(url_for('views.index'))
            else:
                flash("Incorrect Credentials!!", category= 'error')
        else:
            flash("Invalid email address!!", category='error')
    return render_template("login.html", user=current_user)

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST': 
        email = request.form.get("email")
        name = request.form.get("name")
        password = request.form.get("password")
        cpassword = request.form.get("password1")

        user = User.query.filter_by(email=email).first()

        if user:
            flash("Email Exist!!", category= 'error')
        elif len(email) < 5:
            flash("Email must be greater than 5 characters", category= 'error')
        elif len(name) < 4:
            flash("Name must be greater than 4 characters", category= 'error')
        elif password != cpassword:
            flash('Password doesn\'t match', category= 'error')
        elif len(password) < 8:
            flash('Password must be greater than 8 characters.', category= 'error')
            pass
        else:
            user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))
            db.session.add(user)
            db.session.commit()
            flash('Register Successfully!')
            login_user(user)
            return redirect(url_for('views.index'))
    return render_template("register.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))