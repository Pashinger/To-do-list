import os
from flask import Flask, render_template, flash, redirect, url_for, request, session
from flask_bootstrap import Bootstrap
from forms import AccountForm, ListForm, UpdatePasswordForm, UpdateUsernameForm
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

# Add MySQL database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['SQLALCHEMY_DATABASE_URI']
# Secret key
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
# Additional security
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=7)


# Bootstrap
Bootstrap(app)
# Create the extension
db = SQLAlchemy(app)
# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'add_user'
login_manager.login_message = 'You need to log in to access user settings'


# Setup user_loader callback
@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(Users, user_id)
    if user is None:
        # Clear the session if user ID doesn't exist
        session.clear()
    return user


# Creating model
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(16), nullable=False)
    user_email = db.Column(db.String(120), nullable=False, unique=True)
    user_password = db.Column(db.String(255), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    # Allow objects to be identified by username
    def __repr__(self):
        return f'<Username {self.username}'


# Create table schema in the database
with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template('index.html')


# Manage account
@app.route('/user', methods=['GET', 'POST'])
def user_account():
    if not current_user.is_authenticated:
        flash('Log in or create an account to access your lists')
        return redirect(url_for('add_user'))
    else:
        # dodaj też listę z listami to do usera
        # dodaj przycisk, gdzie je można ściągnąć lub wysłać na maila/google calendar
        username = current_user.username
        list_form = ListForm()
        return render_template('user.html',
                               username=username,
                               list_form=list_form)


# Log in or create an account
@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    if current_user.is_authenticated:
        return redirect(url_for('user'))
    else:
        account_form = AccountForm()
        if request.method == 'POST':
            if account_form.validate_on_submit():
                form_username = account_form.username.data
                form_email = account_form.email.data
                form_password = account_form.password.data
                result = db.session.execute(db.select(Users).where(Users.user_email == form_email))
                user = result.scalar()
                # if the user wants to log in
                if 'login_submit' in request.form:
                    if user:
                        if user.username != form_username:
                            flash('Username provided doesn\'t belong to this account, please try again.')
                            account_form.password.data = ''
                            return redirect(url_for('add_user'))
                        elif not check_password_hash(user.user_password, form_password):
                            flash('Password incorrect, please try again.')
                            account_form.password.data = ''
                            return redirect(url_for('add_user'))
                        else:
                            flash('Log in successful')
                            login_user(user)
                            next_page = request.args.get('next')
                            return redirect(next_page or url_for('user_account'))
                    else:
                        flash('There is no such user in the database. Create an account to access your lists')
                        account_form.password.data = ''
                        return redirect(url_for('add_user'))
                # if the user wants to sign up
                elif 'sign_up_submit' in request.form:
                    if user:
                        flash('This email already belongs to an existing account. Use it to log in')
                        account_form.password.data = ''
                        return render_template('add_user.html',
                                               account_form=account_form)
                    else:
                        flash('Account created successfully')
                        hash_and_salted_password = generate_password_hash(form_password,
                                                                          method='pbkdf2:sha256',
                                                                          salt_length=8)

                        user = Users(username=form_username,
                                     user_email=form_email,
                                     user_password=hash_and_salted_password,
                                     date_added=datetime.utcnow())
                        db.session.add(user)
                        db.session.commit()
                        login_user(user)
                        next_page = request.args.get('next')
                        return redirect(next_page or url_for('home'))
        return render_template('add_user.html',
                               account_form=account_form)


#Log out of the account
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


# Update user profile
@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    return render_template('update_user.html')


# Update username
@app.route('/update_username', methods=['GET', 'POST'])
@login_required
def update_username():
    user_to_update = db.session.get(Users, current_user.id)
    update_username_form = UpdateUsernameForm()
    if request.method == 'POST':
        if request.form['new_username'] == user_to_update.username:
            flash('You are already using this username')
            return render_template('update_username.html',
                                   update_username_form=update_username_form)
        else:
            user_to_update.username = request.form['new_username']
            try:
                db.session.commit()
                flash('Username updated successfully')
                return redirect(url_for('user_account'))
            except Exception as ex:
                print(ex)
                flash('There was a problem, user profile hasn\'t been updated')
                return render_template('update_user.html')
    return render_template('update_username.html',
                           update_username_form=update_username_form)


# Update user password
@app.route('/update_password', methods=['GET', 'POST'])
@login_required
def update_password():
    user_to_update = db.session.get(Users, current_user.id)
    update_password_form = UpdatePasswordForm()
    if request.method == 'POST':
        if request.form['new_password'] == request.form['new_password_confirm']:
            if request.form['new_password'] == user_to_update.user_password:
                flash('You are already using this password')
                return render_template('update_password.html',
                                       update_password_form=update_password_form)
            else:
                hash_and_salted_password = generate_password_hash(request.form['new_password'],
                                                                  method='pbkdf2:sha256',
                                                                  salt_length=8)
                user_to_update.user_password = hash_and_salted_password
                try:
                    db.session.commit()
                    flash('Password updated successfully')
                    return redirect(url_for('user_account'))
                except Exception:
                    flash('There was a problem, user profile hasn\'t been updated')
                    return render_template('update_user.html')
        else:
            flash('The passwords provided do not match')
            return render_template('update_password.html',
                                   update_password_form=update_password_form)
    return render_template('update_password.html',
                           update_password_form=update_password_form)


# Delete the account
@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    if request.method == 'POST':
        if 'yes_delete' in request.form:
            try:
                db.session.delete(current_user)
                db.session.commit()
                flash('Your account has been deleted')
                return redirect(url_for('home'))
            except Exception:
                flash('There was a problem, your account hasn\'t been deleted')
                return redirect(url_for('delete_account'))
        elif 'cancel_delete' in request.form:
            return redirect(url_for('home'))
    return render_template('delete_account.html')


# Invalid URL
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# Internal Server Error
@app.errorhandler(500)
def page_not_found(e):
    return render_template('500.html'), 500


if __name__ == '__main__':
    app.run(debug=True)

# todo:
#  1. sformatuj css, font itd
#  6. dodaj przycisk przy wyświetlających się listach, że można sciągnąć ją jako pdf
#  7. albo wysłać na maila albo dadać do Google Calendar
#  9. flash messages powinny znikać
#  11. dodaj drugą table do mysql, która będzie zawierać listy to-do
#  12. zrób ciemną wersję strony z odwróconymi kolorami
#  13. Obtain an SSL Certificate
#  14. http, lax? w app.config
#  16. dodaj forgot my password - wysyła na maila
#  17. dodaj ikonki do flash messages?
#  18. csfr dodaj do form?