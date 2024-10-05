import os
from flask import Flask, render_template, flash, redirect, url_for, request, session, current_app
from flask_bootstrap import Bootstrap
from forms import LoginForm, CreateAccountForm, ListForm, UpdatePasswordForm, UpdateUsernameForm, ForgotLoginForm
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect, generate_csrf
from datetime import datetime, timedelta, UTC
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

app = Flask(__name__)

# Add MySQL database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['SQLALCHEMY_DATABASE_URI']
# Secret key
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
# Additional security
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ['MAIL_USERNAME']
app.config['MAIL_PASSWORD'] = os.environ['MAIL_PASSWORD']
# Recaptcha configuration
app.config['RECAPTCHA_USE_SSL'] = False
app.config['RECAPTCHA_PUBLIC_KEY'] = os.environ.get('RECAPTCHA_PUBLIC_KEY')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.environ.get('RECAPTCHA_PRIVATE_KEY')
app.config['RECAPTCHA_OPTIONS'] = {'theme': 'black'}
# Token salt
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT')

mail = Mail(app)

# Initialize CSRF protection
csrf = CSRFProtect(app)
# Bootstrap
Bootstrap(app)
# Create the extension
db = SQLAlchemy(app)
# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'account_login'
login_manager.login_message = 'You need to log in to access user settings'


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=7)


# Generate reset token
def generate_reset_token(user_email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(user_email, salt=app.config['SECURITY_PASSWORD_SALT'])


# Send email with password reset
def send_password_reset(user_email):
    reset_token = generate_reset_token(user_email)
    reset_url = url_for('reset_password', token=reset_token, _external=True)
    msg = Message('Password Reset Request - Make your own to-do list',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user_email])
    msg.body = f'Click this link to reset your password: {reset_url}\n\nIf you did not want to reset your password, ' \
               f'simply ignore this email - no changes will be made.'
    mail.send(msg)


# Send email with username
def send_username(user_email, username):
    login_url = url_for('account_login', _external=True)
    msg = Message('Your username - Make your own to-do list',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user_email])
    msg.html = f'''
        <p>Your username is: <b>{username}</b></p>
        <p>Click this link to go to the login page and use it to log in: 
        <a href="{login_url}">Login page</a></p>
        <p>If you did not make the request, simply ignore this email - no changes will be made.</p>
    '''
    mail.send(msg)


# Setup user_loader callback
@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(Users, user_id)
    if user is None:
        session.clear()
    return user


# Create model
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(16), nullable=False)
    user_email = db.Column(db.String(120), nullable=False, unique=True)
    user_password = db.Column(db.String(255), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.now(UTC))
    token_last_sent = db.Column(db.DateTime, nullable=True)

    # Allow objects to be identified by username
    def __repr__(self):
        return f'<Username {self.username}'


# Create table schema in the database
with app.app_context():
    db.create_all()


# Home page
@app.route('/')
def home():
    return render_template('index.html')


# Manage account
@app.route('/user', methods=['GET', 'POST'])
def user_account():
    if not current_user.is_authenticated:
        flash('Log in or create an account to access your lists', 'info')
        return redirect(url_for('account_login'))
    else:
        # dodaj też listę z listami to do usera
        # dodaj przycisk, gdzie je można ściągnąć lub wysłać na maila/google calendar
        form = ListForm()
        return render_template('user.html',
                               form=form)


# Login to user account
@app.route('/user/login', methods=['GET', 'POST'])
def account_login():
    if current_user.is_authenticated:
        return redirect(url_for('user_account'))
    else:
        form = LoginForm()
        if request.method == 'POST':
            if form.validate_on_submit():
                form_email = form.email.data
                form_password = form.password.data
                result = db.session.execute(db.select(Users).where(Users.user_email == form_email))
                user = result.scalar()
                if user:
                    if not check_password_hash(user.user_password, form_password):
                        flash('Password incorrect, please try again', 'info')
                        form.password.data = ''
                        return redirect(url_for('account_login'))
                    else:
                        flash('Log in successful', 'success')
                        login_user(user)
                        next_page = request.args.get('next')
                        return redirect(next_page or url_for('user_account'))
                else:
                    flash('There is no such user in the database. Create an account to access your lists', 'info')
                    form.password.data = ''
                    return redirect(url_for('add_user'))
        return render_template('account_login.html',
                               form=form)


# Create an account
@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    if current_user.is_authenticated:
        return redirect(url_for('user_account'))
    else:
        form = CreateAccountForm()
        if request.method == 'POST':
            if form.validate_on_submit():
                form_username = form.username.data
                form_email = form.email.data
                form_password = form.password.data
                result = db.session.execute(db.select(Users).where(Users.user_email == form_email))
                user = result.scalar()
                if user:
                    flash('This email already belongs to an existing account. Use it to log in', 'info')
                    form.password.data = ''
                    return redirect(url_for('account_login'))
                else:
                    flash('Account created successfully', 'success')
                    hash_and_salted_password = generate_password_hash(form_password,
                                                                      method='pbkdf2:sha256',
                                                                      salt_length=8)
                    user = Users(username=form_username,
                                 user_email=form_email,
                                 user_password=hash_and_salted_password,
                                 date_added=datetime.now(UTC))
                    db.session.add(user)
                    db.session.commit()
                    login_user(user)
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('home'))
        return render_template('add_user.html',
                               form=form)


@app.route('/forgot_username', methods=['GET', 'POST'])
def forgot_username():
    form = ForgotLoginForm()
    if request.method == 'POST':
        user_email = form.provide_email.data
        user = db.session.execute(db.select(Users).where(Users.user_email == user_email)).scalar()
        if user:
            send_username(user.user_email, user.username)
            flash('An email with your username has been sent to the provided email', 'warning')
            return redirect(url_for('forgot_username',
                                    form=form))
        else:
            flash('No account is associated with this email', 'info')
            return redirect(url_for('forgot_username',
                                    form=form))
    return render_template('forgot_username.html',
                           form=form)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotLoginForm()
    if request.method == 'POST':
        user_email = form.provide_email.data
        user = db.session.execute(db.select(Users).where(Users.user_email == user_email)).scalar()
        if user:
            # if user.token_last_sent == None
            time_difference = datetime.now(UTC).replace(tzinfo=None) - datetime.fromisoformat('2024-10-05 14:46:23.283+02:00')
            # time_difference = datetime.now(UTC).replace(tzinfo=None) - user.token_last_sent
            print(time_difference)
            if time_difference > 3600:
                flash('A password reset link has already been sent to the email you provided - check your inbox', 'info')
                return redirect(url_for('forgot_password'))
            else:
        # if datetime.now(UTC) -  > 3600:
                send_password_reset(user.user_email)
                # user.reset_token_sent_date = datetime.now(UTC)
                db.session.commit()
                flash('An email has been sent with instructions to reset your password', 'warning')
                return redirect(url_for('forgot_password'))
        else:
            flash('No account is associated with this email', 'info')
            return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    else:
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            user_email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
        except SignatureExpired:
            flash('The reset token has expired. Please repeat the password reset procedure', 'warning')
            return redirect(url_for('forgot_password'))
        except BadSignature:
            flash('Invalid token. Please repeat the password reset procedure', 'warning')
            return redirect(url_for('forgot_password'))

        # NIE ZROBILES WERYFIKACJI TOKENA TUTAJ - VERIFY TOKEN
        # DODAJ KOLEJNĄ KOLUMNĘ W DB, KTÓRA MA VAlue reset token used = False domyślnie a
        # dodaj kolumne token_last_timestamp - będzie się uaktualniać, żeby sprawdzić czy dalej aktualny?
        # jeśli dalej to flash message: flash('A reset link has been sent to your email address')
        form = UpdatePasswordForm()
        user_to_update = db.session.execute(db.select(Users).where(Users.user_email == user_email)).scalar()
        if user_to_update:
            if request.method == 'POST':
                if request.form['new_password'] == request.form['new_password_confirm']:
                    # if request.form['new_password'] == user_to_update.user_password:
                    if check_password_hash(user_to_update.user_password, request.form['new_password']):
                        flash('You are already using this password. You can use it to log in', 'info')
                        return render_template('reset_password.html',
                                               form=form)
                    else:
                        hash_and_salted_password = generate_password_hash(request.form['new_password'],
                                                                          method='pbkdf2:sha256',
                                                                          salt_length=8)
                        user_to_update.user_password = hash_and_salted_password
                        try:
                            db.session.commit()
                            flash('Password updated successfully', 'success')
                            return redirect(url_for('account_login'))
                        except Exception:
                            flash('There was a problem, user profile hasn\'t been updated', 'warning')
                            return redirect(url_for('update_profile'))
                else:
                    flash('The passwords provided do not match', 'warning')
                    return render_template('reset_password.html',
                                           form=form, token=token)
            return render_template('reset_password.html',
                                   form=form,
                                   token=token)
        else:
            flash('A username with the email provided does not exist. Create a new account', 'warning')
            return redirect(url_for('add_user'))


# Log out of the account
@app.route('/logout')
def logout():
    logout_user()
    flash('You logged out of your account', 'success')
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
    form = UpdateUsernameForm()
    if request.method == 'POST':
        if request.form['new_username'] == user_to_update.username:
            flash('You are already using this username', 'info')
            return render_template('update_username.html',
                                   form=form)
        else:
            user_to_update.username = request.form['new_username']
            try:
                db.session.commit()
                flash('Username updated successfully', 'success')
                return redirect(url_for('user_account'))
            except Exception:
                flash('There was a problem, user profile hasn\'t been updated', 'warning')
                return render_template('update_user.html')
    return render_template('update_username.html',
                           form=form)


# Update user password
@app.route('/update_password', methods=['GET', 'POST'])
@login_required
def update_password():
    user_to_update = db.session.get(Users, current_user.id)
    form = UpdatePasswordForm()
    if request.method == 'POST':
        if request.form['new_password'] == request.form['new_password_confirm']:
            if check_password_hash(user_to_update.user_password, request.form['new_password']):
                flash('You are already using this password', 'info')
                return render_template('update_password.html',
                                       form=form)
            else:
                hash_and_salted_password = generate_password_hash(request.form['new_password'],
                                                                  method='pbkdf2:sha256',
                                                                  salt_length=8)
                user_to_update.user_password = hash_and_salted_password
                try:
                    db.session.commit()
                    flash('Password updated successfully', 'success')
                    return redirect(url_for('user_account'))
                except Exception:
                    flash('There was a problem, user profile hasn\'t been updated', 'warning')
                    return render_template('update_user.html')
        else:
            flash('The passwords provided do not match', 'warning')
            return render_template('update_password.html',
                                   form=form)
    return render_template('update_password.html',
                           form=form)


# Delete the account
@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    csrf_token = generate_csrf()
    if request.method == 'POST':
        if 'yes_delete' in request.form:
            try:
                db.session.delete(current_user)
                db.session.commit()
            except Exception:
                flash('There was a problem, your account hasn\'t been deleted', 'warning')
                return redirect(url_for('delete_account'))
            else:
                flash('Your account has been deleted', 'success')
                logout_user()
                return redirect(url_for('home'))
        elif 'cancel_delete' in request.form:
            return redirect(url_for('home'))
    return render_template('delete_account.html', csrf_token=csrf_token)


# Missing or invalid CSRF token
@app.errorhandler(400)
def csrf_error(e):
    return render_template('400.html'), 400


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
#  7. albo wysłać na maila albo dadać do Google Calendar - zanim zaczniesz je robić,
#  sprawdź jaki format mają te rzeczy z Google Calendar + API
#  11. dodaj drugą table do mysql, która będzie zawierać listy to-do
#  12. zrób ciemną wersję strony z odwróconymi kolorami
#  13. Obtain an SSL Certificate, use https, http, lax?
