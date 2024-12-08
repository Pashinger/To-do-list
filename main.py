import os
from flask import Flask, Response, render_template, flash, redirect, url_for, request, session, current_app, send_file
from flask_bootstrap import Bootstrap
from forms import LoginForm, CreateAccountForm, UpdatePasswordForm, UpdateUsernameForm, ForgotLoginForm, \
    SuggestFeatureForm, ToDoForm, DeleteAccountForm, CheckboxForm, EditTask, EditList, DownloadListForm
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import DatabaseError
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect, generate_csrf
from datetime import datetime, timedelta, UTC, date
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from zenquotes_api import get_quote
from pdf_maker import create_task_image
import json

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
    token = serializer.dumps(user_email, salt=app.config['SECURITY_PASSWORD_SALT'])
    token_issued_at = (serializer.loads(token,
                                        salt=current_app.config['SECURITY_PASSWORD_SALT'],
                                        return_timestamp=True)[1]).replace(tzinfo=None)
    return token, token_issued_at


# Send email with password reset
def send_password_reset(user_email):
    reset_token_items = generate_reset_token(user_email)
    reset_token = reset_token_items[0]
    reset_url = url_for('reset_password', token=reset_token, _external=True)
    msg = Message('Password Reset Request - Make your own to-do list',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user_email])
    msg.body = f'Click this link to reset your password: {reset_url}\n\nIf you did not want to reset your password, ' \
               f'simply ignore this email - no changes will be made.'
    mail.send(msg)
    return reset_token_items[1]


# Send email with username
def send_username(user_email, username):
    login_url = url_for('account_login', _external=True)
    msg = Message('Your username - Make your own to-do list',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user_email])
    msg.html = f'''
        <p>Your username is: <strong>{username}</strong></p>
        <p>Click <a href="{login_url}">this link</a> to go to the login page.
        <br>
        <p>If you did not make the request, simply ignore this email - no changes will be made.</p>
    '''
    mail.send(msg)


# Send confirmation email with suggested features
def send_suggestions_confirmation(email, message):
    # send email to commenter
    msg_commenter = Message('Your suggestions have been submitted - we hear you!',
                            sender=app.config['MAIL_USERNAME'],
                            recipients=[email])
    msg_commenter.html = f'''
        <p>Hello,</p>
        <p>your suggestions have been submitted to the creators. You can expect an answer in a few days.</p>
        <p>Here is the message you've submitted:</p>
        <p><i>"{message}"<i/></p>
        <p>Do have a nice day,</p>
        <p>Jakub</p>
        <br>
        <p>This is an automated message - please do not answer this email.</p>
        <br>
        <p>If you did not make the request, simply ignore this email.</p>
    '''
    mail.send(msg_commenter)
    # send suggestions to the developer
    msg_creator = Message(f'Suggestions from user: {email}',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[app.config['MAIL_USERNAME']])
    msg_creator.html = message
    mail.send(msg_creator)


def download_file(chosen_format, chosen_style, list_font, tasks_list, list_name):
    # chosen_format = request.form.get('downloadOption')
    mimetype = 'image'
    if chosen_format == 'pdf':
        mimetype = 'application'
    list_name_full = f'{list_name}.{chosen_format}'
    list_image_stream = create_task_image(chosen_format=chosen_format,
                                          chosen_style=session['style'],
                                          list_font=session['font'],
                                          tasks_list=session['tasks_list'])

    return Response(
        list_image_stream,
        mimetype=f'{mimetype}/{chosen_format}',
        headers={'Content-Disposition': f'attachment;filename={list_name_full}'}
    )


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
    user_lists = db.Column(db.JSON, default=[])
    token_last_sent = db.Column(db.DateTime, nullable=True)
    valid_token = db.Column(db.String(255))

    # Allow objects to be identified by username
    def __repr__(self):
        return f'<Username {self.username}'


# Create table schema in the database
with app.app_context():
    db.create_all()


# Home page
@app.route('/', methods=['GET', 'POST'])
def home():
    csrf_token = generate_csrf()
    add_form = ToDoForm()
    edit_form = EditTask()
    edit_list = EditList()
    checkbox_form = CheckboxForm()
    download_form = DownloadListForm()

    if 'tasks_list' not in session:
        session['tasks_list'] = []
    if 'list_name' not in session:
        date_today = date.today().strftime("%d.%m.%Y")
        session['list_name'] = f'My to-do list {date_today}'
        session['title'] = 'with_date'
    if 'style' not in session:
        session['style'] = 'plain'
    if 'font' not in session:
        session['font'] = 'times'

    if request.method == 'POST':
        action = request.form.get('action')
        form_id = request.form.get('form_id')
        if action == 'save':
            if len(session['tasks_list']) > 0:
                if current_user.is_authenticated:
                    user_to_update = db.session.get(Users, current_user.id)
                    list_data = json.loads(user_to_update.user_lists)
                    if len(list_data) > 9:
                        flash('The maximum number of to-do lists has been reached! Delete unused to-do lists to save'
                              ' a new one', 'info')
                        return redirect(url_for('home'))
                    else:
                        last_edited = datetime.now().strftime('%d/%m/%y %H:%M:%S')
                        current_to_do_dict = {'list_name': session['list_name'],
                                              'style': session['style'],
                                              'font': session['font'],
                                              'tasks_list': session['tasks_list'],
                                              'last_edited': last_edited
                                              }
                        list_data.insert(0, current_to_do_dict)
                        json_list_data = json.dumps(list_data)
                        user_to_update.user_lists = json_list_data
                        db.session.commit()
                        flash('The list has been successfully saved!', 'info')
                        return redirect(url_for('user_account'))
                else:
                    return redirect(url_for('account_login'))
            else:
                flash('This to-do list is empty! Add tasks in order to save it', 'info')
                return redirect(url_for('home'))
        elif action == 'new':
            date_today = date.today().strftime("%d.%m.%Y")
            session['list_name'] = f'My to-do list {date_today}'
            session['title'] = 'with_date'
            session['tasks_list'] = []
            session.modified = True
            return redirect(url_for('home'))
        elif action == 'move_up':
            task_id = int(request.form.get('task_id'))
            task_to_move = session['tasks_list'][task_id]
            session['tasks_list'].pop(task_id)
            if task_id > 0:
                session['tasks_list'].insert(task_id - 1, task_to_move)
            else:
                session['tasks_list'].insert(len(session['tasks_list']), task_to_move)
            session.modified = True
            return redirect(url_for('home'))
        elif action == 'move_down':
            task_id = int(request.form.get('task_id'))
            task_to_move = session['tasks_list'][task_id]
            session['tasks_list'].pop(task_id)
            if task_id < len(session['tasks_list']):
                session['tasks_list'].insert(task_id + 1, task_to_move)
            else:
                session['tasks_list'].insert(0, task_to_move)
            session.modified = True
            return redirect(url_for('home'))
        elif action == 'edit':
            task_id = int(request.form.get('task_id'))
            task_to_edit = session['tasks_list'][task_id]
            session['edited_task_data'] = task_to_edit
            session['edited_task_id'] = task_id
            return redirect(url_for('home'))
        elif action == 'delete':
            task_id = int(request.form.get('task_id'))
            session['tasks_list'].pop(task_id)
            session.modified = True
            return redirect(url_for('home'))

        if edit_list.validate_on_submit() and form_id == 'edit_list':
            session['style'] = request.form.get('styleOption')
            session['font'] = request.form.get('fontOption')
            session['title'] = request.form.get('titleOption')
            if session['title'] == 'with_date':
                date_today = date.today().strftime("%d.%m.%Y")
                session['list_name'] = f'My to-do list {date_today}'
            elif session['title'] == 'no_date':
                session['list_name'] = 'My to-do list'
            elif session['title'] == 'no_title':
                session['list_name'] = ''
            session.modified = True
            return redirect(url_for('home'))

        if edit_form.validate_on_submit() and form_id == 'edit_form':
            new_task_color = request.form.get('taskColor')
            is_crossed_through = session['tasks_list'][session['edited_task_id']][2]
            changed_task = [edit_form.edited_task.data, new_task_color, is_crossed_through]
            session['tasks_list'].pop(session['edited_task_id'])
            session['tasks_list'].insert(session['edited_task_id'], changed_task)
            session.pop('edited_task_id')
            session.modified = True
            return redirect(url_for('home'))

        if add_form.validate_on_submit() and form_id == 'add_form':
            task_color = request.form.get('taskColor')
            if not task_color:
                task_color = 'dark'
            session['tasks_list'].append([add_form.new_task.data, task_color, False])
            session.modified = True
            return redirect(url_for('home'))

        if download_form.validate_on_submit() and form_id == 'download_form':
            chosen_format = request.form.get('downloadOption')
            chosen_style = session['style']
            list_font = session['font']
            tasks_list = session['tasks_list']
            if current_user.is_authenticated:
                list_name = f'{current_user.username}\'s to-do list'
            else:
                list_name = f'{session["list_name"]}'

            return download_file(chosen_format=chosen_format,
                                 chosen_style=chosen_style,
                                 list_font=list_font,
                                 tasks_list=tasks_list,
                                 list_name=list_name)

        if checkbox_form.validate_on_submit() and form_id == 'checkbox_form':
            checkbox_index = request.form.get('checkbox_hidden')

            if session['tasks_list'][int(checkbox_index)][2]:
                session['tasks_list'][int(checkbox_index)][2] = False
            else:
                session['tasks_list'][int(checkbox_index)][2] = True
            session.modified = True

            # TUTAJ DODAJ, JAK checkbox_index < tylu ile sie mieści na stronie bez scrollowania (zmierz mniej więcej len
            # kilku pierwszych tasków?), to żeby redirectowało
            # do głównej a nie do elementu

            view_element = f'#{checkbox_index}'
            return redirect(url_for('home') + view_element)

    edited_task_data = session.pop('edited_task_data', False)
    return render_template('index.html',
                           csrf_token=csrf_token,
                           edited_task_data=edited_task_data,
                           add_form=add_form,
                           edit_form=edit_form,
                           edit_list=edit_list,
                           checkbox_form=checkbox_form,
                           download_form=download_form,
                           tasks_list=session['tasks_list'],
                           list_name=session['list_name'],
                           title=session['title'],
                           style=session['style'],
                           font=session['font']
                           )


# Manage saved user lists
@app.route('/user', methods=['GET', 'POST'])
def user_account():
    csrf_token = generate_csrf()
    download_form = DownloadListForm()
    show_edit_modal = False
    if len(session['tasks_list']) > 0:
        show_edit_modal = True

    if not current_user.is_authenticated:
        flash('Log in or create an account to access your lists', 'info')
        return redirect(url_for('account_login'))
    else:
        user = db.session.get(Users, current_user.id)
        list_data = json.loads(user.user_lists)
        # jak user kliknie w edit to wszystkie dane listy z bazy danych powinny się sciągnąć i wejść do session
        # a później redirectować do strony głównej? Plus czy powinien się pojawić przycisk, żeby anulować zmiany i wrócić
        # do robionej listy, która znowu będzie zapisana w session pod innymi nazwami?

        # NIE DZIAŁA TYTUŁ W ŚCIĄGANEJ LIŚCIE - ROBI SIĘ PO PROSTU MY-TO-DO LIST

        if request.method == 'POST':
            download_list_index = request.form.get('download_list_index')
            deleted_list_index = request.form.get('delete_list_index')
            edited_list_index = request.form.get('edit_list_index')
            if edited_list_index is not None:
                edited_list = list_data[int(edited_list_index)]
                # w save zmień w templacie na save changes to the user list
                session['list_name'] = edited_list['list_name']
                session['style'] = edited_list['style']
                session['font'] = edited_list['font']
                session['tasks_list'] = edited_list['tasks_list']
                return redirect(url_for('home'), )
            elif deleted_list_index is not None:
                list_data.pop(int(deleted_list_index))
                json_list_data = json.dumps(list_data)
                user.user_lists = json_list_data
                db.session.commit()
                return redirect(url_for('user_account'))
            elif download_form.validate_on_submit():
                chosen_format = request.form.get('downloadOption')
                downloaded_list = list_data[int(download_list_index)]
                chosen_style = downloaded_list['style']
                list_font = downloaded_list['font']
                tasks_list = downloaded_list['tasks_list']
                list_name = f'{current_user.username}\'s to-do list'
                return download_file(chosen_format=chosen_format,
                                     chosen_style=chosen_style,
                                     list_font=list_font,
                                     tasks_list=tasks_list,
                                     list_name=list_name)

        return render_template('user.html',
                               csrf_token=csrf_token,
                               download_form=download_form,
                               show_edit_modal=show_edit_modal,
                               list_data=list_data)


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
                    return redirect(url_for('account_login'))
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


# Send an email with the username
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


# Send an email with password reset link
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotLoginForm()
    if request.method == 'POST':
        user_email = form.provide_email.data
        user = db.session.execute(db.select(Users).where(Users.user_email == user_email)).scalar()
        if user:
            if not user.token_last_sent:
                user.token_last_sent = send_password_reset(user.user_email)
                db.session.commit()
                flash('An email has been sent with instructions to reset your password', 'warning')
                return redirect(url_for('forgot_password'))
            else:
                if timedelta(minutes=30) < (datetime.now(UTC).replace(tzinfo=None) - user.token_last_sent):
                    user.token_last_sent = send_password_reset(user.user_email)
                    db.session.commit()
                    flash('An email has been sent with instructions to reset your password', 'warning')
                    return redirect(url_for('forgot_password'))
                else:
                    flash('A password reset link has already been sent to the email you provided - check your inbox',
                          'info')
                    return redirect(url_for('forgot_password'))
        else:
            flash('No account is associated with this email', 'info')
            return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html', form=form)


# Reset password from link
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    else:
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            user_email = serializer.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=1800)
        except SignatureExpired:
            flash('The reset token has expired. Please repeat the password reset procedure', 'warning')
            return redirect(url_for('forgot_password'))
        except BadSignature:
            flash('Invalid token. Please repeat the password reset procedure', 'warning')
            return redirect(url_for('forgot_password'))

        token_issued_at = (serializer.loads(token,
                                            salt=current_app.config['SECURITY_PASSWORD_SALT'],
                                            return_timestamp=True)[1]).replace(tzinfo=None)

        form = UpdatePasswordForm()
        user_to_update = db.session.execute(db.select(Users).where(Users.user_email == user_email)).scalar()
        if user_to_update:
            if not user_to_update.token_last_sent:
                flash('The reset token has expired. Please repeat the password reset procedure', 'warning')
                return redirect(url_for('forgot_password'))
            elif token_issued_at != user_to_update.token_last_sent:
                flash('The reset token has expired. Please repeat the password reset procedure', 'warning')
                return redirect(url_for('forgot_password'))
            if request.method == 'POST':
                if request.form['new_password'] == request.form['new_password_confirm']:
                    if check_password_hash(user_to_update.user_password, request.form['new_password']):
                        flash('You are already using this password. You can use it to log in', 'info')
                        return render_template('reset_password.html',
                                               form=form)
                    else:
                        hash_and_salted_password = generate_password_hash(request.form['new_password'],
                                                                          method='pbkdf2:sha256',
                                                                          salt_length=8)
                        user_to_update.user_password = hash_and_salted_password
                        user_to_update.token_last_sent = None
                        try:
                            db.session.commit()
                            flash('Password updated successfully', 'success')
                            return redirect(url_for('account_login'))
                        except DatabaseError:
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
            except DatabaseError:
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
                except DatabaseError:
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
    form = DeleteAccountForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                db.session.delete(current_user)
                db.session.commit()
            except DatabaseError:
                flash('There was a problem, your account hasn\'t been deleted', 'warning')
                return redirect(url_for('delete_account'))
            else:
                flash('Your account has been deleted', 'success')
                logout_user()
                return redirect(url_for('home'))
        else:
            flash('Pass recaptcha to delete your account', 'info')
            return redirect(url_for('delete_account'))
    return render_template('delete_account.html', csrf_token=csrf_token, form=form)


# Handle downloading files
@app.route('/download')
def download():
    list_to_download = 'static/images/error.png'
    list_to_download_name = 'beagle pies to fejnowergowaty jest'
    return send_file(list_to_download, download_name=list_to_download_name, as_attachment=True)

    # return send_file(BytesIO(upload.data), download_name=upload.filename, as_attachment=True )


# Motivational quotes page from API
@app.route('/motivation')
def motivational_quotes():
    quote_data = get_quote()
    quote = quote_data[0]
    author = quote_data[1]
    if author == 'zenquotes.io':
        author = False
        quote = 'An inspirational quote is currently unavailable due to heavy demand :) Check it out in a moment!'
    return render_template('motivational_quotes.html', quote=quote, author=author)


# About page
@app.route('/about')
def about():
    return render_template('about.html')


# Suggest a feature
@app.route('/suggest_features', methods=['GET', 'POST'])
def suggest_features():
    form = SuggestFeatureForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            commenter_email = request.form['provide_email']
            comment = request.form['textarea']
            formatted_comment = comment.replace('\n', '<br>')
            send_suggestions_confirmation(commenter_email, formatted_comment)
            flash('Your suggestions have been submitted. A confirmation email has been sent to your email')
            return redirect(url_for('suggest_features'))
    return render_template('suggest_features.html', form=form)


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
#  2. wyświetlają się listy w user, można je ściągnąć na 3 sposoby oraz edytować
#  4. zastanów się czy jednak nie użyć javascriptu, żeby strona się nie odświeżała przy każdym przekreśleniu checkboxem
#  5. sprawdź gdzie masz kolor secondary a gdzie tertiary na pc Agaty i zdecyduj się na 1
#  6. Obtain an SSL Certificate, use https, http, lax?
#  7. dodaj komentarze/opisy do funkcji i klas + deklaracje typów
