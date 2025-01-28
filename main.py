import os
from flask import Flask, Response, render_template, flash, redirect, url_for, request, session, current_app
from flask_bootstrap import Bootstrap
from forms import LoginForm, CreateAccountForm, UpdatePasswordForm, UpdateUsernameForm, ForgotLoginForm, \
    SuggestFeatureForm, ToDoForm, DeleteAccountForm, CheckboxForm, EditTask, EditList, DownloadListForm, DiscardChanges
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import DatabaseError
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect, generate_csrf
from datetime import datetime, timedelta, UTC, date
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from zenquotes_api import get_quote
from pdf_maker import create_task_image, calculate_body_length
import json


# Initialize the Flask application
app = Flask(__name__)

# Add MySQL database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('JAWSDB_URL')
# app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')

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
def make_session_permanent() -> None:
    """Set session to permanent with a lifetime of 7 days."""
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=7)


def generate_reset_token(user_email: str) -> tuple[str, datetime]:
    """Generate a token for password reset using a user's email address.

    Args:
        user_email (str): Email address of the user requesting a password reset.

    Returns:
        tuple[str, datetime]: The token and its issuance timestamp.
    """
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    token = serializer.dumps(user_email, salt=app.config['SECURITY_PASSWORD_SALT'])
    token_issued_at = (serializer.loads(token,
                                        salt=current_app.config['SECURITY_PASSWORD_SALT'],
                                        return_timestamp=True)[1]).replace(tzinfo=None)
    return token, token_issued_at


def send_password_reset(user_email: str) -> datetime:
    """Send an email with a password reset link to the user.

    Args:
        user_email (str): The recipient's email address.

    Returns:
        datetime: Timestamp when the token was generated.
    """
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


def send_username(user_email: str, username: str) -> None:
    """Send an email to a user with their username information.

    Args:
        user_email (str): The recipient's email address.
        username (str): The user's username.
    """
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


def send_suggestions_confirmation(email: str, message: str) -> None:
    """Send a confirmation email to the user and forward their suggestions to the developer.

    Args:
        email (str): The email address of the user submitting the suggestions.
        message (str): The message or suggestions provided by the user.
    """
    # Send confirmation email with suggested features
    msg_commenter = Message('Your suggestions have been submitted - we hear you!',
                            sender=app.config['MAIL_USERNAME'],
                            recipients=[email])
    msg_commenter.html = f'''
        <p>Hello,</p>
        <p>your suggestions have been submitted to the creators. You can expect an answer in a few days.</p>
        <p>Here is the message you've submitted:</p>
        <p><i>"{message}"</i></p>
        <p>Do have a nice day,</p>
        <p>Jakub</p>
        <br>
        <p>This is an automated message - please do not answer this email.</p>
        <br>
        <p>If you did not make the request, simply ignore this email.</p>
    '''
    mail.send(msg_commenter)
    # Send user's suggestions to the developer
    msg_creator = Message(f'Suggestions from user: {email}',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[app.config['MAIL_USERNAME']])
    msg_creator.html = message
    mail.send(msg_creator)


def download_file(
        chosen_format: str,
        chosen_style: str,
        list_font: str,
        tasks_list: list[tuple[str, str, bool]],
        chosen_title: str
) -> Response:
    """Generate and return a downloadable file (an image or a PDF) based on the given parameters.

    Args:
        chosen_format (str): The format of the file to be downloaded ('image' or 'pdf').
        chosen_style (str): The style to apply to the file ('plain', 'retro' or 'notebook').
        list_font (str): The font to use for the text in the file ('Times New Roman',
                         'Courier New' or 'Segoe Script').
        tasks_list (list[tuple[str, str, bool]]): A list of tasks to include in the file.
        chosen_title (str): The title of the to-do list to display in the generated file.

    Returns:
        Response: A Flask Response object containing the file stream, with appropriate
                  headers for downloading.
    """

    mimetype = 'image'
    if chosen_format == 'pdf':
        mimetype = 'application'

    if current_user.is_authenticated:
        list_name = f'{current_user.username}\'s to-do list.{chosen_format}'
    else:
        if session['list_name']:
            list_name = f'{session["list_name"]}.{chosen_format}'
        else:
            list_name = f'My to-do list.{chosen_format}'
    list_image_stream = create_task_image(chosen_format=chosen_format,
                                          chosen_style=chosen_style,
                                          list_font=list_font,
                                          tasks_list=tasks_list,
                                          chosen_title=chosen_title
                                          )
    return Response(
        list_image_stream,
        mimetype=f'{mimetype}/{chosen_format}',
        headers={'Content-Disposition': f'attachment;filename={list_name}'}
    )


def clear_list(*args: bool) -> Response:
    """Clears the current to-do list and resets relevant session variables.

    If any boolean arguments are passed, the list edit mode is canceled by
    setting `edited_list_index` to 'not_in_db'. A default list name with the
    current date is set and the tasks list is emptied. The function
    redirects to the user account page if multiple arguments are provided;
    otherwise, it redirects to the home page.

    Args:
        *args (bool): Optional boolean arguments. Used to determine if edit mode
                      is canceled and the redirection target.

    Returns:
        Response: A redirect to the home page or user account page.
    """
    if args:
        session['edited_list_index'] = 'not_in_db'
    date_today = date.today().strftime("%d.%m.%Y")
    session['list_name'] = f'My to-do list {date_today}'
    session['title'] = 'with_date'
    session['tasks_list'] = []
    session.modified = True
    if len(args) > 1:
        return redirect(url_for('user_account'))
    return redirect(url_for('home'))


class Users(UserMixin, db.Model):
    """A database model representing a user in the application.

    Attributes:
        id (int): The primary key for the user.
        username (str): The username of the user (maximum 16 characters).
        user_email (str): The email address of the user, unique across all users.
        user_password (str): The hashed password of the user.
        date_added (datetime): The date and time when the user was added to the database.
        user_lists (list[Any]): A JSON field storing the user's lists.
        token_last_sent (datetime | None): The timestamp of the last token sent
                                           to the user, if any.
        valid_token (str | None): A string representing the user's valid token, if any.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(16), nullable=False)
    user_email = db.Column(db.String(120), nullable=False, unique=True)
    user_password = db.Column(db.String(255), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.now(UTC))
    user_lists = db.Column(db.JSON, default='[]')
    token_last_sent = db.Column(db.DateTime, nullable=True)
    valid_token = db.Column(db.String(255))


# Create table schema in the database
with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id: int) -> Users | None:
    """Load a user from the database for Flask-Login based on the given user ID.

    Args:
        user_id (int): The ID of the user to be loaded.

    Returns:
        Users | None: The user object if found, otherwise None. If the user
                      is not found, the session is cleared.
    """
    user = db.session.get(Users, user_id)
    if user is None:
        session.clear()
    return user


@app.route('/', methods=['GET', 'POST'])
def home() -> Response | str:
    """Render the home page, handle form submissions, and manage to-do lists.

    This route handles various user actions, including creating, editing, saving,
    and downloading to-do lists. It also manages session variables for the user's
    current tasks and to-do list preferences.

    Returns:
        Response | str: A rendered template for the home page or a response redirect
                        depending on the user action.
    """
    csrf_token = generate_csrf()
    add_form = ToDoForm()
    edit_form = EditTask()
    edit_list = EditList()
    checkbox_form = CheckboxForm()
    download_form = DownloadListForm()
    discard_changes_form = DiscardChanges()

    # Ensure session variables exist for task management
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
    if 'edited_list_index' not in session:
        session['edited_list_index'] = 'not_in_db'

    session['list_will_fit'] = calculate_body_length(
        chosen_style=session['style'],
        list_font=session['font'],
        tasks_list=session['tasks_list'],
        chosen_title=session['list_name'])

    if request.method == 'POST':
        action = request.form.get('action')
        form_id = request.form.get('form_id')
        # Save both new and already created to-do lists
        if action == 'save':
            return redirect(url_for('save_list'))
        # Restart to-do list creation process
        elif action == 'new':
            clear_list()
        # Move a task up in the list
        elif action == 'move_up':
            task_id = request.form.get('task_id')
            return redirect(url_for('move_up', task_id=task_id))
        # Move a task down in the list
        elif action == 'move_down':
            task_id = request.form.get('task_id')
            return redirect(url_for('move_down', task_id=task_id))
        # Rewrite or change the colour of a task
        elif action == 'edit':
            task_id = request.form.get('task_id')
            return redirect(url_for('edit_task', task_id=task_id))
        # Delete a task
        elif action == 'delete':
            task_id = request.form.get('task_id')
            return redirect(url_for('delete_task', task_id=task_id))
        # Save the chosen style options of the to-do list
        if edit_list.validate_on_submit() and form_id == 'edit_list':
            style = request.form.get('styleOption')
            font = request.form.get('fontOption')
            title = request.form.get('titleOption')
            return redirect(url_for('save_style_options', style=style, font=font, title=title))
        # Save changes to an edited task
        if edit_form.validate_on_submit() and form_id == 'edit_form':
            new_task_color = request.form.get('taskColor')
            new_task_data = edit_form.edited_task.data
            return redirect(url_for('save_changed_task', new_task_color=new_task_color, new_task_data=new_task_data))
        # Add a new task to the to-do list
        if add_form.validate_on_submit() and form_id == 'add_form':
            task_color = request.form.get('taskColor')
            if not task_color:
                task_color = 'dark'
            task_data = add_form.new_task.data
            return redirect(url_for('add_task', task_color=task_color, task_data=task_data))
        # Download the to-do list in a chosen format
        if download_form.validate_on_submit() and form_id == 'download_form':
            chosen_format = request.form.get('downloadOption')

            return download_file(chosen_format=chosen_format,
                                 chosen_style=session['style'],
                                 list_font=session['font'],
                                 tasks_list=session['tasks_list'],
                                 chosen_title=session['list_name'])
        # Check the task checkbox and strike its text through
        if checkbox_form.validate_on_submit() and form_id == 'checkbox_form':
            checkbox_index = request.form.get('checkbox_hidden')
            return redirect(url_for('checkbox_handler', checkbox_index=checkbox_index))
        # Stop editing a saved list and return it to its saved state
        if discard_changes_form.validate_on_submit() and form_id == 'discard_changes_form':
            clear_list(True, True)

    edited_task_data = session.pop('edited_task_data', False)
    return render_template('index.html',
                           csrf_token=csrf_token,
                           edited_task_data=edited_task_data,
                           add_form=add_form,
                           edit_form=edit_form,
                           edit_list=edit_list,
                           checkbox_form=checkbox_form,
                           download_form=download_form,
                           discard_changes_form=discard_changes_form,
                           tasks_list=session['tasks_list'],
                           list_name=session['list_name'],
                           title=session['title'],
                           style=session['style'],
                           font=session['font'],
                           list_modified=session['edited_list_index'],
                           list_will_fit=session['list_will_fit']
                           )


@app.route('/add_task/<task_color>/<task_data>')
def add_task(task_color: str, task_data: str) -> Response:
    """Add a new task to the to-do list by appending session's tasks_list.

    Args:
        task_color (str): The color chosen for the task text.
        task_data (str): The text of the task.

    Returns:
        Response: A redirect to the home page.
    """
    session['tasks_list'].append([task_data, task_color, False])
    session.modified = True
    return redirect(url_for('home'))


@app.route('/checkbox_handler/<checkbox_index>')
def checkbox_handler(checkbox_index: str) -> Response:
    """Check or uncheck the selected task checkbox and strike its text through.

    Args:
        checkbox_index (str): A string representing the index of the selected task.

    Returns:
        Response: A redirect to the home page.
    """
    # If the selected task's checkbox is checked, uncheck it and vice versa.
    if session['tasks_list'][int(checkbox_index)][2]:
        session['tasks_list'][int(checkbox_index)][2] = False
    else:
        session['tasks_list'][int(checkbox_index)][2] = True
    session.modified = True

    view_element = f'#{checkbox_index}'
    return redirect(url_for('home') + view_element)


@app.route('/edit_task/<task_id>')
def edit_task(task_id: str) -> Response:
    """Rewrite or change the colour of the selected task.

    Args:
        task_id (str): The ID of the task to edit.

    Returns:
        Response: A redirect to the home page.
    """
    task_id = int(task_id)
    task_to_edit = session['tasks_list'][task_id]
    session['edited_task_data'] = task_to_edit
    session['edited_task_id'] = task_id
    return redirect(url_for('home'))


@app.route('/delete_task/<task_id>')
def delete_task(task_id: str) -> Response:
    """Delete the selected task from the session's tasks_list.

    Args:
        task_id (str): The ID of the task to delete.

    Returns:
        Response: A redirect to the home page.
    """
    task_id = int(task_id)
    session['tasks_list'].pop(task_id)
    session.modified = True
    return redirect(url_for('home'))


@app.route('/make_a_new_list')
def make_a_new_list() -> Response:
    """Redirect to the home page and clear the current list if in edit mode.

    If a user list is being edited, cancels the edit mode and clears the current
    list, then redirects to the home page. Otherwise, redirects to the home page.

    Returns:
        Response: A redirect to the home page.
    """
    if session['edited_list_index'] == 'not_in_db':
        return redirect(url_for('home'))
    else:
        return clear_list(True)


@app.route('/move_up/<task_id>')
def move_up(task_id: str) -> Response:
    """Move a task up in the to-do list.

    Moves a task up in the current to-do list, adjusting its position
    in the session's tasks list. If the task is at the top of the list,
    it will be moved to the bottom.

    Args:
        task_id (str): The ID of the task to move.

    Returns:
        Response: A redirect to the home page.
    """
    task_id = int(task_id)
    task_to_move = session['tasks_list'][task_id]
    session['tasks_list'].pop(task_id)
    # Calculate the position in the list where the tasks should move.
    if task_id > 0:
        session['tasks_list'].insert(task_id - 1, task_to_move)
    else:
        session['tasks_list'].insert(len(session['tasks_list']), task_to_move)
    session.modified = True
    return redirect(url_for('home'))


@app.route('/move_down/<task_id>')
def move_down(task_id: str) -> Response:
    """Move a task down in the to-do list.

    Moves a task down in the current to-do list, adjusting its position
    in the session's tasks list. If the task is at the bottom of the list,
    it will be moved to the top.

    Args:
        task_id (str): The ID of the task to move.

    Returns:
        Response: A redirect to the home page.
    """
    task_id = int(task_id)
    task_to_move = session['tasks_list'][task_id]
    session['tasks_list'].pop(task_id)
    # Calculate the position in the list where the tasks should move.
    if task_id < len(session['tasks_list']):
        session['tasks_list'].insert(task_id + 1, task_to_move)
    else:
        session['tasks_list'].insert(0, task_to_move)
    session.modified = True
    return redirect(url_for('home'))


@app.route('/save_list')
def save_list() -> Response:
    """Save the current to-do list to the user's account if authenticated and valid.

    If the user is logged in and the to-do list contains tasks, the list is saved
    to the database. If the list exceeds the allowed limit of 10 saved lists,
    the user is informed via a flash message. Non-authenticated users
    are redirected to the register page.

    Returns:
        Response: A redirect to the user account page, login page, or home page,
                  depending on the operation outcome.
    """
    # Check if there are any tasks in the to-do list
    if len(session['tasks_list']) > 0:
        if current_user.is_authenticated:
            user_to_update = db.session.get(Users, current_user.id)
            list_data = json.loads(user_to_update.user_lists)

            last_edited = datetime.now().strftime('%d/%m/%y %H:%M:%S')
            current_to_do_dict = {'list_name': session['list_name'],
                                  'style': session['style'],
                                  'font': session['font'],
                                  'tasks_list': session['tasks_list'],
                                  'last_edited': last_edited
                                  }
            if session['edited_list_index'] == 'not_in_db':
                if len(list_data) > 9:
                    flash('The maximum number of to-do lists has been reached! Delete unused to-do lists '
                          'to save a new one', 'info')
                    return redirect(url_for('home'))
            else:
                list_data.pop(session['edited_list_index'])

            # Reset session variables after saving
            clear_list(True)

            # Save updated list data to the database
            list_data.insert(0, current_to_do_dict)
            json_list_data = json.dumps(list_data)
            user_to_update.user_lists = json_list_data
            db.session.commit()
            flash('The list has been successfully saved!', 'info')
            return redirect(url_for('user_account'))
        else:
            return redirect(url_for('add_user'))
    else:
        flash('This to-do list is empty! Add tasks in order to save it', 'info')
        return redirect(url_for('home'))


@app.route('/save_changed_task/<new_task_color>/<task_data>')
def save_changed_task(new_task_color: str, new_task_data: str) -> Response:
    """Save the edits made to an already created task in session's tasks_list.

    Args:
        new_task_color (str): The changed color of the task text.
        new_task_data (str): The modified task text.

    Returns:
        Response: A redirect to the home page.
    """
    is_crossed_through = session['tasks_list'][session['edited_task_id']][2]
    changed_task = [new_task_data, new_task_color, is_crossed_through]
    session['tasks_list'].pop(session['edited_task_id'])
    session['tasks_list'].insert(session['edited_task_id'], changed_task)
    session.pop('edited_task_id')
    session.modified = True
    return redirect(url_for('home'))


@app.route('/save_style_options/<style>/<font>/<title>')
def save_style_options(style: str, font: str, title: str) -> Response:
    """Save the selected style options and modify the title accordingly.

    style (str): The selected background.
    font (str): The selected font.
    title (str): The selected title.

    Returns:
        Response: A redirect to the home page.
    """
    session['style'] = style
    session['font'] = font
    session['title'] = title
    if session['title'] == 'with_date':
        date_today = date.today().strftime("%d.%m.%Y")
        session['list_name'] = f'My to-do list {date_today}'
    elif session['title'] == 'no_date':
        session['list_name'] = 'My to-do list'
    elif session['title'] == 'no_title':
        session['list_name'] = ''
    session.modified = True
    return redirect(url_for('home'))


@app.route('/user', methods=['GET', 'POST'])
def user_account() -> Response | str:
    """Handle edits, deletions and downloads of saved user to-do lists.

    Returns:
        Response | str: A redirect to another route if the user is not authenticated,
                        edits a list, deletes a list, or downloads a file. Renders a template
                        with user-specific to-do list data.
    """
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

        # Get the selected list's index from the modals in the template
        if request.method == 'POST':
            download_list_index = request.form.get('download_list_index')
            deleted_list_index = request.form.get('delete_list_index')
            edited_list_index = request.form.get('edit_list_index')
            # Start editing the selected to-do list
            if edited_list_index is not None:
                edited_list = list_data[int(edited_list_index)]
                session['list_name'] = edited_list['list_name']
                session['style'] = edited_list['style']
                session['font'] = edited_list['font']
                session['tasks_list'] = edited_list['tasks_list']
                session['edited_list_index'] = int(edited_list_index)
                session.modified = True
                return redirect(url_for('home'))
            # Delete the selected to-do list from the database
            elif deleted_list_index is not None:
                list_data.pop(int(deleted_list_index))
                json_list_data = json.dumps(list_data)
                user.user_lists = json_list_data
                db.session.commit()
                return redirect(url_for('user_account'))
            # Download the selected to-do list in the chosen format
            elif download_form.validate_on_submit():
                chosen_format = request.form.get('downloadOption')
                downloaded_list = list_data[int(download_list_index)]
                return download_file(chosen_format=chosen_format,
                                     chosen_style=downloaded_list['style'],
                                     list_font=downloaded_list['font'],
                                     tasks_list=downloaded_list['tasks_list'],
                                     chosen_title=downloaded_list['list_name'])
        return render_template('user.html',
                               csrf_token=csrf_token,
                               download_form=download_form,
                               show_edit_modal=show_edit_modal,
                               list_modified=session['edited_list_index'],
                               list_data=list_data)


@app.route('/user/login', methods=['GET', 'POST'])
def account_login() -> Response | str:
    """Authenticate and log in a user.

    Returns:
        Response | str: A rendered template for the login page or a response redirect
                        to the user account if the login process is successful.
    """
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


@app.route('/user/add', methods=['GET', 'POST'])
def add_user() -> Response | str:
    """Register a new user and create a new record in the database.

    Returns:
        Response | str: A rendered template for creating a new account, a response redirect
                        to the home page if an account is created or a response redirect
                        to the login page if the email provided already exists in the database.
    """
    if current_user.is_authenticated:
        return redirect(url_for('user_account'))
    else:
        form = CreateAccountForm()
        if request.method == 'POST':
            if form.validate_on_submit():
                print('WESZŁO DO FORMY')
                form_username = form.username.data
                form_email = form.email.data
                form_password = form.password.data
                result = db.session.execute(db.select(Users).where(Users.user_email == form_email))
                user = result.scalar()
                # Check if a user with the email provided already exists in the database
                if user:
                    flash('This email already belongs to an existing account. Use it to log in', 'info')
                    form.password.data = ''
                    return redirect(url_for('account_login'))
                else:
                    flash('Account created successfully', 'success')
                    # Hash and salt the password provided and add the user to the database
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
            else:
                return 'coś się spitoliło i nie weszło do formy'
        return render_template('add_user.html',
                               form=form)


@app.route('/forgot_username', methods=['GET', 'POST'])
def forgot_username() -> Response | str:
    """Handle the 'Forgot Username' process by verifying the user's email and sending their username.

    Returns:
        Response | str : The rendered template with a form for providing an email
                         and a response redirect to the same template after sending the username
                         to the user email or if the email provided is invalid.
    """
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
def forgot_password() -> Response | str:
    """Reset user's password through an email with password reset link.

    Returns:
        Response | str: Renders the template with a form for providing an email.
                        A redirect back to the 'forgot_password' route after sending
                        a password reset link or handling an invalid email. Checks if
                        the token sent is still active.
    """
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
                # Check if the last sent token is still active
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


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token) -> Response | str:
    """Authenticate the reset token and allow the user to reset their password.

    Args:
        token (str): The reset token included in the URL.

    Returns:
        Response | str: Redirect to the login page if the password is successfully
                        reset, renders the password reset form if the token is valid,
                        or shows an error message if invalid.
    """
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


@app.route('/logout')
def logout() -> Response:
    """Log out of user's account.

    Returns:
        Response: A response redirect to the home page after logging out.
    """
    logout_user()
    flash('You logged out of your account', 'success')
    return clear_list(True)


@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile() -> str:
    """Manage user account details.

    Returns:
        str: Renders the template for displaying user account update options.
    """
    return render_template('update_user.html')


@app.route('/update_username', methods=['GET', 'POST'])
@login_required
def update_username() -> Response | str:
    """Update the username.

    Returns:
        Response | str: Redirects to the user account page if the update is successful,
                        renders the template with the form if the request is a GET, the username
                        is the same or an error occurs.
    """
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


@app.route('/update_password', methods=['GET', 'POST'])
@login_required
def update_password() -> Response | str:
    """Save updated user password.

    Returns:
        Response | str: A redirect response to the user account page if the password
                        is successfully updated, or a rendered template displaying the password
                        update form if the request is a GET or if there are validation issues
                        during the update process.
    """
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
            return render_template('update_password.html', form=form)
    return render_template('update_password.html', form=form)


@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account() -> Response | str:
    """Delete user account from the database and log out.

    Returns:
        Response | str: A redirect response to the home page if the account
                        is successfully deleted, or a rendered template displaying
                        the account deletion confirmation form.
    """
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


@app.route('/motivation')
def motivational_quotes() -> str:
    """Display motivational quotes on a page using API.

    Returns:
        str: A rendered template displaying motivational quotes from an API
             or a predefined info message if the service is unavailable.
    """
    quote_data = get_quote()
    quote = quote_data[0]
    author = quote_data[1]
    if author == 'zenquotes.io':
        author = False
        quote = 'An inspirational quote is currently unavailable due to heavy demand :) Check it out in a moment!'
    return render_template('motivational_quotes.html', quote=quote, author=author)


@app.route('/about')
def about() -> str:
    """Display 'About' page.

    Returns:
        str: A rendered template of the 'About' page.
    """
    return render_template('about.html')


@app.route('/suggest_features', methods=['GET', 'POST'])
def suggest_features() -> Response | str:
    """Display a form where a user can suggest a feature.

    Returns:
        Response | str: A redirect response if the form is successfully submitted,
                        or a rendered template displaying the suggestion form.
    """
    form = SuggestFeatureForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            commenter_email = request.form['provide_email']
            comment = request.form['textarea']
            formatted_comment = comment.replace('\n', '<br>')
            send_suggestions_confirmation(commenter_email, formatted_comment)
            flash('Your suggestions have been submitted. A confirmation email has been sent to your email', 'info')
            return redirect(url_for('suggest_features'))
    return render_template('suggest_features.html', form=form)


@app.errorhandler(400)
def csrf_error(e: Exception) -> tuple[str, int]:
    """Handle a Bad Request (400) error.

    Args:
        e (Exception): The exception object raised during the error.

    Returns:
        tuple[str, int]: A tuple containing the rendered 400 error template
                         and the status code.
    """
    return render_template('400.html'), 400


@app.errorhandler(404)
def page_not_found(e: Exception) -> tuple[str, int]:
    """Handle a Page Not Found (404) error.

    Args:
        e (Exception): The exception object raised during the error.

    Returns:
        tuple[str, int]: A tuple containing the rendered 404 error template
                         and the status code.
    """
    return render_template('404.html'), 404


@app.errorhandler(500)
def page_not_found(e: Exception) -> tuple[str, int]:
    """Handle an Internal Server Error (500).

    Args:
        e (Exception): The exception object raised during the error.

    Returns:
        tuple[str, int]: A tuple containing the rendered 500 error template
                         and the status code.
    """
    return render_template('500.html'), 500


# if __name__ == '__main__':
#     app.run(debug=True)
