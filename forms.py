from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, EmailField, SubmitField, PasswordField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Email, Length


class LoginForm(FlaskForm):
    """Form for user login.

    Attributes:
        email (EmailField): Field for entering the user's email.
        password (PasswordField): Field for entering the user's password.
        login_submit (SubmitField): Submit button for logging in.
    """
    email = EmailField('Write your e-mail:', validators=[DataRequired(), Email()])
    password = PasswordField('Write your password:', validators=[DataRequired(), Length(min=8, max=60)])
    login_submit = SubmitField('Log In')


class CreateAccountForm(FlaskForm):
    """Form for creating a new user account.

    Attributes:
        username (StringField): Field for entering the username.
        email (EmailField): Field for entering the user's email.
        password (PasswordField): Field for entering the user's password.
        recaptcha (RecaptchaField): CAPTCHA field for security.
        sign_up_submit (SubmitField): Submit button for creating an account.
    """
    username = StringField('Write your username:', validators=[DataRequired(), Length(min=2, max=16)])
    email = EmailField('Write your e-mail:', validators=[DataRequired(), Email()])
    password = PasswordField('Write your password:', validators=[DataRequired(), Length(min=8, max=60)])
    # recaptcha = RecaptchaField()
    sign_up_submit = SubmitField('Create an account')


class DiscardChanges(FlaskForm):
    """Form for discarding unsaved changes.

    Attributes:
        discard_changes_submit (SubmitField): Submit button to discard changes.
    """
    discard_changes_submit = SubmitField('You are editing your previously saved list! Click here if you want to discard'
                                         ' these changes')


class EditTask(FlaskForm):
    """Form for editing an individual task.

    Attributes:
        edited_task (StringField): Field for editing a task.
        edit_submit (SubmitField): Submit button to save changes.
    """
    edited_task = StringField('Edit your task:', validators=[DataRequired(), Length(min=1, max=100)])
    edit_submit = SubmitField('Save')


class EditList(FlaskForm):
    """Form for saving list options.

    Attributes:
        options_submit (SubmitField): Submit button to save options.
    """
    options_submit = SubmitField('Save')


class DownloadListForm(FlaskForm):
    """Form for downloading a list.

    Attributes:
        download_submit (SubmitField): Submit button to download a list.
    """
    download_submit = SubmitField('Download')


class UpdateUsernameForm(FlaskForm):
    """Form for updating the username.

    Attributes:
        new_username (StringField): Field for entering a new username.
        new_username_submit (SubmitField): Submit button to save the new username.
        recaptcha (RecaptchaField): CAPTCHA field for security.
    """
    new_username = StringField('Write your new username:', validators=[DataRequired(), Length(min=2, max=16)])
    new_username_submit = SubmitField('Save changes')
    recaptcha = RecaptchaField()


class UpdatePasswordForm(FlaskForm):
    """Form for updating the user's password.

    Attributes:
        new_password (PasswordField): Field for entering a new password.
        new_password_confirm (PasswordField): Field for confirming the new password.
        new_password_submit (SubmitField): Submit button to save the new password.
    """
    new_password = PasswordField('Write your new password:', validators=[DataRequired(), Length(min=8, max=35)])
    new_password_confirm = PasswordField('Confirm your new password:',
                                         validators=[DataRequired(), Length(min=8, max=35)])
    new_password_submit = SubmitField('Save changes')


class ForgotLoginForm(FlaskForm):
    """Form for requesting username or password recovery.

    Attributes:
        provide_email (EmailField): Field for entering the user's email.
        recaptcha (RecaptchaField): CAPTCHA field for security.
        provide_email_submit (SubmitField): Submit button to submit the email.
    """
    provide_email = EmailField('Write your e-mail:', validators=[DataRequired(), Email()])
    recaptcha = RecaptchaField()
    provide_email_submit = SubmitField('Submit email')


class DeleteAccountForm(FlaskForm):
    """Form for deleting a user account.

    Attributes:
        recaptcha (RecaptchaField): CAPTCHA field for security.
        delete_account_submit (SubmitField): Submit button to delete the account.
    """
    recaptcha = RecaptchaField()
    delete_account_submit = SubmitField('Delete my account')


class SuggestFeatureForm(FlaskForm):
    """Form for suggesting a new feature or idea.

    Attributes:
        provide_email (EmailField): Field for entering the user's email.
        textarea (TextAreaField): Field for entering the feature suggestion.
        recaptcha (RecaptchaField): CAPTCHA field for security.
        suggest_feature_submit (SubmitField): Submit button to submit the suggestion.
    """
    provide_email = EmailField('Write your e-mail:', validators=[DataRequired(), Email()])
    textarea = TextAreaField('Write your ideas here:', validators=[DataRequired(), Length(min=5, max=500)])
    recaptcha = RecaptchaField()
    suggest_feature_submit = SubmitField('Send')


class ToDoForm(FlaskForm):
    """Form for adding a new task to a to-do list.

    Attributes:
        new_task (StringField): Field for entering a new task.
        new_task_submit (SubmitField): Submit button to add the task.
    """
    new_task = StringField('Write a new task:', validators=[DataRequired(), Length(min=1, max=100)])
    new_task_submit = SubmitField('add')


class ToDoTitleForm(FlaskForm):
    """Form for adding a title to a to-do list.

    Attributes:
        title (StringField): Field for entering the title.
    """
    title = StringField(validators=[DataRequired(), Length(min=2, max=80)])


class CheckboxForm(FlaskForm):
    """Form for handling a checkbox field.

    Attributes:
        checkbox (BooleanField): Checkbox input field.
    """
    checkbox = BooleanField()
