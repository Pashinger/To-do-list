from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, EmailField, SubmitField, PasswordField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Email, Length


class LoginForm(FlaskForm):
    email = EmailField('Write your e-mail:', validators=[DataRequired(), Email()])
    password = PasswordField('Write your password:', validators=[DataRequired(), Length(min=8, max=60)])
    login_submit = SubmitField('Log In')


class CreateAccountForm(FlaskForm):
    username = StringField('Write your username:', validators=[DataRequired(), Length(min=2, max=16)])
    email = EmailField('Write your e-mail:', validators=[DataRequired(), Email()])
    password = PasswordField('Write your password:', validators=[DataRequired(), Length(min=8, max=60)])
    recaptcha = RecaptchaField()
    sign_up_submit = SubmitField('Create an account')


class EditTask(FlaskForm):
    edited_task = StringField('Edit your task:', validators=[DataRequired(), Length(min=1, max=500)])
    edit_submit = SubmitField('Save')


class EditList(FlaskForm):
    options_submit = SubmitField('Save')


class UpdateUsernameForm(FlaskForm):
    new_username = StringField('Write your new username:', validators=[DataRequired(), Length(min=2, max=16)])
    new_username_submit = SubmitField('Save changes')
    recaptcha = RecaptchaField()


class UpdatePasswordForm(FlaskForm):
    new_password = PasswordField('Write your new password:', validators=[DataRequired(), Length(min=8, max=35)])
    new_password_confirm = PasswordField('Confirm your new password:', validators=[DataRequired(), Length(min=8, max=35)])
    new_password_submit = SubmitField('Save changes')


class ForgotLoginForm(FlaskForm):
    provide_email = EmailField('Write your e-mail:', validators=[DataRequired(), Email()])
    recaptcha = RecaptchaField()
    provide_email_submit = SubmitField('Submit email')


class DeleteAccountForm(FlaskForm):
    recaptcha = RecaptchaField()
    delete_account_submit = SubmitField('Delete my account')


class SuggestFeatureForm(FlaskForm):
    provide_email = EmailField('Write your e-mail:', validators=[DataRequired(), Email()])
    textarea = TextAreaField('Write your ideas here:', validators=[DataRequired(), Length(min=5, max=500)])
    recaptcha = RecaptchaField()
    suggest_feature_submit = SubmitField('Send')


class ToDoForm(FlaskForm):
    new_task = StringField('Write a new task:', validators=[DataRequired(), Length(min=1, max=500)])
    new_task_submit = SubmitField('add')


class ToDoTitleForm(FlaskForm):
    title = StringField(validators=[DataRequired(), Length(min=2, max=80)])


class CheckboxForm(FlaskForm):
    checkbox = BooleanField()
