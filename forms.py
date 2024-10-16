from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, EmailField, SubmitField, PasswordField, TextAreaField
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


class ListForm(FlaskForm):
    task = StringField('Write a new task:', validators=[DataRequired()])
    task_submit = SubmitField('Add')


class UpdateUsernameForm(FlaskForm):
    new_username = StringField('Write your new username:', validators=[DataRequired(), Length(min=2, max=16)])
    new_username_submit = SubmitField('Update username')
    recaptcha = RecaptchaField()


class UpdatePasswordForm(FlaskForm):
    new_password = PasswordField('Write your new password:', validators=[DataRequired(), Length(min=8, max=35)])
    new_password_confirm = PasswordField('Confirm your new password:', validators=[DataRequired(), Length(min=8, max=35)])
    new_password_submit = SubmitField('Update password')


class ForgotLoginForm(FlaskForm):
    provide_email = EmailField('Write your e-mail:', validators=[DataRequired(), Email()])
    recaptcha = RecaptchaField()
    provide_email_submit = SubmitField('Submit email')


class SuggestFeatureForm(FlaskForm):
    provide_email = EmailField('Write your e-mail:', validators=[DataRequired(), Email()])
    textarea = TextAreaField('Write your ideas here:', validators=[DataRequired(), Length(min=5, max=500)])
    recaptcha = RecaptchaField()
    suggest_feature_submit = SubmitField('Send')