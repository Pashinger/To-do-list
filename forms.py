from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, Length


class AccountForm(FlaskForm):
    username = StringField('Write your username:', validators=[DataRequired(), Length(min=2, max=16)])
    email = EmailField('Write your e-mail:', validators=[DataRequired(), Email()])
    password = PasswordField('Write your password:', validators=[DataRequired(), Length(min=8, max=60)])
    login_submit = SubmitField('Log In')
    sign_up_submit = SubmitField('Create an account')


class ListForm(FlaskForm):
    task = StringField('Write a new task', validators=[DataRequired()])
    task_submit = SubmitField('Add')


class UpdateUsernameForm(FlaskForm):
    new_username = StringField('Write your new username:', validators=[DataRequired(), Length(min=2, max=16)])
    new_username_submit = SubmitField('Update username')


class UpdatePasswordForm(FlaskForm):
    new_password = PasswordField('Write your new password:', validators=[DataRequired(), Length(min=8, max=35)])
    new_password_confirm = PasswordField('Confirm your new password:', validators=[DataRequired(), Length(min=8, max=35)])
    new_password_submit = SubmitField('Update password')