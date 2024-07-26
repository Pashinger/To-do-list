from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
# from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'qTxTi6fO6zsqajr9lgLw1Tnt'
Bootstrap(app)

# Configure Flask-Login
# login_manager = LoginManager()
# login_manager.init_app(app)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/user/<username>')
def user(username):
    return render_template('user.html', username=username)

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