from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort, current_app
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField, SubmitField, SelectField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from flask_wtf.file import FileAllowed
from flask_wtf import CSRFProtect
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
import os
import secrets
from PIL import Image
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from itsdangerous import URLSafeTimedSerializer as Serializer, BadSignature, SignatureExpired
import re
import logging
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import socket

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'SxQpmhxEK2xN3RdUbbr3lK58ZQUVjBRO'  # Hard-coded secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///yourdatabase.db'  # Hard-coded database URI
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'barrackdrive@gmail.com'
app.config['MAIL_PASSWORD'] = 'veryStrong'
app.config['MAIL_DEFAULT_SENDER'] = ('BARRACK', 'barrackdrive@gmail.com')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
mail = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Create the uploads directory if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# Define models
def generate_slug(title):
    title = title.lower()
    title = re.sub(r'\s+', '-', title)
    title = re.sub(r'[^\w\-]', '', title)
    return title


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    image_file = db.Column(db.String(20), nullable=True, default=None)

    def __repr__(self):
        return f'<User {self.email}>'

    def get_reset_token(self, expires_sec=1800):
        return serializer.dumps(self.email, salt='password-reset-salt')

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        try:
            email = serializer.loads(token, salt='password-reset-salt', max_age=expires_sec)
        except (SignatureExpired, BadSignature):
            return None
        return User.query.filter_by(email=email).first()

    @staticmethod
    def verify_reset_token(token):
        secret_key = current_app.config['SECRET_KEY']
        if not isinstance(secret_key, str):
            raise TypeError(f"SECRET_KEY should be a string, got {type(secret_key).__name__}")
        s = Serializer(secret_key)
        try:
            user_id = s.loads(token)['user_id']
        except (BadSignature, SignatureExpired):
            return None
        return User.query.get(user_id)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    intro = db.Column(db.Text, nullable=False)
    paragraph_1 = db.Column(db.Text, nullable=False)
    my_back_quote = db.Column(db.Text, nullable=True)
    subheading = db.Column(db.Text, nullable=True)
    paragraph_2 = db.Column(db.Text, nullable=True)
    paragraph_3 = db.Column(db.Text, nullable=True)
    conclusion = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    image = db.Column(db.String(255), nullable=True)
    image_2 = db.Column(db.String(255), nullable=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=True)
    category = db.relationship('Category', backref='posts')

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = generate_slug(self.title)
        super().save(*args, **kwargs)

    def __repr__(self):
        return f'<Post {self.title}>'


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<Category {self.name}>'


# Define forms
class SubscribeForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    intro = TextAreaField('Introduction', validators=[DataRequired()])
    paragraph_1 = TextAreaField('Paragraph 1', validators=[DataRequired()])
    my_back_quote = TextAreaField('Back Quote')
    subheading = TextAreaField('Subheading')
    paragraph_2 = TextAreaField('Paragraph 2')
    paragraph_3 = TextAreaField('Paragraph 3')
    conclusion = TextAreaField('Conclusion')
    category_id = SelectField('Category', coerce=int)
    image = FileField('Image', validators=[FileAllowed(['jpg', 'png'])])
    image_2 = FileField('Image 2', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Submit')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if not user:
            raise ValidationError('There is no account with that email. You must register first.')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')


class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')


# Utility function for truncating words
def truncatewords(value, num_words):
    words = value.split()
    if len(words) > num_words:
        return ' '.join(words[:num_words]) + '...'
    return value


app.jinja_env.filters['truncatewords'] = truncatewords


# Initialize Flask-Admin
class MyAdminIndexView(AdminIndexView):
    @expose('/')
    @login_required
    def index(self):
        return super(MyAdminIndexView, self).index()


class AuthModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated


admin = Admin(app, name='MyAdmin', template_mode='bootstrap3', index_view=MyAdminIndexView())
admin.add_view(AuthModelView(Post, db.session))
admin.add_view(AuthModelView(Category, db.session))


# Route to serve uploaded files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# Routes
@app.route("/")
@app.route("/home")
def home():
    form = SubscribeForm()
    return render_template('index.html', form=form)


@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/portfolio/details")
def portfolio_details():
    return render_template('portfolio_details.html', title='Portfolio Details')


@app.route("/contact")
def contact():
    return render_template('contact.html', title='Contact')


@app.route('/blog')
def blog():
    posts = Post.query.all()
    recent_posts = sorted(posts, key=lambda x: x.created_at, reverse=True)[:4]
    return render_template('blog.html', posts=posts, recent_posts=recent_posts)


@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form.get('email')
    # Add subscription logic here
    flash('Subscribed successfully!', 'success')
    return redirect(request.referrer)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if (form.validate_on_submit()):
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('admin.index'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/blog/<slug>')
def blog_single(slug):
    post = Post.query.filter_by(slug=slug).first()
    if not post:
        abort(404)
    recent_posts = Post.query.order_by(Post.created_at.desc()).limit(4).all()
    return render_template('blog_single.html', post=post, posts=recent_posts)


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)  # No need for .decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        # Redirect to login page or send confirmation email
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account', image_file=image_file, form=form)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)


def send_email():
    msg = Message('Subject', recipients=['recipient@example.com'])
    msg.body = 'This is a test email'
    try:
        mail.send(msg)
    except socket.gaierror as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"Error sending email: {e}")


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@example.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not request this, please ignore this email.
'''
    try:
        mail.send(msg)
    except socket.gaierror as e:
        print(f"Failed to send email due to socket error: {e}")
        flash('There was an issue connecting to the email server. Please try again later.', 'danger')
    except Exception as e:
        print(f"Failed to send email: {e}")
        flash('An unexpected error occurred while sending the email. Please try again later.', 'danger')


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn


if __name__ == '__main__':
    app.run(debug=True)
