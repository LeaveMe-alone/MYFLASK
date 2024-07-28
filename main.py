from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField, SubmitField, SelectField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
import os
import logging
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')  # Use environment variable for secret key
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///yourdatabase.db')
app.config['UPLOAD_FOLDER'] = 'static/uploads'  # Moved uploads folder inside static
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Set max upload size to 16MB
db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)

# Create the uploads directory if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Define models
import re


def generate_slug(title):
    # Convert to lowercase
    title = title.lower()
    # Replace spaces with hyphens
    title = re.sub(r'\s+', '-', title)
    # Remove all non-alphanumeric characters except hyphens
    title = re.sub(r'[^\w\-]', '', title)
    return title


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
    category = db.relationship('Category', backref='posts')  # Define relationship

    def __repr__(self):
        return f'<Post {self.title}>'

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


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    intro = TextAreaField('Introduction', validators=[DataRequired()])
    paragraph_1 = TextAreaField('Paragraph 1', validators=[DataRequired()])
    my_back_quote = TextAreaField('Back Quote')
    subheading = TextAreaField('Subheading')
    paragraph_2 = TextAreaField('Paragraph 2')
    paragraph_3 = TextAreaField('Paragraph 3')
    conclusion = TextAreaField('Conclusion')
    category_id = SelectField('Category', coerce=int)  # Add category selection
    image = FileField('Image')
    image_2 = FileField('Image 2')
    submit = SubmitField('Submit')



# Utility function for truncating words
def truncatewords(value, num_words):
    words = value.split()
    if len(words) > num_words:
        return ' '.join(words[:num_words]) + '...'
    return value


app.jinja_env.filters['truncatewords'] = truncatewords


# Initialize Flask-Admin
class PostModelView(ModelView):
    form_overrides = {
        'image': FileField,
        'image_2': FileField
    }

    form_excluded_columns = ('slug',)

    def on_model_change(self, form, model, is_created):
        if form.image.data:
            filename = secure_filename(form.image.data.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            logging.debug(f"Saving image to {filepath}")
            form.image.data.save(filepath)
            model.image = filename

        if form.image_2.data:
            filename_2 = secure_filename(form.image_2.data.filename)
            filepath_2 = os.path.join(app.config['UPLOAD_FOLDER'], filename_2)
            logging.debug(f"Saving image 2 to {filepath_2}")
            form.image_2.data.save(filepath_2)
            model.image_2 = filename_2

        # Ensure the slug is generated before saving
        if not model.slug:
            model.slug = generate_slug(model.title)

        return super().on_model_change(form, model, is_created)


admin = Admin(app, name='MyAdmin', template_mode='bootstrap3')
admin.add_view(PostModelView(Post, db.session))
admin.add_view(ModelView(Category, db.session))


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
    # Assuming you fetch your posts from a database or any other source
    posts = Post.query.all()  # Replace this with your actual data fetching logic
    recent_posts = sorted(posts, key=lambda x: x.created_at, reverse=True)[:4]
    return render_template('blog.html', posts=posts, recent_posts=recent_posts)


@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form.get('email')
    # Add subscription logic here
    flash('Subscribed successfully!', 'success')
    return redirect(request.referrer)



@app.route('/blog/<slug>')
def blog_single(slug):
    post = Post.query.filter_by(slug=slug).first()  # Fetch a single post based on the slug
    if not post:
        abort(404)  # Return a 404 error if the post is not found

    recent_posts = Post.query.order_by(Post.created_at.desc()).limit(4).all()  # Fetch the 4 most recent posts
    return render_template('blog_single.html', post=post, posts=recent_posts)




if __name__ == '__main__':
    app.run(debug=True)
