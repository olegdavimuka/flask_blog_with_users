import os
import smtplib
from datetime import date
from email.generator import Generator
from email.mime.text import MIMEText
from functools import wraps
from io import StringIO

from flask import Flask, render_template, redirect, url_for, flash, abort, send_from_directory
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

from forms import RegisterForm, LoginForm, CreatePostForm, CommentForm, EmailForm, UserInfoForm

FROM_EMAIL = os.environ.get("FROM_EMAIL")
FROM_EMAIL_PASSWORD = os.environ.get("FROM_EMAIL_PASSWORD")
TO_EMAIL = os.environ.get("TO_EMAIL")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
uri = os.environ.get("DATABASE_URL", "sqlite:///blog.db")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


# CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    author_id = db.Column(db.Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")

    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    text = db.Column(db.Text, nullable=False)

    author_id = db.Column(db.Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="comments")

    post_id = db.Column(db.Integer, ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


db.create_all()


def send_email(name, email, phone, message):
    with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
        connection.starttls()
        connection.login(FROM_EMAIL, FROM_EMAIL_PASSWORD)

        msg = MIMEText(f"Name: {name}\n"
                       f"Email Address: {email}\n"
                       f"Phone Number: {phone}\n"
                       f"Message: {message}")
        msg['Subject'] = "Hello! New message on Blog-CV!"
        str_io = StringIO()
        g = Generator(str_io, False)
        g.flatten(msg)

        connection.sendmail(
            from_addr=FROM_EMAIL,
            to_addrs=TO_EMAIL,
            msg=str_io.getvalue()
        )
    pass


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )

        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password=hash_and_salted_password
        )

        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():

        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))

        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))

        else:
            login_user(user)
            return redirect(url_for("get_all_posts"))

    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=form.comment.data,
            author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        form.comment.data = ""

    return render_template("post.html", post=requested_post, form=form, current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/cv")
def cv():
    return render_template("cv.html", current_user=current_user)


@app.route('/download')
@login_required
def download():
    return send_from_directory(directory='static', path="files/cv.pdf")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    email_form = EmailForm()
    if current_user.is_authenticated:
        email_form = EmailForm(
            name=current_user.name,
            email=current_user.email
        )

    if email_form.validate_on_submit():
        send_email(name=email_form.name.data,
                   email=email_form.email.data,
                   phone=email_form.phone.data,
                   message=email_form.message.data)
        flash("Your email was sent. I will contact you as soon as possible.")
        return redirect(url_for("contact"))

    return render_template("contact.html", form=email_form, current_user=current_user)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)

    comments_to_delete = [Comment.query.get(comment.id) for comment in post_to_delete.comments]
    for comment in comments_to_delete:
        db.session.delete(comment)

    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/user-info", methods=["GET", "POST"])
@login_required
def user_info():
    user_info_form = UserInfoForm(
        name=current_user.name,
        email=current_user.email
    )

    if user_info_form.validate_on_submit():
        if not check_password_hash(current_user.password, user_info_form.password.data):
            flash('Password incorrect, please try again.')
            return redirect(url_for("user_info"))
            # TODO: How to pass variable via redirect?

        if User.query.filter_by(email=user_info_form.email.data).first():
            flash("This email already taken, try another.")
            return redirect(url_for("user_info"))

        current_user.name = user_info_form.name.data
        current_user.email = user_info_form.email.data
        db.session.commit()
        flash('Information successfully changed!')

    return render_template("user_info.html", form=user_info_form, current_user=current_user)


@app.route("/<int:post_id>/delete_comment/<int:comment_id>")
@login_required
def delete_comment(comment_id, post_id):
    comment_to_delete = Comment.query.get(comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
