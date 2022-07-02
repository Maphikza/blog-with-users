from flask import Flask, render_template, redirect, url_for, flash, request, abort, jsonify
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import os

# app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

app = Flask(__name__)
app.config['SECRET_KEY'] = "8BYkEfBA6O6donzWlSihBXox7C0sKR6b"
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB > from this ('sqlite:///blog.db')
# app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///blog.db") os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_DATABASE_URI'] = "postgres://nhojzizxsdppvc:00620c781744c8425c7abc6e7e3ddec343c6f8c718429ba72e7306f8e783e620@ec2-44-205-41-76.compute-1.amazonaws.com:5432/dev1u25sd1bgdj"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##Gravatar initialize
gravatar = Gravatar(app)

login_manager = LoginManager()
login_manager.init_app(app)

# print(current_user)
##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

    #creating database relationship with column named author in the BlogPost Table of the database
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # This section adds the author id which in inherited from the User table of the database
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    # This code creates a relationship or reference link to the User object or table from the database.
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")


    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)

db.create_all()

@app.errorhandler(403)
def not_authorised(e):
    error = str(e).split(":")
    error_title = error[0][4:]
    error_description = error[1]
    return render_template('403.html', error_title=error_title, error_description=error_description ), 403



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = request.form.get("name")
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()
        if user:
            flash("This email is already registered, try to login.")
            return redirect(url_for('login'))
        else:
            password = request.form.get("password")
            hashed_and_salted_password = generate_password_hash(password=password, method='pbkdf2:sha256', salt_length=8)

            new_user = User(name=name, email=email, password=hashed_and_salted_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("That email doesn't exist, please try again.")
            return redirect(url_for('login'))
        elif user:
            password = check_password_hash(pwhash=user.password, password=password)
            if not password:
                flash("password incorrect, please try again")
                return redirect(url_for('login'))
            elif password:
                login_user(user=user)
                return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if form.validate_on_submit():
        new_comment = request.form.get("body")
        if current_user.is_anonymous:
            flash("You need to login or register to comment.")
            return redirect(url_for('login'))
        comment = Comment(author_id=current_user.id, post_id=post_id, text=new_comment)
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))

    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
def add_new_post():
    if current_user.is_authenticated and current_user.id == 1:
        form = CreatePostForm()
        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author_id=current_user.id,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    elif current_user.is_anonymous or current_user.id != 1:
        return abort(403)

    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    if current_user.is_authenticated and current_user.id == 1:
        post = BlogPost.query.get(post_id)
        edit_form = CreatePostForm(
            title=post.title,
            subtitle=post.subtitle,
            img_url=post.img_url,
            author=post.author,
            body=post.body
        )
        if edit_form.validate_on_submit():
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            post.author = edit_form.author.data
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id))

    elif current_user.is_anonymous or current_user.id != 1:
        return abort(403)

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    if current_user.is_authenticated and current_user.id == 1:
        post_to_delete = BlogPost.query.get(post_id)
        db.session.delete(post_to_delete)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    elif current_user.is_anonymous or current_user.id != 1:
        return abort(403)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
