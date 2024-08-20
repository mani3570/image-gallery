import re
from flask import Flask, redirect, render_template, url_for, request, session
import os
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import base64

load_dotenv()

MONGO_URL = os.getenv("MONGO_URL")

application = Flask(__name__)

# Set a secret key for session management
application.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

# MongoDB Atlas connection string
client = MongoClient(MONGO_URL)
db = client["pbl_cloud"]
users_collection = db["users"]


# @application.route("/index")
# def index():
#     if "username" not in session:
#         return redirect(url_for("home"))

#     return render_template("index.html")


@application.route("/view")
def view():
    if "username" not in session:
        return redirect(url_for("home"))

    # Retrieve the uploaded images from the user's collection
    user_uploads = db[session["username"]].find()
    uploads = []
    for upload in user_uploads:
        uploads.applicationend(
            {"filename": upload["filename"], "image_data": upload["image_data"]}
        )

    return render_template("view.html", uploads=uploads)


@application.route("/login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            return "Please enter both username and password"
        user = users_collection.find_one({"username": username})
        if user and check_password_hash(user["password"], password):
            session["username"] = username  # Store username in session
            return redirect(url_for("home"))
        else:
            return "Invalid username or password"
    return render_template("login.html")


@application.route("/signup", methods=["GET", "POST"])
def user_signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            return "Please enter both username and password"
        user = users_collection.find_one({"username": username})
        if user:
            return "Username already exists"
        hashed_password = generate_password_hash(password)
        users_collection.insert_one({"username": username, "password": hashed_password})
        session["username"] = username  # Log in the user after signup
        return redirect(url_for("user_login"))  # Redirect to login after signup
    return render_template("signup.html")


@application.route("/upload", methods=["POST"])
def upload_file():
    if "username" not in session:
        return redirect(url_for("home"))  # Ensure user is logged in to upload files
    if "file" not in request.files:
        return "No file part", 400
    file = request.files["file"]
    if not file.filename:
        return "No selected file", 400
    if file:
        filename = secure_filename(file.filename)

        # Convert the image to Base64 directly from memory
        image_data = base64.b64encode(file.read()).decode("utf-8")

        # Store the Base64 string in the user's collection
        user_collection = db[session["username"]]
        user_collection.insert_one({"filename": filename, "image_data": image_data})

        return render_template("view.html")


@application.route("/")
def home():
    if "username" in session:
        return render_template(
            "index.html"
        )  # Redirect logged-in users to the index page
    return render_template("login.html")


@application.route("/logout")
def logout():
    session.pop("username", None)  # Log out the user
    return redirect(url_for("home"))


if __name__ == "__main__":
    application.run(debug=True, host="0.0.0.0", port=5000)
