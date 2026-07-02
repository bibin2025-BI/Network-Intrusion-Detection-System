from flask import Flask, request, render_template, jsonify, url_for
import sqlite3 as sql
import numpy as np
import random
import string
import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import Scanner
from time import time

def generate_password():
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(8))



def send_password(uname, new_pswd):
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login('a74564924@gmail.com', 'vaubkelfhiqjcwgd')
    msg = MIMEMultipart()
    msg['From'] = 'a74564924@gmail.com'
    msg['To'] = uname
    msg['Subject'] = 'New Password'
    body = f'Hello {uname.split("@")[0]},\nYour new password is {new_pswd}.\nPlease login and change your password.\n'
    msg.attach(MIMEText(body, 'plain'))
    server.send_message(msg)
    server.quit()


app = Flask(__name__)

@app.route("/home")
def home():    
    return render_template("home.html")

@app.route('/')
def index():
    return render_template('index.html')

@app.route("/log")
def log():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    uname = request.form['uname']
    pswd = request.form['pswd']
    print("User Credentials: ", uname, pswd)
    conn = sql.connect(r"Database\users.db")
    res = conn.execute(f"SELECT COUNT(*) FROM USER WHERE UNAME='{uname}' AND PSWD='{pswd}'").fetchone()
    if res[0]:
        return jsonify({'success': True, 'redirect': url_for('home')})
    else:
        return jsonify({'success': False})


@app.route("/register", methods=["POST"])
def register():
    uname = request.form['uname']
    pswd = request.form['pswd']
    fname = request.form['fname']
    try:
        conn = sql.connect(r"Database\users.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO USER (FNAME, UNAME, PSWD) VALUES (?, ?, ?)", (fname, uname, pswd))
        conn.commit()
        return jsonify({'msg': "Account Created"})
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'msg': "Account creation failed!"})


@app.route("/logout")
def logout():
    return jsonify({'redirect': url_for("log")})
    

@app.route("/changepassword", methods=["POST"])
def changepassword():
    print("User Details:",request.form)
    user = request.form['user']
    cpswd = request.form['cpswd']
    npswd = request.form['npswd']
    try:
        conn = sql.connect(r"Database\users.db")
        cursor = conn.cursor()
        cursor.execute(f"UPDATE USER SET PSWD='{npswd}' WHERE UNAME='{user}' AND PSWD='{cpswd}'")
        conn.commit()
        return jsonify({'success': True})
    except Exception as ex:
        print(ex)
        return jsonify({'success': False})


@app.route("/reset-password", methods=["POST"])
def resetPassword():
    email = request.form['email']
    try:
        npswd = generate_password()
        send_password(email, npswd)
        conn = sql.connect(r"Database\users.db")
        cursor = conn.cursor()
        cursor.execute(f"UPDATE USER SET PSWD='{npswd}' WHERE UNAME='{email}'")
        conn.commit()
        return jsonify({'success': True, 'msg': "Password sent to your email.."})
    except Exception as ex:
        print(ex)
        return jsonify({'success': False, 'msg': 'Something went wrong! Please try again'})


@app.route("/analyze", methods=["POST"])
def analyze():
    labels = []
    return jsonify({'success': True})


@app.route("/feedback", methods=["POST"])
def feedback():
    print(request.form)
    email = request.form['email']
    conn = sql.connect(r"Database\users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT FNAME FROM USER WHERE UNAME=?", (email,))
    conn.commit()
    result = cursor.fetchone()
    full_name = result[0] if result else None
    if full_name is None:
        return jsonify({'success': False, 'msg': 'No such user exists'})
    
    comment = request.form['comment']
    try:
        conn = sql.connect(r"Database\users.db")
        cursor = conn.cursor()
        now = datetime.datetime.now()
        cursor.execute("INSERT INTO FEEDBACKS (FULLNAME, EMAIL, FEEDBACK, DATETIME) VALUES (?, ?, ?, ?)", (full_name, email, comment, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'success': False})

@app.route("/analyze_file", methods=["POST"])
def analyze_file():
    if request.method == "POST":
        file = request.files["file"]
        if file:
            filename = file.filename
            file_path = os.path.join("SavedFiles", filename)
            file.save(file_path)
            start_time = time()
            result = Scanner.scan(file_path)
            end_time = time()
            duration = end_time - start_time
            if type(result) != bool:
                label = ["Normal", "Intrusion Detected"][result]
                return jsonify({'success': True, 'result': label, duration: duration})
            else:
                return jsonify({'success': False, 'msg': 'Unable to process file'})

if __name__ == '__main__':
    app.run(host="127.0.0.1", debug=True, port=4556)