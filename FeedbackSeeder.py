import sqlite3
import random
import string
import datetime

conn = sqlite3.connect(r'Database\users.db')
c = conn.cursor()

c.execute("""CREATE TABLE IF NOT EXISTS feedbacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT,
            email TEXT,
            feedback TEXT,
            datetime TEXT
            )""")

conn.commit()

feedbacks = [
    ("John Doe", "john@example.com", "This is a great website!", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    ("Jane Doe", "jane@example.com", "I love the design of this website!", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    ("Bob Smith", "bob@example.com", "This website is so easy to use!", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    ("Alice Johnson", "alice@example.com", "I have been using this website for years and it's always improving!", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    ("Michael Brown", "michael@example.com", "This website is so fast and reliable!", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
]

for feedback in feedbacks:
    c.execute("INSERT INTO feedbacks (fullname, email, feedback, datetime) VALUES (?, ?, ?, ?)", feedback)

conn.commit()
conn.close()
