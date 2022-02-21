import sqlite3

conn = sqlite3.connect("Database.db")

with conn as db:
    cursor = db.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS user(
userID INTEGER PRIMARY KEY,
username VARCHAR(20) NOT NULL,
password VARCHAR(20) NOT NULL,
key VARCHAR(20));
''')

cursor.execute('pragma encoding=UTF16')
db.commit()
