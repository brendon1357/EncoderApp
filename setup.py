import sqlite3
import json
import os
from cryptography.fernet import Fernet

def writeKeyToFile():
	# generate a new random key
	databaseKey = Fernet.generate_key()

	jsonData = {"DB_KEY": databaseKey.decode("utf-8")}

	jsonObject = json.dumps(jsonData, indent=4)

	# create the secrets.json file if it doesn't exist
	if (not(os.path.isfile("secrets.json"))):
		with open("secrets.json", "w") as f:
			f.write(jsonObject)

def setupDatabase():
	conn = sqlite3.connect("Database.db")

	with conn as db:
	    cursor = db.cursor()

	cursor.execute('''
	CREATE TABLE IF NOT EXISTS user(
	userID INTEGER PRIMARY KEY,
	username VARCHAR(20) NOT NULL,
	password VARCHAR(24) NOT NULL,
	key VARCHAR(100));
	''')

	cursor.execute('pragma encoding=UTF16')
	db.commit()

if __name__ == "__main__":
	writeKeyToFile()
	setupDatabase()