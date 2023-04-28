import sqlite3
import os
import mysql.connector
from dotenv import load_dotenv, set_key

# read secrets from the env file
def readSecrets(file, key):
	load_dotenv(file)
	return os.getenv(key)

# connect to the database and return connection instance
def getDB():
	USER = readSecrets("secrets.env", "DATABASE_USER")
	PASSWORD = readSecrets("secrets.env", "DATABASE_PASSWORD")

	try:
		connection = mysql.connector.connect(
			host="localhost",
			user=USER,
			password=PASSWORD,
			database="PasswordManagement"
		)
		return connection

	except mysql.connector.Error as e:
		print("Error: {}".format(e))
		return None
