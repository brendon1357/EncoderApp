import mysql.connector
from staticlibrary import readSecrets


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
