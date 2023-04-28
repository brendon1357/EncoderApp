import socket
import ssl
import os
import threading
import bcrypt
import mysql.connector
import json
import re
from db import readSecrets, getDB
from cryptography.fernet import Fernet

class HandleClient(threading.Thread):
	def __init__(self, clientSock, address):
		threading.Thread.__init__(self)
		self.sock = clientSock
		self.address = address

	# insert username, password hash, and salt into database
	def insertUser(self, username, password):
		connection = getDB()
		if connection is None:
			print("Could not connect to database")
			return
		try:
			cursor = connection.cursor()
			# generate a random salt
			salt = bcrypt.gensalt()
			# hash the password with the random salt
			hashedPassword = bcrypt.hashpw(password.encode(), salt)
			insertQuery = "INSERT INTO userstable (username, passwordHash, salt) VALUES (%s, %s, %s)"
			values = (username.lower(), hashedPassword, salt)
			cursor.execute(insertQuery, values)
			connection.commit()
			
			# respond with a msg that the client has registered successfully
			print("Client " + self.address[0] + " successfully registered")
			self.sock.sendall(b'Successfully registered')
	
		except mysql.connector.Error as e:
			print("Error: {}".format(e))

	# adds the user to the database if the user doesn't already exist
	def createUser(self, username, password):
		connection = getDB()
		if connection is None:
			print("Could not connect to database")
			return
		try:
			cursor = connection.cursor()
			selectQuery = "SELECT COUNT(*) FROM userstable WHERE username = %s"
			cursor.execute(selectQuery, (username,))
			result = cursor.fetchone()

			if (result[0] > 0):
				print("Client " + self.address[0] + " failed to register")
				self.sock.sendall(b'Username already exists')
			else:
				self.insertUser(username, password)

		except mysql.connector.Error as e:
			print("Error: {}".format(e))

	# check for successful login
	def loginSuccess(self, username, password):
		connection = getDB()
		if connection is None:
			print("Could not connect to database")
			return
		try:
			cursor = connection.cursor()
			selectQuery = "SELECT salt, passwordHash FROM userstable WHERE username = %s"
			cursor.execute(selectQuery, (username,))
			result = cursor.fetchone()
			if result is not None:
				salt = result[0]
				hashedPassword = result[1]

				hashedInputPassword = bcrypt.hashpw(password.encode(), salt.encode())

				if hashedPassword == hashedInputPassword.decode():
					print("Client " + self.address[0] + " successfully logged in")
					self.sock.sendall(b'Login successful')
				else:
					print("Client " + self.address[0] + " failed to login")
					self.sock.sendall(b'Username or password does not exist')
			else:
				print("Client " + self.address[0] + " failed to login")
				self.sock.sendall(b'Username or password does not exist')

		except mysql.connector.Error as e:
			print("Error: {}".format(e))

	# save the given password and password label in the database for the given user
	def savePassword(self, username, password, label):
		connection = getDB()
		if connection is None:
			print("Could not connect to database")
			return
		try:
			cursor = connection.cursor()
			selectUserIDQuery = "SELECT id FROM userstable WHERE username = %s"
			cursor.execute(selectUserIDQuery, (username,))
			userID = cursor.fetchone()[0]

			selectKeyQuery = "SELECT encryptionkey FROM encryptionkeys WHERE userID = %s"
			cursor.execute(selectKeyQuery, (userID,))
			key = cursor.fetchone()

			if not key:
				newKey = Fernet.generate_key()
				insertEncryptionKeyQuery = "INSERT INTO encryptionkeys (userID, encryptionkey) VALUES (%s, %s)"
				cursor.execute(insertEncryptionKeyQuery, (userID, newKey))
				connection.commit()
				key = newKey
			else:
				key = key[0]

			f = Fernet(key)
			encryptedPassword = f.encrypt(password.encode())

			checkExistingQuery = "SELECT * FROM passwordstable WHERE userID = %s AND (encryptedPassword = %s OR label = %s)"
			cursor.execute(checkExistingQuery, (userID, encryptedPassword, label))

			if cursor.fetchall():
				 print("Client " + self.address[0] + " password or label already exists for: " + username)
				 self.sock.sendall(b'Password or label already exists. Generate a unique password and enter a unique label')
			else:
				insertEncryptedPasswordQuery = "INSERT INTO passwordstable (userID, encryptedPassword, label) VALUES (%s, %s, %s)"
				cursor.execute(insertEncryptedPasswordQuery, (userID, encryptedPassword, label))
				connection.commit()

				print("Client " + self.address[0] + " password save successfully for: " + username)
				self.sock.sendall(b'Password saved')

		except mysql.connector.Error as e:
			print("Error: {}".format(e))

	# return true if given string is a valid password otherwise return false
	def validPassword(self, str):
		if len(str) < 8:
			return False
		symbols = r'[@!#$%&-]'
		return bool(re.search(symbols, str))

	# keep listening for messages from the client and handle requests
	def run(self):
		while True:
			msg = self.sock.recv(2048).decode()
			if not msg:
				print("Client disconnected from IP: " + self.address[0])
				self.sock.close()
				break
			else:
				jsonData = json.loads(msg)
				if jsonData["type"] == "Register":
					username = jsonData["username"]
					password = jsonData["password"]
					if username == "" or password == "":
						print("Client " + self.address[0] + " failed to register empty input(s)")
						self.sock.sendall(b'Username or password empty')
					elif len(username) < 6 or len(username) > 40:
						print("Client " + self.address[0] + " failed to register username invalid")
						self.sock.sendall(b'Username must be greater than 5 characters and less than 40 characters')
					elif not self.validPassword(password):
						print("Client " + self.address[0] + " failed to register invalid password")
						self.sock.sendall(b'Password must be at least 8 characters and contain a symbol: @, !, #, $, %, &, -')
					else:
						print("Client " + self.address[0] + " attempting to create account with username: " + username)
						self.createUser(username, password)

				elif jsonData["type"] == "Login":
					username = jsonData["username"]
					password = jsonData["password"]
					if username == "" or password == "":
						print("Client " + self.address[0] + " failed to login empty input(s)")
						self.sock.sendall(b'Username or password empty')
					else:
						print("Client " + self.address[0] + " attempting to login with username: " + username)
						self.loginSuccess(username, password)

				elif jsonData["type"] == "Save password":
					username = jsonData["username"]
					password = jsonData["password"]
					label = jsonData["label"]
					if (password == "" or label == ""):
						print("Client " + self.address[0] + " attempting to save an empty password or empty label: " + username)
						self.sock.sendall(b'Empty input(s) enter a label and generate a password')
					else:
						print("Client " + self.address[0] + " attempting to save a password with username: " + username)
						self.savePassword(username, password, label)


# the server class
class Server():
	def __init__(self):
		self.s = socket.socket()
		self.s.bind(('127.0.0.1', 33333))
		self.s.listen()
		self.sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
		self.sslContext.load_cert_chain('server_cert.pem', keyfile='server_key.pem', password=readSecrets("secrets.env", "KEYFILE_PASS").encode())

	# keep listening for client connections and create a thread for each client
	def start(self):
		print("Server started...")
		while True:
			conn, clientAddress = self.s.accept()
			print("Client connected from IP: " + clientAddress[0] + " on PORT: " + str(clientAddress[1]))
			connSSL = self.sslContext.wrap_socket(conn, server_side=True)
			clientThread = HandleClient(connSSL, clientAddress)
			clientThread.start()

# start the server
if __name__ == "__main__":
	server = Server()
	server.start()
