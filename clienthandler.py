import socket
import ssl
import os
import threading
import bcrypt
import mysql.connector
import json
import re
import time
from cryptography.fernet import Fernet
from staticlibrary import isJson
from db import getDB
from logger import Logger


# Class to handle clients in a new thread for each client
class HandleClient(threading.Thread):
	def __init__(self, clientSock, address):
		threading.Thread.__init__(self)
		self.sock = clientSock
		self.address = address
		self.lastRequestTime = {}
		self.lastTimeoutTime = 0

		loggerObject = Logger("logfile.log")
		self.logger = loggerObject.getLogger()
 
	# check the last request sent and prevent multiple requests too frequently
	def checkRateLimit(self, requestType):
		if requestType in self.lastRequestTime:
			timeSinceLast = time.time() - self.lastRequestTime[requestType]
			if self.userOnTimeout():
				return False
			if timeSinceLast < 0.25:
				self.lastTimeoutTime = time.time()
				return False
		return True

	# check if the user has been put on a temporary timeout after doing frequent requests
	def userOnTimeout(self):
		if time.time() - self.lastTimeoutTime < 3:
			return True
		return False

	# insert username, password hash, and salt into database
	def insertUser(self, username, password):
		connection = getDB()
		if connection is None:
			print("Could not connect to database")
			self.logger.critical("Could not connect to database")
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
			print("Client " + self.address[0] + " [" + username + "]" + " successfully registered")
			self.logger.info("Client " + self.address[0] + " [" + username + "]" + " successfully registered")
			self.sock.sendall(b'Successfully registered')
		except Exception as e:
			self.sock.sendall(b'Server error')
			print("Error: {}".format(e))
			self.logger.error(e)

	# adds the user to the database if the user doesn't already exist
	def createUser(self, username, password):
		if username == "" or password == "":
			print("Client " + self.address[0] + " failed to register empty input(s)")
			self.logger.warning("Client " + self.address[0] + " failed to register empty input(s)")
			self.sock.sendall(b'Username or password empty')
			return
		elif len(username) < 6 or len(username) > 40:
			print("Client " + self.address[0] + " failed to register username invalid")
			self.logger.warning("Client " + self.address[0] + " failed to register username invalid")
			self.sock.sendall(b'Username must be greater than 5 characters and less than 40 characters')
			return
		elif not self.validPassword(password):
			print("Client " + self.address[0] + " failed to register invalid password")
			self.logger.warning("Client " + self.address[0] + " failed to register invalid password")
			self.sock.sendall(b'Password must be at least 8 characters and contain a symbol')
			return

		print("Client " + self.address[0] + " attempting to create account with username: " + username)
		self.logger.info("Client " + self.address[0] + " attempting to create account with username: " + username)
		connection = getDB()
		if connection is None:
			print("Could not connect to database")
			self.logger.critical("Could not connect to database")
			return
		try:
			cursor = connection.cursor()
			selectQuery = "SELECT COUNT(*) FROM userstable WHERE username = %s"
			cursor.execute(selectQuery, (username,))
			result = cursor.fetchone()

			if result[0] > 0:
				print("Client " + self.address[0] + " failed to register username already exists")
				self.logger.warning("Client " + self.address[0] + " failed to register username already exists")
				self.sock.sendall(b'Username already exists')
			else:
				self.insertUser(username, password)
		except Exception as e:
			self.sock.sendall(b'Server error')
			print("Error: {}".format(e))
			self.logger.error(e)

	# check for user in database
	def authenticateUser(self, username, password):
		if username == "" or password == "":
			print("Client " + self.address[0] + " failed to login empty input(s)")
			self.logger.warning("Client " + self.address[0] + " failed to login empty input(s)")
			self.sock.sendall(b'Username or password empty')
			return

		print("Client " + self.address[0] + " attempted to login with username: " + username)
		self.logger.info("Client " + self.address[0] + " attempted to login with username: " + username)
		connection = getDB()
		if connection is None:
			print("Could not connect to database")
			self.logger.critical("Could not connect to database")
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
					print("Client " + self.address[0] + " [" + username + "]" + " successfully logged in")
					self.logger.info("Client " + self.address[0] + " [" + username + "]" + " successfully logged in")
					self.sock.sendall(b'Login successful')
				else:
					print("Client " + self.address[0] + " failed to login username or password does not exist")
					self.logger.warning("Client " + self.address[0] + " failed to login username or password does not exist")
					self.sock.sendall(b'Username or password does not exist')
			else:
				print("Client " + self.address[0] + " failed to login username or password does not exist")
				self.logger.warning("Client " + self.address[0] + " failed to login username or password does not exist")
				self.sock.sendall(b'Username or password does not exist')
		except Exception as e:
			self.sock.sendall(b'Server error')
			print("Error: {}".format(e))
			self.logger.error(e)

	# save the given password and password label in the database for the given user
	def savePassword(self, username, password, label):
		if password == "" or label == "":
			print("Client " + self.address[0] + " [" + username + "]" + " attempted to save an empty password or label")
			self.logger.warning("Client " + self.address[0] + " [" + username + "]" + " attempted to save an empty password or label")
			self.sock.sendall(b'Empty input(s) enter a label and generate a password')
			return
		elif len(password) > 32 or len(password) < 8:
			print("Client " + self.address[0] + " [" + username + "]" + " attempted to save an invalid password (invalid length)")
			self.logger.warning("Client " + self.address[0] + " [" + username + "]" + " attempted to save an invalid password (invalid length)")
			self.sock.sendall(b'Password must be between 8 and 32 characters inclusive')
			return
		elif len(label) >=50:
			print("Client " + self.address[0] + " [" + username + "]" + " attempted to save a password with a label over 50 characters")
			self.logger.warning("Client " + self.address[0] + " [" + username + "]" + " attempted to save a password with a label over 50 characters")
			self.sock.sendall(b'Label must be 50 characters or less')
			return

		print("Client " + self.address[0] + " [" + username + "]" + " attempted to save a password")
		self.logger.info("Client " + self.address[0] + " [" + username + "]" + " attempted to save a password")
		connection = getDB()
		if connection is None:
			print("Could not connect to database")
			self.logger.critical("Could not connect to database")
			return
		try:
			userID = self.getUserID(username)
			if userID is None:
				print("Could not retrieve user id")
				self.logger.critical("Could not retrieve user id")
				return

			cursor = connection.cursor()
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
				 print("Client " + self.address[0] + " [" + username + "]" + " password or label already exists")
				 self.logger.warning("Client " + self.address[0] + " [" + username + "]" + " password or label already exists")
				 self.sock.sendall(b'Password or label already exists. Generate a unique password and enter a unique label')
			else:
				insertEncryptedPasswordQuery = "INSERT INTO passwordstable (userID, encryptedPassword, label) VALUES (%s, %s, %s)"
				cursor.execute(insertEncryptedPasswordQuery, (userID, encryptedPassword, label))
				connection.commit()

				print("Client " + self.address[0] + " [" + username + "]" + " password saved successfully")
				self.logger.info("Client " + self.address[0] + " [" + username + "]" + " password saved successfully")
				self.sock.sendall(b'Password saved')
		except Exception as e:
			self.sock.sendall(b'Server error')
			print("Error: {}".format(e))
			self.logger.error(e)

	# return true if given string is a valid password otherwise return false
	def validPassword(self, str):
		if len(str) < 8:
			return False
		symbols = r'[#%!^&()<>?_=+@~-]'
		return bool(re.search(symbols, str))

	# send the users passwords over socket to them
	def sendPasswords(self, username):
		print("Client " + self.address[0] + " [" + username + "]" + " attempted to retrieve passwords")
		self.logger.info("Client " + self.address[0] + " [" + username + "]" + " attempted to retrieve passwords")
		connection = getDB()
		if connection is None:
			print("Could not connect to database")
			self.logger.critical("Could not connect to database")
			return
		try:
			userID = self.getUserID(username)
			if userID is None:
				print("Could not retrieve user id")
				self.logger.critical("Could not retrieve user id")
				return

			cursor = connection.cursor()
			selectPasswordsQuery = "SELECT encryptedPassword, label FROM passwordstable WHERE userID = %s"
			cursor.execute(selectPasswordsQuery, (userID,))
			passwords = cursor.fetchall()

			passwordData = []
			for encryptedPassword, label in passwords:
				passwordData.append({"encryptedPassword": encryptedPassword, "label": label})

			jsonData = json.dumps(passwordData)
			self.sock.sendall(jsonData.encode())

			print("Client " + self.address[0] + " [" + username + "]" + " passwords were sent successfully")
			self.logger.info("Client " + self.address[0] + " [" + username + "]" + " passwords were sent successfully")
		except Exception as e:
			self.sock.sendall(b'Server error')
			print("Error: {}".format(e))
			self.logger.error(e)

	# update password label in database
	def updateLabel(self, username, newLabel, oldLabel):
		if newLabel == "":
			print("Client " + self.address[0] + " [" + username + "]" + " attempted to update label with empty string")
			self.logger.warning("Client " + self.address[0] + " [" + username + "]" + " attempted to update label with empty string")
			self.sock.sendall(b'Cant update empty label')
			return
		elif len(newLabel) > 50:
			print("Client " + self.address[0] + " [" + username + "]" + " attempted to modify label to over 50 characters")
			self.logger.warning("Client " + self.address[0] + " [" + username + "]" + " attempted to modify label to over 50 characters")
			self.sock.sendall(b'Label must be 50 characters or less')
			return

		print("Client " + self.address[0] + " [" + username + "]" + " attempted to update label")
		self.logger.info("Client " + self.address[0] + " [" + username + "]" + " attempted to update label")
		connection = getDB()
		if connection is None:
			print("Could not connect to database")
			self.logger.critical("Could not connect to database")
			return None
		try:
			userID = self.getUserID(username)
			if userID is None:
				print("Could not retrieve user id")
				self.logger.critical("Could not retrieve user id")
				return

			cursor = connection.cursor()
			updateLabelQuery = """
				UPDATE passwordstable AS pt1
				LEFT JOIN passwordstable AS pt2 ON pt1.userID = pt2.userID AND pt2.label = %s
				SET pt1.label = %s
				WHERE pt1.userID = %s AND pt1.label = %s AND pt2.label IS NULL
			"""
			cursor.execute(updateLabelQuery, (newLabel, newLabel, userID, oldLabel))
			connection.commit()

			if cursor.rowcount > 0:
				print("Client " + self.address[0] + " [" + username + "]" + " updated label successfully")
				self.logger.info("Client " + self.address[0] + " [" + username + "]" + " updated label successfully")
				self.sock.sendall(b'Label updated')
			else:
				print("Client " + self.address[0] + " [" + username + "]" + " failed to update label not unique")
				self.logger.warning("Client " + self.address[0] + " [" + username + "]" + " failed to update label not unique")
				self.sock.sendall(b'Update failed, enter unique label')
		except Exception as e:
			self.sock.sendall(b'Server error')
			print("Error: {}".format(e))
			self.logger.error(e)

	# decrypt the given password for the given user and send it over socket
	def decryptPassword(self, username, password):
		if len(password) <= 32:
			print("Client " + self.address[0] + " [" + username + "]" + " password was already decrypted")
			self.logger.warning("Client " + self.address[0] + " [" + username + "]" + " password was already decrypted")
			self.sock.sendall(b'Already decrypted')
			return
		
		print("Client " + self.address[0] + " [" + username + "]" + " attempted to decrypt a password")
		self.logger.info("Client " + self.address[0] + " [" + username + "]" + " attempted to decrypt a password")
		connection = getDB()
		if connection is None:
			print("Could not connect to database")
			self.logger.critical("Could not connect to database")
			return
		try:
			userID = self.getUserID(username)
			if userID is None:
				print("Could not retrieve user id")
				self.logger.critical("Could not retrieve user id")
				return

			cursor = connection.cursor()
			selectKeyQuery = "SELECT encryptionkey FROM encryptionkeys WHERE userID = %s"
			cursor.execute(selectKeyQuery, (userID,))
			encryptionKey = cursor.fetchone()[0]

			f = Fernet(encryptionKey)
			decryptedPassword = f.decrypt(password).decode()

			passwordData = {"msg": "Password decrypted", "password": decryptedPassword}
			jsonData = json.dumps(passwordData)
			self.sock.sendall(jsonData.encode())

			print("Client " + self.address[0] + " [" + username + "]" + " decrypted password successfully")
			self.logger.info("Client " + self.address[0] + " [" + username + "]" + " decrypted password successfully")
		except Exception as e:
			self.sock.sendall(b'Server error')
			print("Error: {}".format(e))
			self.logger.error(e)

	# get user id for given username
	def getUserID(self, username):
		connection = getDB()
		if connection is None:
			print("Could not connect to database")
			self.logger.critical("Could not connect to database")
			return None
		try:
			cursor = connection.cursor()
			selectUserIDQuery = "SELECT id FROM userstable WHERE username = %s"
			cursor.execute(selectUserIDQuery, (username,))
			return cursor.fetchone()[0]
		except Exception as e:
			print("Error: {}".format(e))
			self.logger.error(e)
			return None

	# delete the given password for the given user
	def deletePassword(self, username, password):
		print("Client " + self.address[0] + " [" + username + "]" + " attempted to delete a password")
		self.logger.info("Client " + self.address[0] + " [" + username + "]" + " attempted to delete a password")
		connection = getDB()
		if connection is None:
			print("Could not connect to database")
			self.logger.critical("Could not connect to database")
			return
		try:
			userID = self.getUserID(username)
			if userID is None:
				print("Could not retrieve user id")
				self.logger.critical("Could not retrieve user id")
				return
			cursor = connection.cursor()

			passwordToDelete = password
			deletePasswordQuery = "DELETE FROM passwordstable WHERE userID = %s AND encryptedPassword = %s"
			cursor.execute(deletePasswordQuery, (userID, passwordToDelete))
			connection.commit()

			if cursor.rowcount > 0:
				print("Client " + self.address[0] + " [" + username + "]" + " deleted password successfully")
				self.logger.info("Client " + self.address[0] + " [" + username + "]" + " deleted password successfully")
				cursor = connection.cursor()
				selectPasswordsQuery = "SELECT encryptedPassword, label FROM passwordstable WHERE userID = %s"
				cursor.execute(selectPasswordsQuery, (userID,))
				passwords = cursor.fetchall()
				passwordData = []
				for encryptedPassword, label in passwords:
					passwordData.append({"encryptedPassword": encryptedPassword, "label": label})
				data = {"msg": "Password deleted successfully", "passwords": passwordData}
				jsonData = json.dumps(data)
				self.sock.sendall(jsonData.encode())
			else:
				print("Client " + self.address[0] + " [" + username + "]" + " failed to delete password")
				self.logger.warning("Client " + self.address[0] + " [" + username + "]" + " failed to delete password")
				data = {"msg": "Password failed to delete"}
				jsonData = json.dumps(data)
				self.sock.sendall(jsonData.encode())
		except Exception as e:
			print("Error: {}".format(e))
			self.logger.error(e)
			return None

	# keep listening for messages from the client and handle requests
	def run(self):
		while True:
			msg = self.sock.recv(2048).decode()
			if not msg:
				print("Client disconnected from IP: " + self.address[0])
				self.logger.info("Client disconnected from IP: " + self.address[0])
				self.sock.close()
				break 

			if isJson(msg):
				jsonData = json.loads(msg)
				if not self.checkRateLimit(jsonData["type"]):
					print("Client " + self.address[0] + " tried to perform the same operation too frequently")
					self.logger.warning("Client " + self.address[0] + " tried to perform the same operation too frequently")
					self.sock.sendall(b'Too many requests, please wait at least 3 seconds')
					continue
				
				username = jsonData["username"].lower()
				if jsonData["type"] == "Register":
					password = jsonData["password"]
					self.createUser(username, password)

				elif jsonData["type"] == "Login":
					password = jsonData["password"]
					self.authenticateUser(username, password)

				elif jsonData["type"] == "Save password":
					password = jsonData["password"]
					label = jsonData["label"].strip()
					self.savePassword(username, password, label)

				elif jsonData["type"] == "Get passwords":
					self.sendPasswords(username)

				elif jsonData["type"] == "Decrypt password":
					password = jsonData["password"]
					self.decryptPassword(username, password)

				elif jsonData["type"] == "Modify label":
					newLabel = jsonData["newLabel"].strip()
					oldLabel = jsonData["oldLabel"].strip()
					self.updateLabel(username, newLabel, oldLabel)

				elif jsonData["type"] == "Delete password":
					password = jsonData["password"]
					self.deletePassword(username, password)

				self.lastRequestTime[jsonData["type"]] = time.time()
			else:
				print("Client " + self.address[0] + " [" + username + "]" + " sent an invalid request")
				self.logger.warning("Client " + self.address[0] + " [" + username + "]" + " sent an invalid request")
				self.sock.sendall(b'Server could not handle request')