import json
import fasteners
import os
import customtkinter as tk
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv


# read secrets from the env file
def readSecrets(file, key) -> str:
	load_dotenv(file)
	return os.getenv(key)

# get the serializer
def getSerializer() -> object:
	return URLSafeTimedSerializer(readSecrets("secrets.env", "SERIALIZER_KEY"))

# helper function to determine if given input is valid json format or not
def isJson(input) -> bool:
	try:
		json.loads(input)
		return True
	except json.JSONDecodeError:
		return False

# helper function to send a msg over given socket with given data and return the response
def sendAndReceiveMsg(socket, givenData, bufferSize) -> str:
	if socket == None:
		return "Not connected to server" 
	try:
		data = givenData
		jsonData = json.dumps(data)
		socket.sendall(jsonData.encode())
		msg = socket.recv(bufferSize).decode()
		return msg
	except OSError as e:
		print("Socket Error: {}".format(e))
		return "A server error occurred"
	except Exception as e:
		print("Unexpected Error: {}".format(e))
		return "An unexpected error occurred"

# try to acquire lock at temp file location to check if an instance of the program is already running
def getInstanceLock() -> object:
	lock = fasteners.InterProcessLock("C:/tmp/app.lock")
	acquireLock = lock.acquire(blocking=False)
	if acquireLock:
		return lock
