import socket
import ssl
import threading
from clienthandler import HandleClient
from db import readSecrets


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
