import socket
import ssl
import threading
from clienthandler import HandleClient
from staticlibrary import readSecrets
from logger import Logger

# the server class
class Server():
	def __init__(self):
		self.s = socket.socket()
		self.s.bind(('127.0.0.1', 33333))
		self.s.listen()
		self.sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
		self.sslContext.load_cert_chain('../resources/server_cert.pem', keyfile='../resources/server_key.pem', password=readSecrets("../resources/secrets.env", "KEYFILE_PASS").encode())

		loggerObject = Logger("../resources/logfile.log")
		self.logger = loggerObject.getLogger()

	# keep listening for client connections and create a thread for each client
	def start(self) -> None:
		print("Server started...")
		while True:
			conn, clientAddress = self.s.accept()
			print("Client connected from IP: " + clientAddress[0] + " on PORT: " + str(clientAddress[1]))
			self.logger.info("Client connected from IP: " + clientAddress[0] + " on PORT: " + str(clientAddress[1]))
			connSSL = self.sslContext.wrap_socket(conn, server_side=True)
			clientThread = HandleClient(connSSL, clientAddress)
			clientThread.start()


# start the server
if __name__ == "__main__":
	server = Server()
	server.start()
