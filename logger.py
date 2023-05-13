import logging

# class to handle logging server side errors/warnings/info
class Logger():
	def __init__(self, file):
		self.file = file

		logging.basicConfig(filename=self.file, 
                    format='%(asctime)s %(levelname)s %(message)s', 
                    filemode='a')
		self.logger = logging.getLogger()
		self.logger.setLevel(logging.DEBUG)

	def getLogger(self):
		return self.logger