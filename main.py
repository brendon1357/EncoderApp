import sqlite3
import collections
import random
import string
import customtkinter as tk
from cryptography.fernet import Fernet
from tkinter import messagebox

# key used to decrypt database information
DATABASE_KEY = b'ydp8TlGve70o-viJZYk_pM3uRsDMJ-il9imb9otGRic='

# decrypts a previously encoded string to it's original form
def decryptMessage(encryptedPassword, key):
	f = Fernet(key)
	decryptedPassword = f.decrypt(encryptedPassword)

	return decryptedPassword.decode()

# encrypts inputted string into bytes.
def encryptMessage(password, key):
	encodedPassword = password.encode()
	f = Fernet(key)
	encodedPassword = f.encrypt(encodedPassword)

	return encodedPassword

# searches for user's username in database
def searchUser(username):
	with sqlite3.connect("Database.db") as db:
		cursor = db.cursor()
	cursor.execute("SELECT * FROM user")
	results = cursor.fetchall()

	if results:
		for i in results:
			# loops through all encrypted usernames, decrypts them and checks if the username
			# user is logging in with matches any registered usernames
			if decryptMessage(i[1], DATABASE_KEY).lower() == username.lower():
				real_user = i[1]
				return real_user


# the root window of the application
class Root(tk.CTk):
	def __init__(self):
		tk.CTk.__init__(self)
		# dictionary to store all of the frammes
		self.frames = {}

		container = tk.CTkFrame(self)
		self.title("Password Manager")
		self.resizable(False, False)
		container.pack()
		tk.set_appearance_mode("dark")
		tk.set_default_color_theme("blue")

		loginFrame = LoginScreen(container, self, 350, 450)
		self.frames[LoginScreen] = loginFrame
		self.createFrame(LoginScreen, 0, 0, 50, 50)

		passwordManagementFrame = PasswordManagementScreen(container, self, 500, 700, "")
		self.frames[PasswordManagementScreen] = passwordManagementFrame

		informationFrame = InformationScreen(container, self, 500, 350)
		self.frames[InformationScreen] = informationFrame

	# create a frame and add it to the grid at given row and col
	def createFrame(self, name, row, col, padx, pady):
		frame = self.frames[name]
		frame.grid(row=row, column=col, padx=padx, pady=pady)
		if (not(name == InformationScreen)):
			self.centerWindow()

	# show the given frame
	def showFrame(self, name):
		frame = self.frames[name]
		frame.grid()

	# hide the given frame
	def hideFrame(self, name):
		frame = self.frames[name]
		frame.grid_remove()

	# destroy the given frame
	def destroyFrame(self, name):
		frame = self.frames[name]
		frame.destroy()

	# set the key for the given frame
	# should only be used when constructing PasswordManagementScreen
	def setKeyForFrame(self, name, key):
		self.frames[name].setKey(key)

	# set the username for the given frame
	# should only be used when constructing PasswordManagementScreen
	def setUsernameForFrame(self, name, username):
		self.frames[name].setUsername(username)

	place window at the center of the screen
	def centerWindow(self):
		self.update_idletasks()
		width = self.winfo_reqwidth()
		height = self.winfo_reqheight()
		x = (self.winfo_screenwidth() // 2) - (width // 2)
		y = (self.winfo_screenheight() // 2) - (height // 2)
		self.geometry('+{}+{}'.format( x, y))


# frame that displays information on how to use the application
class InformationScreen(tk.CTkFrame):
	def __init__(self, parent, controller, height, width):
		tk.CTkFrame.__init__(self, parent, height=height, width=width)

		infoLabel = tk.CTkLabel(self, text="User Instructions", font=("Arial", 30, "bold"))
		infoLabel.place(relx=0.50, rely=0.10, anchor=tk.CENTER)

		textBox = tk.CTkTextbox(self, wrap="word", width=325, height=500, activate_scrollbars=False)
		textBox.place(relx=0.50, rely=0.70, anchor=tk.CENTER)
		textBox.insert("0.0", "Generate a new password by clicking the Generate Password button. ")
		textBox.insert("end", "Doing so will give you your true password and your encoded password. Your true password is what will be ")
		textBox.insert("end", "used to create some account (not for this app). You will create an account with the true password and store the encoded password.\n\n")
		textBox.insert("end", "The encoded password ")
		textBox.insert("end", "should be stored somewhere easily retrievable, along with the specific account you're using the password for ")
		textBox.insert("end", "so you know what account it is associated with.\n\n")
		textBox.insert("end", "When you wish to log into an account you created with a generated password from here, you must get the encoded password ")
		textBox.insert("end", "wherever you have it stored, then log back into this app, paste the encoded password in the decode field and press Decode. ")
		textBox.insert("end", "This will give you your true password which you can then use.")
		textBox.configure(fg_color="gray20", state="disabled")


# main frame after logging in, where the user can generate passwords and decode them
class PasswordManagementScreen(tk.CTkFrame):
	def __init__(self, parent, controller, height, width, key):
		tk.CTkFrame.__init__(self, parent, height=height, width=width)
		self.instructions = False
		self.instructionsCreated = False
		self.key = key
		self.username = ""
		sliderValue = tk.IntVar()
		sliderValue.set(8)

		headerLabel = tk.CTkLabel(self, text="Manage Your Passwords", font=("Arial", 30, "bold"))
		headerLabel.place(relx=0.50, rely=0.10, anchor=tk.CENTER)

		lengthLabel = tk.CTkLabel(self, text="Length:")
		lengthLabel.place(relx=0.65, rely=0.32, anchor=tk.CENTER)

		sliderValLabel = tk.CTkLabel(self, textvariable=sliderValue)
		sliderValLabel.place(relx=0.70, rely=0.32, anchor=tk.CENTER)

		slider = tk.CTkSlider(self, from_=8, to=24, number_of_steps=16, variable=sliderValue)
		slider.place(relx=0.45, rely=0.32, anchor=tk.CENTER)		

		passwordField = tk.CTkEntry(self, placeholder_text="True password will appear here", width=450)
		passwordField.configure(state="readonly")
		passwordField.place(relx=0.95, rely=0.25, anchor=tk.E)

		encodeField = tk.CTkEntry(self, placeholder_text="Encoded password will appear here, store this somewhere safe", width=450)
		encodeField.configure(state="readonly")
		encodeField.place(relx=0.95, rely=0.40, anchor=tk.E)

		helpButton = tk.CTkButton(self, text="Help", font=("Arial", 16, "bold"), command=lambda: self.displayInstructions(controller))
		helpButton.place(relx=0.50, rely=0.80, anchor=tk.CENTER)

		generateButton = tk.CTkButton(self, text="Generate", font=("Arial", 16, "bold"), 
			command=lambda: self.passwordGenerator(int(slider.get()), passwordField, encodeField))
		generateButton.place(relx=0.05, rely=0.25, anchor=tk.W)

		decodeField = tk.CTkEntry(self, placeholder_text="Paste encoded password here to get true password back", width=450)
		decodeField.place(relx=0.95, rely=0.60, anchor=tk.E)

		decodePassButton = tk.CTkButton(self, text="Decode", font=("Arial", 16, "bold"), command=lambda: self.decodePassword(decodeField, self.key))
		decodePassButton.place(relx=0.05, rely=0.60, anchor=tk.W)

	# set the key
	def setKey(self, key):
		self.key = key

	# set the username
	def setUsername(self, username):
		self.username = username

	# display the instructions for the app
	def displayInstructions(self, controller):
		self.instructions = not(self.instructions)
		if (not(self.instructionsCreated)):
			controller.createFrame(InformationScreen, 0, 1, (0, 25), 25)
			self.instructionsCreated = True
		else:
			if (self.instructions):
				controller.showFrame(InformationScreen)
			else:
				controller.hideFrame(InformationScreen)

	# generate password and update the appropriate fiels with true password/encoded password
	def passwordGenerator(self, length, trueField, encodeField):
		# get random password of given length with letters, digits, and different symbols
		validSymbols = "&%@-()![]{}"
		characters = string.ascii_letters + string.digits + validSymbols
		password = ''.join(random.choice(characters) for i in range(length))

		trueField.configure(state="normal")
		trueField.delete(0, len(trueField.get()))
		trueField.insert(0, password)
		trueField.configure(state="readonly")

		encodeField.configure(state="normal")
		encodeField.delete(0, len(encodeField.get()))
		encodedPass = encryptMessage(trueField.get(), self.key.encode())
		encodeField.insert(0, encodedPass)
		encodeField.configure(state="readonly")

	# decode password in decode field
	def decodePassword(self, decodeField, key):
		if (len(decodeField.get()) > 0):
			try:
				decodedPassword = decryptMessage(decodeField.get().encode(), key.encode())
				decodeField.delete(0, len(decodeField.get()))
				decodeField.insert(0, decodedPassword)
			except:
				messagebox.showerror(title="Error", message="Cannot decode this password."
					" Check that you have entered the encoded password correctly. If you have encoded this password in a different account you"
					" must log into that account and decode it there.")


# the login frame
class LoginScreen(tk.CTkFrame):
	def __init__(self, parent, controller, height, width):
		tk.CTkFrame.__init__(self, parent, height=height, width=width)

		headerLabel = tk.CTkLabel(self, text="Login or Register", font=("Arial", 30, "bold"))
		headerLabel.place(relx=0.50, rely=0.20, anchor=tk.CENTER)

		userEntry = tk.CTkEntry(self, placeholder_text="Username", width=250)
		userEntry.place(relx=0.50, rely=0.40, anchor=tk.CENTER)

		passwordEntry = tk.CTkEntry(self, placeholder_text="Password", width=250, show="*")
		passwordEntry.place(relx=0.50, rely=0.55, anchor=tk.CENTER)

		loginButton = tk.CTkButton(self, text="Login", font=("Arial", 16, "bold"), width = 100, 
			command=lambda: self.loginSuccess(userEntry, passwordEntry, controller))
		loginButton.place(relx=0.33, rely=0.75, anchor=tk.CENTER)

		registerButton = tk.CTkButton(self, text="Register", font=("Arial", 16, "bold"), width = 100, 
			command=lambda: self.createUser(userEntry, passwordEntry))
		registerButton.place(relx=0.67, rely=0.75, anchor=tk.CENTER)

	# adds the user to the database if the user doesn't already exist
	def createUser(self, userEntry, passwordEntry):
		with sqlite3.connect("Database.db") as db:
			cursor = db.cursor()
		# adding a check flag to bypass adding user to database if username already exists or user/pass field empty
		check = False
		cursor.execute("SELECT * FROM user")
		results = cursor.fetchall()
		# if there is anything that exists within database
		if results:
			# searches database to see if username already exists
			for i in results:
				# if the username already exists user isn't able to register with that username
				if decryptMessage(i[1], DATABASE_KEY).lower() == userEntry.get().lower():
					messagebox.showerror(title="Error", message="Username already exists!")
					check = True
					userEntry.delete(0, len(userEntry.get()))
					break

				elif userEntry.get() == "" or passwordEntry.get() == "":
					messagebox.showerror(title="Error", message="Username or password empty!")
					check = True
					break

			if not check:
				self.insertData(userEntry, passwordEntry)

		else:
			if userEntry.get() == "" or passwordEntry.get() == "":
				messagebox.showerror(title="Error", message="Username or password empty!")

			else:
				self.insertData(userEntry, passwordEntry)

	# insert username and password into database
	def insertData(self, userEntry, passwordEntry):
		with sqlite3.connect("Database.db") as db:
			cursor = db.cursor()
		# insert registered username and password into database
		insert = ''' INSERT INTO user(username, password)
												VALUES(?, ?)'''
		cursor.execute(insert, [encryptMessage(userEntry.get(), DATABASE_KEY),
									 encryptMessage(passwordEntry.get(), DATABASE_KEY)])
		db.commit()
		messagebox.showinfo(title="Registered", message="Successfully registered.")

	# notify user login has failed
	def loginFailure(self, userEntry, passwordEntry):
		messagebox.showerror(title="Error", message="Username or password does not exist!")
		userEntry.delete(0, len(userEntry.get()))
		passwordEntry.delete(0, len(passwordEntry.get()))

	# check for successful login
	def loginSuccess(self, userEntry, passwordEntry, controller):
		with sqlite3.connect("Database.db") as db:
			cursor = db.cursor()
		cursor.execute("SELECT * FROM user")
		results = cursor.fetchall()
		# initializing count to handle error messages
		count = 0

		# loops through database table and checks if username and password exists
		if results:
			for i in results:
				# increase count every time loop repeats
				count += 1
				# if username and password is in database log user in and open main window
				if userEntry.get().lower() == decryptMessage(i[1], DATABASE_KEY).lower() and \
						passwordEntry.get() == decryptMessage(i[2], DATABASE_KEY):
					self.updateKey(userEntry.get())
					controller.setKeyForFrame(PasswordManagementScreen, self.getKey(userEntry.get()))
					controller.setUsernameForFrame(PasswordManagementScreen, userEntry.get())
					controller.destroyFrame(LoginScreen)
					controller.createFrame(PasswordManagementScreen, 0, 0, (25, 25), 25)
					break

				# if count is equal to length of table and login boxes empty, break out of loop
				elif count == len(results):
					if userEntry.get() == "" or passwordEntry.get() == "":
						messagebox.showerror(title="Error", message="Username or password empty!")
						break

					# else if count is equal to length of table and user trying to login,
					# username/password doesn't exist
					else:
						self.loginFailure(userEntry, passwordEntry)

		else:
			self.loginFailure(userEntry, passwordEntry)

	# update the key for the given username in database
	def updateKey(self, username):
		with sqlite3.connect("Database.db") as db:
			cursor = db.cursor()

		cursor.execute("SELECT key FROM user WHERE username = ?", (searchUser(username),))
		for row in cursor:
			for elem in row:
				if elem is None:
					newKey = Fernet.generate_key()
					cursor.execute("UPDATE user SET key = ? WHERE username = ?",
									(encryptMessage(str(newKey)[1:].replace("'", ""), DATABASE_KEY),
									 searchUser(username)))
					db.commit()
					break

	# get the key for the user with given username from database
	def getKey(self, username):
		with sqlite3.connect("Database.db") as db:
			cursor = db.cursor()

		cursor.execute("SELECT key FROM user WHERE username = ?", (searchUser(username),))
		for row in cursor:
			for elem in row:
				if elem is not None:
					return decryptMessage(elem, DATABASE_KEY)

if __name__== "__main__":
	app = Root()
	app.mainloop()
		