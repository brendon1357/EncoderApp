import string
import random
import customtkinter as tk
import socket
import ssl
import json
import sys
import threading
import os
import sys
from functools import partial
from staticlibrary import isJson, sendAndReceiveMsg, getInstanceLock
from concurrent.futures import ThreadPoolExecutor

"""
IMPORTANT NOTE: Rebuild GUI using grid when finished all functionality and polishing
"""

# the root window of the application
class Root(tk.CTk):
	def __init__(self, socket):
		tk.CTk.__init__(self)
		# dictionary to store all of the frames
		self.frames = {} 
		self.socket = socket

		container = tk.CTkFrame(self)
		self.title("Password Manager")
		self.resizable(False, False)
		container.pack()
		tk.set_appearance_mode("dark")
		tk.set_default_color_theme("blue")

		loginFrame = LoginScreen(container, self, 400, 600, self.socket)
		self.frames[LoginScreen] = loginFrame
		self.createFrame(LoginScreen, 0, 0, 100, 75)

		registrationFrame = RegistrationScreen(container, self, 400, 600, self.socket)
		self.frames[RegistrationScreen] = registrationFrame
		self.createFrame(RegistrationScreen, 0, 0, 100, 75)
		self.hideFrame(RegistrationScreen)

		passwordManagementFrame = PasswordManagementScreen(container, self, 500, 700, self.socket)
		self.frames[PasswordManagementScreen] = passwordManagementFrame
		self.createFrame(PasswordManagementScreen, 0, 0, (25, 25), 25)
		self.hideFrame(PasswordManagementScreen)

		passwordViewFrame = ViewPasswordsScreen(container, self, 500, 825, self.socket)
		self.frames[ViewPasswordsScreen] = passwordViewFrame
		self.createFrame(ViewPasswordsScreen, 0, 0, (25, 25), 25)
		self.hideFrame(ViewPasswordsScreen)

	# create a frame and add it to the grid at given row and col
	def createFrame(self, name, row, col, padx, pady) -> None:
		frame = self.frames[name]
		frame.grid(row=row, column=col, padx=padx, pady=pady)
		if name == LoginScreen:
			self.centerWindow()

	# add a frame to frames
	def addFrame(self, name, obj) -> None:
		self.frames[name] = obj

	# show the given frame
	def showFrame(self, name) -> None:
		frame = self.frames[name]
		frame.focus()
		frame.grid()

	# hide the given frame
	def hideFrame(self, name) -> None:
		frame = self.frames[name]
		frame.grid_remove()

	# destroy the given frame
	def destroyFrame(self, name) -> None:
		frame = self.frames[name]
		frame.destroy()

	# set the username for the given frame
	def setUsernameForFrame(self, name, username) -> None:
		self.frames[name].setUsername(username)

	# set the access token for frame
	def setTokenForFrame(self, name, token) -> None:
		self.frames[name].setToken(token)

	# call the displayPasswords method for the ViewPasswordsScreen class
	def setupPasswordDisplay(self, passwords) -> None:
		self.frames[ViewPasswordsScreen].displayPasswords(passwords)

	# place window at the center of the screen
	def centerWindow(self) -> None:
		self.update_idletasks()
		width = self.winfo_reqwidth()
		height = self.winfo_reqheight()
		x = (self.winfo_screenwidth() // 2) - (width // 2)
		y = (self.winfo_screenheight() // 2) - (height // 2)
		self.geometry('+{}+{}'.format(x, y))


# a popup window to ask user for confirmation when deleting a password
class ConfirmationWindow(tk.CTkToplevel):
	def __init__(self):
		tk.CTkToplevel.__init__(self)
		self.geometry("375x150")
		self.title("Confirm Delete")
		self.resizable(False, False)

		self.confirmed = False

		askConfirmationLabel =  tk.CTkLabel(self, text="Are you sure you want to delete this password?", font=("Arial", 14, "bold"))
		askConfirmationLabel.place(relx=0.50, rely=0.30, anchor=tk.CENTER)

		yesButton = tk.CTkButton(self, text="Yes", font=("Arial", 14, "bold"), cursor="hand2", width=150, command=lambda: self.yesClicked())
		yesButton.place(relx=0.04, rely=0.65, anchor=tk.W)

		noButton = tk.CTkButton(self, text="No", font=("Arial", 14, "bold"), cursor="hand2", width=150, command=lambda: self.noClicked())
		noButton.place(relx=0.96, rely=0.65, anchor=tk.E)

	def yesClicked(self) -> None:
		self.confirmed = True
		self.destroy()

	def noClicked(self) -> None:
		self.destroy()

	def isConfirmed(self) -> bool:
		return self.confirmed


# a popup input window to ask for a new password label
class InputWindow(tk.CTkToplevel):
	def __init__(self):
		tk.CTkToplevel.__init__(self)
		self.geometry("375x150")
		self.title("New Label")
		self.resizable(False, False)

		self.enteredLabel = ""

		headerLabel =  tk.CTkLabel(self, text="Enter a new label below or cancel", font=("Arial", 14, "bold"))
		headerLabel.place(relx=0.50, rely=0.20, anchor=tk.CENTER)

		self.entry = tk.CTkEntry(self, placeholder_text="Enter new label here", width=350, font=("Arial", 14))
		self.entry.place(relx=0.50, rely=0.45, anchor=tk.CENTER)

		okButton = tk.CTkButton(self, text="Ok", font=("Arial", 14, "bold"), cursor="hand2", width=150, command=lambda: self.okClicked())
		okButton.place(relx=0.03, rely=0.75, anchor=tk.W)

		cancelButton = tk.CTkButton(self, text="Cancel", font=("Arial", 14, "bold"), cursor="hand2", width=150, command=lambda: self.cancelClicked())
		cancelButton.place(relx=0.97, rely=0.75, anchor=tk.E)

	def okClicked(self) -> None:
		self.enteredLabel = self.entry.get()
		self.destroy()

	def cancelClicked(self) -> None:
		self.destroy()

	def getInput(self) -> str:
		if len(self.enteredLabel) > 0:
			return self.enteredLabel
		return ""


# the frame to view all of the users saved passwords
class ViewPasswordsScreen(tk.CTkScrollableFrame):
	def __init__(self, parent, controller, height, width, socket):
		tk.CTkScrollableFrame.__init__(self, parent, height=height, width=width, fg_color="#333333")
		self.token = None
		self.socket = socket
		self.username = ""
		self.controller = controller
		self.passwords = []

		self.informationLabel = tk.CTkLabel(self, text="", font=("Arial", 14, "bold"))
		self.informationLabel.grid(row=0, column=0, padx=(150, 0))

		backButton = tk.CTkButton(self, text="Back", font=("Arial", 16, "bold"), width=95, fg_color="#15a100", hover_color="#107d00", 
			command=lambda: self.goBack())
		backButton.grid(row=0, column=0, pady=(5, 20), padx=(5, 0), sticky="w")

	# display all of the users saved passwords
	def displayPasswords(self, passwords):
		for i, password in enumerate(passwords, start=1):
			encryptedPassword = password["encryptedPassword"]
			label = password["label"]

			listLabel = tk.CTkLabel(self, text=label, font=("Arial", 14, "bold"), cursor="hand2")
			deleteLabel = tk.CTkLabel(self, text="Delete", font=("Arial", 14, "bold"), cursor="hand2", text_color="red")
			if i == 1:
				listLabel.grid(row=i, column=0, pady=(0, 0), sticky="w")
				deleteLabel.grid(row=i, column=0, pady=(0, 0), sticky="e")
			else:
				listLabel.grid(row=i, column=0, pady=(40, 0), sticky="w")
				deleteLabel.grid(row=i, column=0, pady=(40, 0), sticky="e")
  
			listPassword = tk.CTkEntry(self, width=500)
			listPassword.insert(tk.END, encryptedPassword)
			listPassword.configure(state="readonly")
			listPassword.grid(row=i+1, column=0, pady=(0, 40))

			decryptButton = tk.CTkButton(self, text="Decrypt", font=("Arial", 16, "bold"), height=32, 
			command=partial(self.startDecryptThread, listPassword))
			decryptButton.grid(row=i+1, column=1, pady=(0, 40), padx=20)

			copyButton = tk.CTkButton(self, text="Copy", font=("Arial", 16, "bold"), height=32, 
			command=partial(self.copyPassword, listPassword))
			copyButton.grid(row=i+1, column=2, pady=(0, 40), padx=(0, 20))

			listLabel.bind("<Button-1>", command=partial(self.modifyLabel, listLabel))
			deleteLabel.bind("<Button-1>", command=partial(self.deletePassword, listPassword))

	# prompt the user to input a new label and start a new thread to send that new label in a request to the server
	def modifyLabel(self, label, event) -> None:
		inputWindow = InputWindow()
		inputWindow.transient(self)
		inputWindow.grab_set()
		inputWindow.update_idletasks()
		# place at center of screen
		inputWindowWidth = inputWindow.winfo_width()
		inputWindowHeight = inputWindow.winfo_height()
		rootCenterX = self.controller.winfo_x() + self.controller.winfo_width() // 2
		rootCenterY = self.controller.winfo_y() + self.controller.winfo_height() // 2
		inputWindow.geometry('+{}+{}'.format(rootCenterX - inputWindowWidth // 2, rootCenterY - inputWindowHeight // 2))
		self.wait_window(inputWindow)

		enteredInput = inputWindow.getInput()
		# if the user clicks cancel or dialog input is somehow empty then don't send any requests
		if enteredInput == "":
			return
		threading.Thread(target=self.sendModifyRequestToServer, args=(label, enteredInput)).start()

	# send a request to modify/update a label for a saved password
	def sendModifyRequestToServer(self, label, enteredInput) -> None:
		self.informationLabel.configure(text="Loading...")
		self.informationLabel.configure(text_color="green")
		data = {"type": "Modify label", "token": self.token, "username": self.username, "newLabel": enteredInput, "oldLabel": label.cget("text")}
		msg = sendAndReceiveMsg(self.socket, data, 1024)
		if msg == "Label updated":
			self.informationLabel.configure(text="Updated successfully")
			self.informationLabel.configure(text_color="green")
			label.configure(text=enteredInput)
		else:
			self.informationLabel.configure(text=msg)
			self.informationLabel.configure(text_color="#ff4242")

	# prompt the user to confirm deletion of password and send request in a new thread
	def deletePassword(self, passwordEntry, event) -> None: 
		if len(passwordEntry.get()) <= 32:
			self.informationLabel.configure(text="Can only delete password before decryption")
			self.informationLabel.configure(text_color="#ff4242")
			return
		confirmationWindow = ConfirmationWindow()
		confirmationWindow.transient(self)
		confirmationWindow.grab_set()
		confirmationWindow.update_idletasks()
		confirmationWindowWidth = confirmationWindow.winfo_width()
		confirmationWindowHeight = confirmationWindow.winfo_height()
		rootCenterX = self.controller.winfo_x() + self.controller.winfo_width() // 2
		rootCenterY = self.controller.winfo_y() + self.controller.winfo_height() // 2
		confirmationWindow.geometry('+{}+{}'.format(rootCenterX - confirmationWindowWidth // 2, rootCenterY - confirmationWindowHeight // 2))
		self.wait_window(confirmationWindow)
		if confirmationWindow.isConfirmed():
			#threading.Thread(target=self.sendDeleteRequestToServer, args=(passwordEntry,)).start()
			self.sendDeleteRequestToServer(passwordEntry)

	# send a request to delete the requested saved password
	def sendDeleteRequestToServer(self, passwordEntry) -> None:
		self.informationLabel.configure(text="Loading...")
		self.informationLabel.configure(text_color="green")
		data = {"type": "Delete password", "token": self.token, "username": self.username, "password": passwordEntry.get()}
		# run this in a separate thread so I can update the GUI in main thread based on result
		with ThreadPoolExecutor(max_workers=1) as executor:
			future = executor.submit(sendAndReceiveMsg, self.socket, data, 4096)
		msg = future.result()
		self.refreshPasswordList(msg)

	# refresh the password list by updating all of the widgets
	def refreshPasswordList(self, msg) -> None:
		if isJson(msg):
			jsonData = json.loads(msg)
			if jsonData["msg"] == "Password deleted successfully":
				self.informationLabel.configure(text="")
				if len(jsonData["passwords"]) > 0:
					self.informationLabel.configure(text=jsonData["msg"])
					self.informationLabel.configure(text_color="green")
				for widget in self.winfo_children():
					if isinstance(widget, tk.CTkLabel):
						if widget.cget("text_color") == "green" or widget.cget("text_color") == "#ff4242":
							continue
					if isinstance(widget, tk.CTkButton):
						if widget.cget("text") == "Back":
							continue
					widget.destroy()
				self.displayPasswords(jsonData["passwords"])
			else:
				self.informationLabel.configure(text=jsonData["msg"])
				self.informationLabel.configure(text_color="#ff4242")
		else:
			self.informationLabel.configure(text=msg)
			self.informationLabel.configure(text_color="#ff4242")

	# send a request to decrypt given password
	def decryptPassword(self, passwordEntry) -> None:
		self.informationLabel.configure(text="Loading...")
		self.informationLabel.configure(text_color="green")
		data = {"type": "Decrypt password", "token": self.token, "username": self.username, "password": passwordEntry.get()}
		msg = sendAndReceiveMsg(self.socket, data, 1024)
		if msg == "Already decrypted":
			self.informationLabel.configure(text="Password already decrypted, you can copy it")
			self.informationLabel.configure(text_color="#ff4242")
			return
		elif msg == "Too many requests too quickly":
			self.informationLabel.configure(text=msg)
			self.informationLabel.configure(text_color="#ff4242")
			return

		if isJson(msg):
			jsonData = json.loads(msg)
			if jsonData["msg"] == "Password decrypted":
				passwordEntry.configure(state="normal")
				passwordEntry.delete(0, len(passwordEntry.get()))
				passwordEntry.insert(0, jsonData["password"])
				passwordEntry.configure(state="readonly")
				self.informationLabel.configure(text="")
			else:
				self.informationLabel.configure(text=msg)
				self.informationLabel.configure(text_color="#ff4242")
		else:
			self.informationLabel.configure(text=msg)
			self.informationLabel.configure(text_color="#ff4242")

	# method to start decrypting password in a separate thread
	def startDecryptThread(self, listPassword) -> None:
		threading.Thread(target=self.decryptPassword, args=(listPassword,)).start()

	# copy password to clipboard
	def copyPassword(self, passwordEntry) -> None:
		self.clipboard_clear()
		self.clipboard_append(passwordEntry.get())
		self.informationLabel.configure(text="Password copied, you can now paste anywhere")
		self.informationLabel.configure(text_color="green")

	# set the username
	def setUsername(self, username) -> None:
		self.username = username

	# set the token
	def setToken(self, token) -> None:
		self.token = token

	# set the passwords
	def setPasswords(self, passwords) -> None:
		self.passwords = passwords

	# go back to the password management screen
	def goBack(self) -> None:
		self.informationLabel.configure(text="")
		self.controller.hideFrame(ViewPasswordsScreen)
		self.controller.showFrame(PasswordManagementScreen)


# the frame for registering an account
class RegistrationScreen(tk.CTkFrame):
	def __init__(self, parent, controller, height, width, socket):
		tk.CTkFrame.__init__(self, parent, height=height, width=width, fg_color="#333333")
		self.socket = socket
		self.controller = controller

		headerLabel = tk.CTkLabel(self, text="Create Account Below", font=("Arial", 32, "bold"))
		headerLabel.grid(row=0, column=0, padx=(100, 100), pady=(40, 0))

		usernameLabel = tk.CTkLabel(self, text="Username", font=("Arial", 16, "bold"))
		usernameLabel.grid(row=1, column=0, padx=(100, 0), pady=(40, 0), sticky="W")

		passwordLabel = tk.CTkLabel(self, text="Password", font=("Arial", 16, "bold"))
		passwordLabel.grid(row=3, column=0, padx=(100, 0), pady=(15, 0), sticky="W")

		retypePasswordLabel = tk.CTkLabel(self, text="Retype Password", font=("Arial", 16, "bold"))
		retypePasswordLabel.grid(row=5, column=0, padx=(100, 0), pady=(15, 0), sticky="W")

		self.informationLabel = tk.CTkLabel(self, text="", font=("Arial", 14, "bold"))
		self.informationLabel.grid(row=7, column=0, pady=(10, 0))

		self.userEntry = tk.CTkEntry(self, placeholder_text="Enter username here", width=350, font=("Arial", 14))
		self.userEntry.grid(row=2, column=0)

		self.passwordEntry = tk.CTkEntry(self, placeholder_text="Enter password here", width=350, font=("Arial", 14), show="*")
		self.passwordEntry.grid(row=4, column=0)

		self.retypePasswordEntry = tk.CTkEntry(self, placeholder_text="Retype password here", width=350, font=("Arial", 14), show="*")
		self.retypePasswordEntry.grid(row=6, column=0)

		registerButton = tk.CTkButton(self, text="Register", font=("Arial", 20, "bold"), width=350, height=32, 
			command=lambda: threading.Thread(target=self.createUser).start())
		registerButton.grid(row=8, column=0, pady=(10, 0))

		loginLabel = tk.CTkLabel(self, text="Click here to login", font=("Arial", 16, "bold"), cursor="hand2", text_color="#4aa8ff")
		loginLabel.grid(row=9, column=0, pady=(20, 30))

		loginLabel.bind("<Button-1>", lambda event: self.loginScreen())

		self.userEntry.bind("<Return>", lambda event: threading.Thread(target=self.createUser).start())
		self.passwordEntry.bind("<Return>", lambda event: threading.Thread(target=self.createUser).start())

	# show the login screen
	def loginScreen(self) -> None:
		self.controller.hideFrame(RegistrationScreen)
		self.controller.showFrame(LoginScreen)
		self.informationLabel.configure(text="")
		self.userEntry.delete(0, len(self.userEntry.get()))
		self.passwordEntry.delete(0, len(self.passwordEntry.get()))

	# send a request to the server to add the user to the database
	def createUser(self) -> None:
		self.informationLabel.configure(text="Loading...")
		self.informationLabel.configure(text_color="green")
		data = {"type": "Register", "username": self.userEntry.get(), "password": self.passwordEntry.get()}
		msg = sendAndReceiveMsg(self.socket, data, 1024)
		if msg == "Successfully registered":
			self.informationLabel.configure(text=msg)
			self.informationLabel.configure(text_color="green")
		else:
			self.informationLabel.configure(text=msg)
			self.informationLabel.configure(text_color="#ff4242")


# main frame after logging in, where the user can generate passwords and decrypt them
class PasswordManagementScreen(tk.CTkFrame):
	def __init__(self, parent, controller, height, width, socket):
		tk.CTkFrame.__init__(self, parent, height=height, width=width, fg_color="#333333")
		self.token = None
		self.username = ""
		self.passwords = []
		self.socket = socket
		self.controller = controller
		sliderValue = tk.IntVar()
		sliderValue.set(8) 

		logoutButton = tk.CTkButton(self, text="Logout", font=("Arial", 16, "bold"), width=95, fg_color="#ff392b", hover_color="#960a00", cursor="hand2", 
			command=lambda: self.logout())
		logoutButton.grid(row=0, column=0, padx=(10, 0), pady=(10, 0), sticky="W")

		headerLabel = tk.CTkLabel(self, text="Manage Your Passwords", font=("Arial", 30, "bold"))
		headerLabel.grid(row=1, column=0,pady=(10, 40))

		generatePasswordGrid = tk.CTkFrame(self, fg_color="#333333", width=0, height=0)
		generatePasswordGrid.grid(row=2, column=0) 

		passwordInfoLabel = tk.CTkLabel(generatePasswordGrid, text="Generate or enter a password", font=("Arial", 14, "bold"))
		passwordInfoLabel.grid(row=0, column=1, padx=(3, 0), sticky="W")

		lengthLabel = tk.CTkLabel(generatePasswordGrid, text="Length: ", font=("Arial", 14, "bold"))
		lengthLabel.grid(row=2, column=1, padx=(10, 0), pady=(10, 0))

		sliderValLabel = tk.CTkLabel(generatePasswordGrid, textvariable=sliderValue, font=("Arial", 14, "bold"))
		sliderValLabel.grid(row=2, column=1, padx=(80, 0), pady=(10, 0))

		self.informationLabel = tk.CTkLabel(self, text="", font=("Arial", 14, "bold"))
		self.informationLabel.grid(row=4, column=0, pady=(25, 0))

		self.slider = tk.CTkSlider(generatePasswordGrid, from_=8, to=32, number_of_steps=24, variable=sliderValue)
		self.slider.grid(row=2, column=1, sticky="W", pady=(10, 0))

		generateButton = tk.CTkButton(generatePasswordGrid, text="Generate", font=("Arial", 16, "bold"), width=160, height=32, 
			command=lambda: self.passwordGenerator())
		generateButton.grid(row=1, column=0, padx=25)

		self.passwordField = tk.CTkEntry(generatePasswordGrid, placeholder_text="Generate or enter a password here", width=450, height=32, fg_color="#363636")
		self.passwordField.grid(row=1, column=1, padx=(0, 25), sticky="W")

		savePasswordGrid = tk.CTkFrame(self, fg_color="#333333", width=0, height=0)
		savePasswordGrid.grid(row=3, column=0) 

		generatedPasswordLabel = tk.CTkLabel(savePasswordGrid, text="Whats this password for?", font=("Arial", 14, "bold"))
		generatedPasswordLabel.grid(row=0, column=1, padx=(3, 0), pady=(50, 0), sticky="W")

		self.generatedPasswordLabelEntry = tk.CTkEntry(savePasswordGrid, placeholder_text="Enter a label for this password", width=450, height=32, fg_color="#363636")
		self.generatedPasswordLabelEntry.grid(row=1, column=1, padx=(0, 25), sticky="W")

		savePasswordButton = tk.CTkButton(savePasswordGrid, text="Save Password", font=("Arial", 16, "bold"), width=160, height=32, 
			command=lambda: threading.Thread(target=self.savePassword).start())
		savePasswordButton.grid(row=1, column=0, padx=25)

		viewButton = tk.CTkButton(self, text="Access Your Data", font=("Arial", 16, "bold"), width=180, height=32,
			command=lambda: threading.Thread(target=self.viewPasswords).start())
		viewButton.grid(row=5, column=0, pady=(20, 40))

	# send a request to retrieve the users passwords so they can be viewed
	def viewPasswords(self) -> None:
		self.informationLabel.configure(text="Loading...")
		self.informationLabel.configure(text_color="green")
		data = {"type": "Get passwords", "token": self.token, "username": self.username}
		msg = sendAndReceiveMsg(self.socket, data, 4096)
		if isJson(msg):
			passwords = json.loads(msg)
			self.passwords = passwords
			# hide this frame and setup password view frame
			self.controller.hideFrame(PasswordManagementScreen)
			self.controller.setupPasswordDisplay(passwords)
			self.controller.showFrame(ViewPasswordsScreen)
			self.informationLabel.configure(text="")
		else:
			self.informationLabel.configure(text=msg)
			self.informationLabel.configure(text_color="#ff4242")
			
	# logout (restart the program)
	def logout(self) -> None:
		os.execv(sys.executable, ['python'] + sys.argv)

	# set the username
	def setUsername(self, username) -> None:
		self.username = username

	# set the token
	def setToken(self, token) -> None:
		self.token = token

	# generate password and update the appropriate fiels with true password/encoded password
	def passwordGenerator(self) -> None:
		length = int(self.slider.get())
		# get random password of given length with letters, digits, and different symbols
		validSymbols = "@-!$#&~_?%()^<>"
		upperLetters = string.ascii_uppercase
		digits = string.digits
		characters = string.ascii_letters + digits + validSymbols

		# select at least 1 uppercase letter, 1 symbol, and 1 digit
		password = [random.choice(upperLetters), random.choice(validSymbols), random.choice(digits)]

		for i in range(length - 3):
			password.append(random.choice(characters))

		# shuffle the characters to make it more secure
		random.shuffle(password)
		password_str = ''.join(password)

		# update the password field with the new password
		self.passwordField.delete(0, len(self.passwordField.get()))
		self.passwordField.insert(0, password_str)

	# send a request to the server to save the password
	def savePassword(self) -> None:
		self.informationLabel.configure(text="Loading...")
		self.informationLabel.configure(text_color="green")
		data = {
				"type": "Save password",
				"token": self.token, 
				"password": self.passwordField.get(), 
				"username": self.username, 
				"label": self.generatedPasswordLabelEntry.get()
		}
		msg = sendAndReceiveMsg(self.socket, data, 1024)
		if msg == "Password saved":
			self.informationLabel.configure(text=msg)
			self.informationLabel.configure(text_color="green")
		else:
			self.informationLabel.configure(text=msg)
			self.informationLabel.configure(text_color="#ff4242")

 
# the login frame
class LoginScreen(tk.CTkFrame):
	def __init__(self, parent, controller, height, width, socket):
		tk.CTkFrame.__init__(self, parent, height=height, width=width, fg_color="#333333")
		self.socket = socket
		self.controller = controller

		headerLabel = tk.CTkLabel(self, text="Login to Your Account", font=("Arial", 32, "bold"))
		headerLabel.grid(row=0, column=0, padx=(100, 100), pady=(40, 0))

		usernameLabel = tk.CTkLabel(self, text="Username", font=("Arial", 16, "bold"))
		usernameLabel.grid(row=1, column=0, padx=(100, 0), pady=(40, 0), sticky="W")

		passwordLabel = tk.CTkLabel(self, text="Password", font=("Arial", 16, "bold"))
		passwordLabel.grid(row=3, column=0, padx=(100, 0), pady=(15, 0), sticky="W")

		self.userEntry = tk.CTkEntry(self, placeholder_text="Enter username here", width=350, font=("Arial", 14))
		self.userEntry.grid(row=2, column=0)

		self.passwordEntry = tk.CTkEntry(self, placeholder_text="Enter password here", width=350, font=("Arial", 14), show="*")
		self.passwordEntry.grid(row=4, column=0)

		loginButton = tk.CTkButton(self, text="Login", font=("Arial", 20, "bold"), width=350, height=32, 
			command=lambda: threading.Thread(target=self.loginSuccess).start())
		loginButton.grid(row=6, column=0, pady=(10, 0))
 
		self.registerLabel = tk.CTkLabel(self, text="Click here to register", font=("Arial", 16, "bold"), cursor="hand2", text_color="#4aa8ff")
		self.registerLabel.grid(row=7, column=0, pady=(20, 30))

		self.informationLabel = tk.CTkLabel(self, text="", font=("Arial", 14, "bold"))
		self.informationLabel.grid(row=5, column=0, pady=(10, 0))

		self.registerLabel.bind("<Button-1>", lambda event: self.registrationScreen())
		
		self.userEntry.bind("<Return>", lambda event: threading.Thread(target=self.loginSuccess).start())
		self.passwordEntry.bind("<Return>", lambda event: threading.Thread(target=self.loginSuccess).start())

	# show the registration screen
	def registrationScreen(self) -> None:
		self.controller.hideFrame(LoginScreen)
		self.controller.showFrame(RegistrationScreen)
		self.informationLabel.configure(text="")
		self.userEntry.delete(0, len(self.userEntry.get()))
		self.passwordEntry.delete(0, len(self.passwordEntry.get()))
		
	# send a request to the server to login the user
	def loginSuccess(self) -> None:
		self.informationLabel.configure(text_color="green")
		self.informationLabel.configure(text="Loading...")
		data = {"type": "Login", "username": self.userEntry.get(), "password": self.passwordEntry.get()}
		msg = sendAndReceiveMsg(self.socket, data, 1024)
		if "Login successful" in msg:
			login, token = msg.split(":")
			self.informationLabel.configure(text="")
			self.controller.setTokenForFrame(PasswordManagementScreen, token)
			self.controller.setUsernameForFrame(PasswordManagementScreen, self.userEntry.get())
			self.controller.setTokenForFrame(ViewPasswordsScreen, token)
			self.controller.setUsernameForFrame(ViewPasswordsScreen, self.userEntry.get())
			self.controller.hideFrame(LoginScreen)
			self.controller.createFrame(PasswordManagementScreen, 0, 0, (25, 25), 25)
			self.userEntry.delete(0, len(self.userEntry.get()))
			self.passwordEntry.delete(0, len(self.passwordEntry.get()))
		else:
			self.informationLabel.configure(text_color="#ff4242")
			self.informationLabel.configure(text=msg)


# start the client instance
if __name__== "__main__":
	# acquire lock to check if we have a client instance already running
	lock = getInstanceLock()
	if lock is not None:
		sslSock = None
		try:
			s = socket.socket()
			s.settimeout(15)
			# bind to ip and port
			s.connect(('127.0.0.1', 33333))

			sslContext = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="../resources/trust_store/server_cert.pem")
			sslSock = sslContext.wrap_socket(s, server_hostname="PWManage")
		except Exception as e:
			print(e)
		app = Root(sslSock)
		app.mainloop()

		# release lock when program ends
		lock.release()
	else:
		sys.exit()
