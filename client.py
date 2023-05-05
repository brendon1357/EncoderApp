import string
import random
import customtkinter as tk
import socket
import ssl
import json
from tkinter import messagebox
from functools import partial

# the root window of the application
class Root(tk.CTk):
    def __init__(self, socket):
        tk.CTk.__init__(self)
        # dictionary to store all of the frammes
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
        self.createFrame(LoginScreen, 0, 0, 50, 50)

        registrationFrame = RegistrationScreen(container, self, 400, 600, self.socket)
        self.frames[RegistrationScreen] = registrationFrame
        self.createFrame(RegistrationScreen, 0, 0, 50, 50)
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
    def createFrame(self, name, row, col, padx, pady):
        frame = self.frames[name]
        frame.grid(row=row, column=col, padx=padx, pady=pady)
        if name == LoginScreen:
            self.centerWindow()

    # show the given frame
    def showFrame(self, name):
        frame = self.frames[name]
        frame.focus()
        frame.grid()

    # hide the given frame
    def hideFrame(self, name):
        frame = self.frames[name]
        frame.grid_remove()

    # destroy the given frame
    def destroyFrame(self, name):
        frame = self.frames[name]
        frame.destroy()

    # set the username for the given frame
    def setUsernameForFrame(self, name, username):
        self.frames[name].setUsername(username)

    # call the displayPasswords method for the ViewPasswordsScreen class
    def setupPasswordDisplay(self, passwords):
        self.frames[ViewPasswordsScreen].displayPasswords(passwords)

    # place window at the center of the screen
    def centerWindow(self):
        self.update_idletasks()
        width = self.winfo_reqwidth()
        height = self.winfo_reqheight()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry('+{}+{}'.format(x, y))


# the frame to view all of the users saved passwords
class ViewPasswordsScreen(tk.CTkScrollableFrame):
    def __init__(self, parent, controller, height, width, socket):
        tk.CTkScrollableFrame.__init__(self, parent, height=height, width=width)
        self.socket = socket
        self.username = ""
        self.controller = controller

        self.successLabel = tk.CTkLabel(self, text="", font=("Arial", 14, "bold"), text_color="green")
        self.successLabel.grid(row=0, column=0, sticky="e")

        self.errorLabel = tk.CTkLabel(self, text="", font=("Arial", 14, "bold"), text_color="#ff4242")
        self.errorLabel.grid(row=0, column=0, sticky="e")

        backButton = tk.CTkButton(self, text="Go Back", font=("Arial", 16, "bold"), height=32, 
            command=lambda: self.goBack())
        backButton.grid(row=0, column=0, pady=(0, 20), sticky="w")

    # display all of the users saved passwords
    def displayPasswords(self, passwords):
        for i, password in enumerate(passwords, start=1):
            encryptedPassword = password["encryptedPassword"]
            label = password["label"]

            listLabel = tk.CTkLabel(self, text=label, font=("Arial", 14, "bold"), cursor="hand2")
            if i == 1:
                listLabel.grid(row=i, column=0, pady=(0, 0), sticky="w")
            else:
                listLabel.grid(row=i, column=0, pady=(40, 0), sticky="w")
  
            listPassword = tk.CTkEntry(self, width=500)
            listPassword.insert(tk.END, encryptedPassword)
            listPassword.configure(state="readonly")
            listPassword.grid(row=i+1, column=0, pady=(0, 40))

            decryptButton = tk.CTkButton(self, text="Decrypt", font=("Arial", 16, "bold"), height=32, 
            command=partial(self.decryptPassword, listPassword))
            decryptButton.grid(row=i+1, column=1, pady=(0, 40), padx=20)

            copyButton = tk.CTkButton(self, text="Copy", font=("Arial", 16, "bold"), height=32, 
            command=partial(self.copyPassword, listPassword))
            copyButton.grid(row=i+1, column=2, pady=(0, 40), padx=(0, 20))

            listLabel.bind("<Button-1>", command=partial(self.modifyLabel, listLabel))

    # send a request to modify/update a label for a saved password
    def modifyLabel(self, label, event):
        dialog = tk.CTkInputDialog(text="Enter a new label name below", title="Modify Label")
        # place at center of screen
        width = dialog.winfo_reqwidth()
        height = dialog.winfo_reqheight()
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry('+{}+{}'.format( x, y))

        dialogInput = dialog.get_input()
        # if the user clicks cancel or dialog input is somehow empty then don't send any requests
        if dialogInput == None or dialogInput == "":
            return
        
        try:
            data = {"type": "Modify label", "username": self.username, "newLabel": dialogInput, "oldLabel": label.cget("text")}
            jsonData = json.dumps(data)
            self.socket.sendall(jsonData.encode())
            msg = self.socket.recv(2048).decode()
            if msg == "Label updated":
                self.errorLabel.configure(text="")
                label.configure(text=dialogInput)
                self.successLabel.configure(text="Updated successfully")
            else:
                self.errorLabel.configure(text=msg)
        except Exception as e:
            print(e)

    # send a request to decrypt given password
    def decryptPassword(self, passwordEntry):
        try:
            data = {"type": "Decrypt password", "username": self.username, "password": passwordEntry.get()}
            jsonData = json.dumps(data)
            self.socket.sendall(jsonData.encode())
            msg = self.socket.recv(2048).decode()
            if msg == "Already decrypted":
                return

            jsonData = json.loads(msg)
            if jsonData["msg"] == "Password decrypted":
                passwordEntry.configure(state="normal")
                passwordEntry.delete(0, len(passwordEntry.get()))
                passwordEntry.insert(0, jsonData["password"])
                passwordEntry.configure(state="readonly")
            else:
                messagebox.showerror(title="Error", message=msg)

        except Exception as e:
            print(e)

    # copy password to clipboard
    def copyPassword(self, passwordEntry):
        self.clipboard_clear()
        self.clipboard_append(passwordEntry.get())
        self.successLabel.configure(text="Password copied to clipboard")

    # set the username
    def setUsername(self, username):
        self.username = username

    # go back to the password management screen
    def goBack(self):
        self.successLabel.configure(text="")
        self.controller.hideFrame(ViewPasswordsScreen)
        self.controller.showFrame(PasswordManagementScreen)


# the frame for registering an account
class RegistrationScreen(tk.CTkFrame):
    def __init__(self, parent, controller, height, width, socket):
        tk.CTkFrame.__init__(self, parent, height=height, width=width)
        self.socket = socket
        self.controller = controller

        headerLabel = tk.CTkLabel(self, text="Create an Account Below", font=("Arial", 32, "bold"))
        headerLabel.place(relx=0.50, rely=0.15, anchor=tk.CENTER)

        usernameLabel = tk.CTkLabel(self, text="Username", font=("Arial", 16, "bold"))
        usernameLabel.place(relx=0.28, rely=0.33, anchor=tk.CENTER)

        passwordLabel = tk.CTkLabel(self, text="Password", font=("Arial", 16, "bold"))
        passwordLabel.place(relx=0.28, rely=0.50, anchor=tk.CENTER)

        self.errorLabel = tk.CTkLabel(self, text="", font=("Arial", 14, "bold"), text_color="#ff4242")
        self.errorLabel.place(relx=0.50, rely=0.66, anchor=tk.CENTER)

        self.successLabel = tk.CTkLabel(self, text="", font=("Arial", 14, "bold"), text_color="green")
        self.successLabel.place(relx=0.50, rely=0.66, anchor=tk.CENTER)

        self.userEntry = tk.CTkEntry(self, placeholder_text="Enter username here", width=350, font=("Arial", 14))
        self.userEntry.place(relx=0.50, rely=0.40, anchor=tk.CENTER)

        self.passwordEntry = tk.CTkEntry(self, placeholder_text="Enter password here", width=350, font=("Arial", 14), show="*")
        self.passwordEntry.place(relx=0.50, rely=0.57, anchor=tk.CENTER)

        registerButton = tk.CTkButton(self, text="Register", font=("Arial", 20, "bold"), width=350, height=32, 
            command=lambda: self.createUser())
        registerButton.place(relx=0.50, rely=0.75, anchor=tk.CENTER)

        loginLabel = tk.CTkLabel(self, text="Click here to login", font=("Arial", 16, "bold"), cursor="hand2", text_color="#4aa8ff")
        loginLabel.place(relx=0.50, rely=0.88, anchor=tk.CENTER)

        loginLabel.bind("<Button-1>", lambda event: self.loginScreen())

        self.userEntry.bind("<Return>", lambda event: self.createUser())
        self.passwordEntry.bind("<Return>", lambda event: self.createUser())

    # show the login screen
    def loginScreen(self):
        self.controller.hideFrame(RegistrationScreen)
        self.controller.showFrame(LoginScreen)
        self.errorLabel.configure(text="")
        self.successLabel.configure(text="")
        self.userEntry.delete(0, len(self.userEntry.get()))
        self.passwordEntry.delete(0, len(self.passwordEntry.get()))

    # send a request to the server to add the user to the database
    def createUser(self):
        if self.socket == None:
            self.errorLabel.configure(text="Not connected to server")
            return
        try:
            data = {"type": "Register", "username": self.userEntry.get(), "password": self.passwordEntry.get()}
            jsonData = json.dumps(data)
            self.socket.sendall(jsonData.encode())
            msg = self.socket.recv(2048).decode()
            if "Successfully registered" in msg:
                self.errorLabel.configure(text="")
                self.successLabel.configure(text=msg)
            else:
                self.errorLabel.configure(text=msg)
                self.successLabel.configure(text="")
        except Exception as e:
            print(e)
            self.successLabel.configure(text="")
            self.errorLabel.configure(text="Error connecting to server")


# main frame after logging in, where the user can generate passwords and decrypt them
class PasswordManagementScreen(tk.CTkFrame):
    def __init__(self, parent, controller, height, width, socket):
        tk.CTkFrame.__init__(self, parent, height=height, width=width)
        self.username = ""
        self.passwords = []
        self.socket = socket
        self.controller = controller
        sliderValue = tk.IntVar()
        sliderValue.set(8)

        headerLabel = tk.CTkLabel(self, text="Manage Your Passwords", font=("Arial", 30, "bold"))
        headerLabel.place(relx=0.50, rely=0.10, anchor=tk.CENTER)

        lengthLabel = tk.CTkLabel(self, text="Length: ", font=("Arial", 14, "bold"))
        lengthLabel.place(relx=0.65, rely=0.32, anchor=tk.CENTER)

        sliderValLabel = tk.CTkLabel(self, textvariable=sliderValue, font=("Arial", 14, "bold"))
        sliderValLabel.place(relx=0.70, rely=0.32, anchor=tk.CENTER)

        self.errorLabel = tk.CTkLabel(self, text="", font=("Arial", 14, "bold"), text_color="#ff4242")
        self.errorLabel.place(relx=0.50, rely=0.85, anchor=tk.CENTER)

        self.successLabel = tk.CTkLabel(self, text="", font=("Arial", 14, "bold"), text_color="green")
        self.successLabel.place(relx=0.50, rely=0.85, anchor=tk.CENTER)

        self.slider = tk.CTkSlider(self, from_=8, to=24, number_of_steps=16, variable=sliderValue)
        self.slider.place(relx=0.45, rely=0.32, anchor=tk.CENTER)        

        self.passwordField = tk.CTkEntry(self, placeholder_text="True password will appear here", width=450)
        self.passwordField.configure(state="readonly")
        self.passwordField.place(relx=0.95, rely=0.25, anchor=tk.E)

        generateButton = tk.CTkButton(self, text="Generate", font=("Arial", 16, "bold"), height=32, 
            command=lambda: self.passwordGenerator())
        generateButton.place(relx=0.05, rely=0.25, anchor=tk.W)

        generatedPasswordLabel = tk.CTkLabel(self, text="What's this password for?", font=("Arial", 14, "bold"))
        generatedPasswordLabel.place(relx=0.57, rely=0.45, anchor=tk.E)

        self.generatedPasswordLabelEntry = tk.CTkEntry(self, placeholder_text="Enter a label for this password", width=450)
        self.generatedPasswordLabelEntry.place(relx=0.95, rely=0.51, anchor=tk.E)

        saveButton = tk.CTkButton(self, text="Save Password", font=("Arial", 16, "bold"), width=160, height=32, 
            command=lambda: self.savePassword())
        saveButton.place(relx=0.35, rely=0.75, anchor=tk.CENTER)

        viewButton = tk.CTkButton(self, text="View Passwords", font=("Arial", 16, "bold"), width=160, height=32,
            command=lambda: self.viewPasswords())
        viewButton.place(relx=0.65, rely=0.75, anchor=tk.CENTER)

    # send a request to retrieve the users passwords so they can be viewed
    def viewPasswords(self):
        if self.socket == None:
            self.errorLabel.configure(text="Not connected to server")
            return
        try:
            data = {"type": "Get passwords", "username": self.username}
            jsonData = json.dumps(data)
            self.socket.sendall(jsonData.encode())
            msg = self.socket.recv(2048).decode()
            passwords = json.loads(msg)
            self.passwords = passwords
            # hide this frame and setup password view frame
            self.controller.hideFrame(PasswordManagementScreen)
            self.controller.setupPasswordDisplay(passwords)
            self.controller.showFrame(ViewPasswordsScreen)
            self.errorLabel.configure(text="")
            self.successLabel.configure(text="")
            
        except Exception as e:
            print(e)
            self.errorLabel.configure(text="Error connecting to server")

    # set the username
    def setUsername(self, username):
        self.username = username

    # generate password and update the appropriate fiels with true password/encoded password
    def passwordGenerator(self):
        length = int(self.slider.get())
        # get random password of given length with letters, digits, and different symbols
        validSymbols = "@-!$#&"
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

        # update the trueField with the new password
        self.passwordField.configure(state="normal")
        self.passwordField.delete(0, len(self.passwordField.get()))
        self.passwordField.insert(0, password_str)
        self.passwordField.configure(state="readonly")

    # send a request to the server to save the password
    def savePassword(self):
        if self.socket == None:
            self.errorLabel.configure(text="Not connected to server")
            return
        try:
            data = {
                "type": "Save password", 
                "password": self.passwordField.get(), 
                "username": self.username, 
                "label": self.generatedPasswordLabelEntry.get()
            }
            jsonData = json.dumps(data)
            self.socket.sendall(jsonData.encode())
            msg = self.socket.recv(2048).decode()
            if "Password saved" in msg:
                self.errorLabel.configure(text="")
                self.successLabel.configure(text=msg)
            else:
                self.successLabel.configure(text="")
                self.errorLabel.configure(text=msg)
        except Exception as e:
            print(e)
            self.successLabel.configure(text="")
            self.errorLabel.configure(text="Error connecting to server")


# the login frame
class LoginScreen(tk.CTkFrame):
    def __init__(self, parent, controller, height, width, socket):
        tk.CTkFrame.__init__(self, parent, height=height, width=width)
        self.socket = socket
        self.controller = controller

        headerLabel = tk.CTkLabel(self, text="Login to Your Account", font=("Arial", 32, "bold"))
        headerLabel.place(relx=0.50, rely=0.15, anchor=tk.CENTER)

        usernameLabel = tk.CTkLabel(self, text="Username", font=("Arial", 16, "bold"))
        usernameLabel.place(relx=0.28, rely=0.33, anchor=tk.CENTER)

        passwordLabel = tk.CTkLabel(self, text="Password", font=("Arial", 16, "bold"))
        passwordLabel.place(relx=0.28, rely=0.50, anchor=tk.CENTER)

        self.errorLabel = tk.CTkLabel(self, text="", font=("Arial", 14, "bold"), text_color="#ff4242")
        self.errorLabel.place(relx=0.50, rely=0.66, anchor=tk.CENTER)

        self.userEntry = tk.CTkEntry(self, placeholder_text="Enter username here", width=350, font=("Arial", 14))
        self.userEntry.place(relx=0.50, rely=0.40, anchor=tk.CENTER)

        self.passwordEntry = tk.CTkEntry(self, placeholder_text="Enter password here", width=350, font=("Arial", 14), show="*")
        self.passwordEntry.place(relx=0.50, rely=0.57, anchor=tk.CENTER)

        loginButton = tk.CTkButton(self, text="Login", font=("Arial", 20, "bold"), width=350, height=32, 
            command=lambda: self.loginSuccess())
        loginButton.place(relx=0.50, rely=0.75, anchor=tk.CENTER)
 
        self.registerLabel = tk.CTkLabel(self, text="Click here to register", font=("Arial", 16, "bold"), cursor="hand2", text_color="#4aa8ff")
        self.registerLabel.place(relx=0.50, rely=0.88, anchor=tk.CENTER)

        self.registerLabel.bind("<Button-1>", lambda event: self.registrationScreen())
        
        self.userEntry.bind("<Return>", lambda event: self.loginSuccess())
        self.passwordEntry.bind("<Return>", lambda event: self.loginSuccess())

    # show the registration screen
    def registrationScreen(self):
        self.controller.hideFrame(LoginScreen)
        self.controller.showFrame(RegistrationScreen)
        self.errorLabel.configure(text="")
        self.userEntry.delete(0, len(self.userEntry.get()))
        self.passwordEntry.delete(0, len(self.passwordEntry.get()))
        
    # send a request to the server to login the user
    def loginSuccess(self):
        if self.socket == None:
            self.errorLabel.configure(text="Not connected to server")
            return
        try:
            data = {"type": "Login", "username": self.userEntry.get(), "password": self.passwordEntry.get()}
            jsonData = json.dumps(data)
            self.socket.sendall(jsonData.encode())
            msg = self.socket.recv(2048).decode()
            if "Login successful" in msg:
                self.controller.setUsernameForFrame(PasswordManagementScreen, self.userEntry.get())
                self.controller.setUsernameForFrame(ViewPasswordsScreen, self.userEntry.get())
                self.controller.destroyFrame(LoginScreen)
                self.controller.createFrame(PasswordManagementScreen, 0, 0, (25, 25), 25)
            else:
                self.errorLabel.configure(text=msg)
        except Exception as e:
            print(e)
            self.errorLabel.configure(text="Error connecting to server")


# start the client instance
if __name__== "__main__":
    sslSock = None
    try:
        s = socket.socket()
        s.settimeout(15)
        # bind to ip and port
        s.connect(('127.0.0.1', 33333))

        sslContext = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="trust_store/server_cert.pem")
        sslSock = sslContext.wrap_socket(s, server_hostname="PWManage")
    except Exception as e:
        print(e)
    app = Root(sslSock)
    app.mainloop()
