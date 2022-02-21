import sqlite3
import collections
import random
import string
import tkinter as tk
import tkinter.font
from tkinter import messagebox, Text, Toplevel, Menu
from cryptography.fernet import Fernet

################################################
# initializing all windows for the program.
root_register = tk.Tk()
root_register.title("Registration Screen")
root_register.resizable(False, False)

root_login = Toplevel(root_register)
root_login.title("Login Screen")
root_login.resizable(False, False)
# hiding window until needed.
root_login.withdraw()

root = Toplevel(root_login)
root.title("Password Decoder")
root.resizable(False, False)
root.withdraw()
################################################
PERMANENT_KEY = Fernet.generate_key()

# key used to decrypt database information.
DATABASE_KEY = b'' # IMPORTANT ! KEY IS EMPTY IN SOURCE CODE BUT EXISTS IN DOWNLOADABLE VERSION OF GUI !


# overrides default event command for a specific key/button
# returns "break" => removes default event command
def override(event):
    return "break"


# used to make an event for create_user() that can be binded to any key, in this case
# it will be binded to the enter key for the registration window.
# returns "break" => removes default event command after binding new command
def enter_handler_register(DATABASE_KEY, user_entry, password_entry):
    create_user(DATABASE_KEY, user_entry, password_entry)

    return "break"


# used to make an event for login_success() that can be binded to any key, in this case
# it will be binded to the enter key for the login window.
# returns "break" => removes default event command after binding new command
def enter_handler_login(user_entry_two, password_entry_two, user_key_entry, temp_list):
    login_success(user_entry_two, password_entry_two, user_key_entry, temp_list)

    return "break"


# function to center window on user's screen.
# returns none.
def center_window(window):
    win_height = 500
    win_width = 650

    w = window.winfo_screenwidth()
    h = window.winfo_screenheight()

    x = int((w / 2) - (win_width / 2))
    y = int((h / 2) - (win_height / 2))

    window.geometry('{}x{}+{}+{}'.format(win_width, win_height, x, y))


# displays login screen.
# returns none.
def display_login():
    root_login.deiconify()
    root_register.withdraw()
    center_window(root_login)


# goes back to register screen.
# returns none.
def back():
    root_login.withdraw()
    root_register.deiconify()
    center_window(root_register)


def insert_data(user_entry, password_entry):
    with sqlite3.connect("Database.db") as db:
        cursor = db.cursor()
    # insert registered username and password into database along with generated key.
    insert = ''' INSERT INTO user(username, password)
                                            VALUES(?, ?)'''
    cursor.execute(insert, [encrypt_message(user_entry.get("1.0", "end-1c"), DATABASE_KEY),
                                 encrypt_message(password_entry.get("1.0", "end-1c"), DATABASE_KEY)])
    db.commit()
    tkinter.messagebox.showinfo(title="Registered", message="Successfully registered. Please continue.")


# function that adds the user to the database if the user doesn't already exist
# returns none.
def create_user(DATABASE_KEY, user_entry, password_entry):
    with sqlite3.connect("Database.db") as db:
        cursor = db.cursor()
    # adding a check flag to bypass adding user to database if username already exists or user/pass field empty.
    check = False
    cursor.execute("SELECT * FROM user")
    results = cursor.fetchall()
    # if there is anything that exists within database.
    if results:
        # searches database to see if username already exists.
        for i in results:
            # if the username already exists user isn't able to register with that username.
            if decrypt_message(i[1], DATABASE_KEY).lower() == user_entry.get("1.0", "end-1c").lower():
                tkinter.messagebox.showerror(title="Error", message="Username already exists!")
                check = True
                user_entry.delete("1.0", "end")
                password_entry.delete("1.0", "end")
                break

            elif user_entry.get("1.0", "end-1c") == "" or password_entry.get("1.0", "end-1c") == "":
                tkinter.messagebox.showerror(title="Error", message="Username or password empty!")
                check = True
                break

        if not check:
            insert_data(user_entry, password_entry)

    else:
        if user_entry.get("1.0", "end-1c") == "" or password_entry.get("1.0", "end-1c") == "":
            tkinter.messagebox.showerror(title="Error", message="Username or password empty!")

        else:
            insert_data()


def insert_key(user_key_entry, temp_list):
    with sqlite3.connect("Database.db") as db:
        cursor = db.cursor()

    cursor.execute("SELECT key FROM user WHERE username = ?", (search_user(temp_list),))
    for row in cursor:
        for elem in row:
            if elem is not None:
                user_key_entry.config(state="normal")
                user_key_entry.insert(tk.INSERT, decrypt_message(elem, DATABASE_KEY))
                user_key_entry.config(state="disabled")
                break


def login_failure(user_entry_two, password_entry_two):
    tk.messagebox.showerror(title="Error", message="Username or password does not exist!")
    user_entry_two.delete("1.0", "end")
    password_entry_two.delete("1.0", "end")


# checks if temporary registration has been completed and proceeds with login when finding
# username and password in temporary create_user() or in database.
# returns none.
def login_success(user_entry_two, password_entry_two, user_key_entry, temp_list):
    temp_list.append(user_entry_two.get("1.0", "end-1c").lower())
    with sqlite3.connect("Database.db") as db:
        cursor = db.cursor()
    cursor.execute("SELECT * FROM user")
    results_db = cursor.fetchall()
    # initializing count to handle error messages.
    count = 0

    # loops through database table and checks if username and password exists.
    if results_db:
        for i in results_db:
            # increase count every time loop repeats.
            count += 1
            # if username and password is in database log user in and open main window.
            if user_entry_two.get("1.0", "end-1c").lower() == decrypt_message(i[1], DATABASE_KEY).lower() and \
                    password_entry_two.get("1.0", "end-1c") == decrypt_message(i[2], DATABASE_KEY):
                tk.messagebox.showinfo(title="Login Success", message="Successfully logged in.")

                insert_key(user_key_entry, temp_list)
                root_login.withdraw()
                root.deiconify()
                center_window(root)
                break

            # if count is equal to length of table and login boxes empty, break out of loop.
            elif count == len(results_db):
                if user_entry_two.get("1.0", "end-1c") == "" or password_entry_two.get("1.0", "end-1c") == "":
                    tk.messagebox.showerror(title="Error", message="Username or password empty!")
                    break

                # else if count is equal to length of table and user trying to login,
                # username/password doesn't exist.
                else:
                    login_failure(user_entry_two, password_entry_two)

    else:
        login_failure(user_entry_two, password_entry_two)


# when user tries to exit window, asks for confirmation and then closes the window.
# returns none.
def on_closing():
    if messagebox.askokcancel("Quit", "Are you sure you want to quit?"):
        root_register.destroy()


# encrypts any inputted string into bytes.
# @ param password => string to be encoded.
# returns encrypted_password.
def encrypt_message(password, key):
    encoded_password = password.encode()
    f = Fernet(key)
    encrypted_password = f.encrypt(encoded_password)

    return encrypted_password


# decrypts a previously encoded string to it's original form.
# @ param encrypted_password => string to be decoded.
# returns decrypted_password.
def decrypt_message(encrypted_password, key):
    f = Fernet(key)
    decrypted_password = f.decrypt(encrypted_password)

    return decrypted_password.decode()


def passwordGenerator():
    length_list = 6
    letters = string.ascii_letters
    password_list = []

    for i in range(length_list):
        random_choice = random.randint(1, 2)

        if random_choice == 1:
            password_list.append(random.choice(letters))

        else:
            password_list.append(random.randint(1, 9))

    password_list_to_str = "".join([str(i) for i in password_list])

    return password_list_to_str


def get_password():
    return passwordGenerator() + "-" + passwordGenerator() + "-" + passwordGenerator() + "-" + passwordGenerator()


# inserts and deletes generated password into password textbox.
# returns none.
def format_password_generator(password_generated_entry, user_key_entry):
    if len(password_generated_entry.get("1.0", "end-1c")) == 0:

        if len(user_key_entry.get("1.0", "end-1c")) != 0:
            password_generated_entry.config(state="normal")
            password_generated_entry.insert("1.0", get_password())
            password_generated_entry.config(state="disabled")

        else:
            tk.messagebox.showerror(title="Add Key", message="You must click Add Key first before creating passwords!")
    else:

        if len(user_key_entry.get("1.0", "end-1c")) != 0:
            password_generated_entry.config(state="normal")
            password_generated_entry.delete("1.0", "end-1c")
            password_generated_entry.insert("1.0", get_password())
            password_generated_entry.config(state="disabled")

        else:
            tk.messagebox.showerror(title="Add Key", message="You must click Add Key first before creating passwords!")


# inserts encrypted password into encrypted textbox.
# returns none.
def format_encrypted_password(password_generated_entry, user_key_entry, encode_entry):
    if len(password_generated_entry.get("1.0", "end-1c")) == 0:
        tkinter.messagebox.showerror(title="Error", message="No password to encode!")

    elif len(encode_entry.get("1.0", "end-1c")) == 0:
        encoded_pass = encrypt_message(password_generated_entry.get("1.0", "end-1c"),
                                       user_key_entry.get("1.0", "end-1c").encode())
        encode_entry.insert("1.0", encoded_pass)

        tkinter.messagebox.showinfo(title="Encode",
                                    message="Successfully encoded password. Paste the encoded text in\n"
                                            "the textbox below to decode when needed. \n\nIMPORTANT: Copy"
                                            " and save the encoded password in a safe location!")

    else:
        tkinter.messagebox.showerror(title="Error", message="Encode textbox not empty!")


# inserts decrypted password into decrypted textbox.
# returns none.
def format_decrypted_password(decode_entry, user_key_entry, decode_entry_pass):
    if len(decode_entry.get("1.0", "end-1c")) == 0:
        tkinter.messagebox.showerror(title="Error", message="Must insert encoded password in the corresponding"
                                                                " textbox!")

    elif "gAAAAA" not in decode_entry.get("1.0", "end-1c"):
        tkinter.messagebox.showerror(title="Error", message="Invalid token! AKA (Encoded password).")

    elif len(decode_entry.get("1.0", "end-1c")) != 120:
        tkinter.messagebox.showerror(title="Error", message="Invalid token! AKA (Encoded password).")

    else:
        if len(decode_entry_pass.get("1.0", "end-1c")) == 0:
            decode_entry_pass.config(state="normal")
            decode_entry_pass.insert("1.0", decrypt_message(decode_entry.get("1.0", "end-1c").encode(),
                                                            user_key_entry.get("1.0", "end-1c").encode()))
            decode_entry_pass.config(state="disabled")

        else:
            decode_entry_pass.config(state="normal")
            decode_entry_pass.delete("1.0", "end")
            decode_entry_pass.insert("1.0", decrypt_message(decode_entry.get("1.0", "end-1c").encode(),
                                                            user_key_entry.get("1.0", "end-1c").encode()))
            decode_entry_pass.config(state="disabled")


def clear_and_add(new_key, user_key_entry, decode_entry_pass, password_generated_entry, decode_entry, encode_entry):
    user_key_entry.config(state="normal")
    user_key_entry.delete("1.0", "end")
    user_key_entry.insert(tk.INSERT, new_key)
    user_key_entry.config(state="disabled")
    tk.messagebox.showinfo(title="New Key Added", message="Old key removed and new key added.")
    decode_entry_pass.config(state="normal")
    decode_entry_pass.delete("1.0", "end")
    decode_entry_pass.config(state="disabled")
    password_generated_entry.config(state="normal")
    password_generated_entry.delete("1.0", "end")
    password_generated_entry.config(state="disabled")
    decode_entry.delete("1.0", "end")
    encode_entry.delete("1.0", "end")


# updates the user's key in the database from None to a randomly generated key.
# returns none.
def update_key(temp_list, user_key_entry, decode_entry_pass, password_generated_entry, decode_entry, encode_entry):
    with sqlite3.connect("Database.db") as db:
        cursor = db.cursor()

    cursor.execute("SELECT key FROM user WHERE username = ?", (search_user(temp_list),))
    for row in cursor:
        for elem in row:
            if elem is None:
                cursor.execute("UPDATE user SET key = ? WHERE username = ?",
                                (encrypt_message(str(PERMANENT_KEY)[1:].replace("'", ""), DATABASE_KEY),
                                 search_user(temp_list)))
                db.commit()
                user_key_entry.config(state="normal")
                user_key_entry.delete("1.0", "end")
                user_key_entry.insert(tk.INSERT, PERMANENT_KEY)
                tk.messagebox.showinfo(title="Key Added", message="Key successfully added and stored in database.")
                break

            else:
                new_key = Fernet.generate_key()

                cursor.execute("UPDATE user SET key = ? WHERE username = ?",
                               (encrypt_message(str(new_key)[1:].replace("'", ""), DATABASE_KEY), search_user(temp_list)))
                db.commit()
                if messagebox.askokcancel("Add New Key", "Are you sure you want to add a new key? Doing this"
                                                         " will render passwords previously encoded with your"
                                                         " current key unable to be decoded."):
                    clear_and_add(new_key, user_key_entry, decode_entry_pass, password_generated_entry, decode_entry, encode_entry)
                break


# searches for user's username in database.
# returns real_user => the encrypted username of the user.
def search_user(temp_list):
    with sqlite3.connect("Database.db") as db:
        cursor = db.cursor()
    cursor.execute("SELECT * FROM user")
    results = cursor.fetchall()

    if results:
        for i in results:
            # loops through all encrypted usernames, decrypts them and checks if the username
            # user is logging in with matches any registered usernames.
            if len(temp_list) != 0:
                if decrypt_message(i[1], DATABASE_KEY).lower() == temp_list[0]:
                    real_user = i[1]
                    return real_user


# creates popup context menu.
# returns none.
def do_popup(m, event):
    try:
        m.tk_popup(event.x_root, event.y_root)

    finally:
        m.grab_release()


def main():
    temp_list = []
    # creating window canvas for registration screen.
    canvas_register = tk.Canvas(root_register, height=500, width=650, bg="lightblue")
    canvas_register.pack()

    # creating a frame that will be centered on the canvas of the registration screen.
    frame_register = tk.Frame(root_register, height=275, width=350, bg="lightgrey",
                          highlightbackground="darkgrey", highlightthickness=2)
    frame_register.place(relx=0.5, rely=0.45, anchor=tk.CENTER)

    # creating window canvas for login screen.
    canvas_login = tk.Canvas(root_login, height=500, width=650, bg="grey")
    canvas_login.pack()

    # creating a frame that will be centered on the canvas of the login screen.
    frame_login = tk.Frame(root_login, height=275, width=350, bg="lightblue",
                       highlightbackground="azure", highlightthickness=2)
    frame_login.place(relx=0.5, rely=0.45, anchor=tk.CENTER)

    # creating window canvas for the root (or main) screen.
    canvas_root = tk.Canvas(root, height=500, width=650, bg="lightgrey")
    canvas_root.pack()

    # creating a context menu and adding labels for cut, copy, and paste.
    m = Menu(root, tearoff=0)
    m.add_command(label="Cut")
    m.add_command(label="Copy")
    m.add_command(label="Paste")

    # configuring the command for each label of the context menu.
    m.entryconfigure("Cut", command=lambda: root.event_generate("<Control-x>"))
    m.entryconfigure("Copy", command=lambda: root.event_generate("<Control-c>"))
    m.entryconfigure("Paste", command=lambda: root.event_generate("<Control-v>"))

    # binds the do_popup function to the right mouse button to make context menu appear.
    root.bind("<Button-3>", (lambda event: do_popup(m, event)))

    small_font = tk.font.Font(family='Helvetica', size=9, weight='bold')

    # button that utilizes create_user().
    generate_register_button = tk.Button(root_register, text="Register", padx=20, pady=5, fg="black",
                                     bg="white", font=small_font, command=lambda: create_user(DATABASE_KEY, user_entry, password_entry))
    generate_register_button.place(relx=0.5, rely=0.60, anchor=tk.CENTER)

    # button that utilizes display_login().
    continue_button = tk.Button(root_register, text="Continue", padx=20, pady=5, fg="black",
                            bg="white", font=small_font, command=lambda: display_login())
    continue_button.place(relx=0.80, rely=0.90, anchor=tk.CENTER)

    # registration username label.
    user_label = tk.Label(root_register, text="Username:", font=small_font, bg="azure", width=12)
    user_label.place(relx=0.35, rely=0.30, anchor=tk.CENTER)

    # registration password label.
    password_label = tk.Label(root_register, text="Password:", font=small_font, bg="azure", width=12)
    password_label.place(relx=0.35, rely=0.40, anchor=tk.CENTER)

    # registration entry textbox.
    user_entry = Text(root_register, height=1, width=20)
    user_entry.place(relx=0.60, rely=0.30, anchor=tk.CENTER)
    user_entry.bind('<Tab>', override)
    user_entry.bind('<Return>', override)

    # registration entry textbox.
    password_entry = Text(root_register, height=1, width=20)
    password_entry.place(relx=0.60, rely=0.40, anchor=tk.CENTER)
    password_entry.bind('<Tab>', override)
    password_entry.bind('<Return>', (lambda event: enter_handler_register(DATABASE_KEY, user_entry, password_entry)))

    # login username label.
    user_label_two = tk.Label(root_login, text="Username:", font=small_font, bg="azure", width=12)
    user_label_two.place(relx=0.35, rely=0.30, anchor=tk.CENTER)

    # login password label.
    password_label_two = tk.Label(root_login, text="Password:", font=small_font, bg="azure", width=12)
    password_label_two.place(relx=0.35, rely=0.40, anchor=tk.CENTER)

    # login username textbox.
    user_entry_two = Text(root_login, height=1, width=20)
    user_entry_two.place(relx=0.60, rely=0.30, anchor=tk.CENTER)
    user_entry_two.bind('<Tab>', override)
    user_entry_two.bind('<Return>', override)

    # login password textbox
    password_entry_two = Text(root_login, height=1, width=20)
    password_entry_two.place(relx=0.60, rely=0.40, anchor=tk.CENTER)
    password_entry_two.bind('<Tab>', override)
    password_entry_two.bind('<Return>', (lambda event: enter_handler_login(user_entry_two, password_entry_two, user_key_entry, temp_list)))

    login_button = tk.Button(root_login, text="Login", padx=20, pady=5, fg="black",
                         bg="white", font=small_font, command=lambda: login_success(user_entry_two, password_entry_two,
                            user_key_entry, temp_list))
    login_button.place(relx=0.5, rely=0.60, anchor=tk.CENTER)

    back_button = tk.Button(root_login, text="Back", padx=20, pady=5, fg="black",
                        bg="white", font=small_font, command=lambda: back())
    back_button.place(relx=0.20, rely=0.90, anchor=tk.CENTER)

    # button that utilizes format_password_generator().
    generate_pass_button = tk.Button(root, text="Generate Password", width=20, pady=5, fg="black",
                                    bg="white", font=small_font, command=lambda: format_password_generator(password_generated_entry, user_key_entry))
    generate_pass_button.place(relx=0.15, rely=0.25, anchor=tk.CENTER)

    # textbox for generated password from format_password_generator().
    password_generated_entry = Text(root, height=1, width=50)
    password_generated_entry.config(state="disabled")
    password_generated_entry.place(relx=0.65, rely=0.25, anchor=tk.CENTER)

    # button that utilizes format_encrypted_password().
    encode_pass_button = tk.Button(root, text="Encode Password", width=20, pady=5, fg="black",
                                bg="white", font=small_font, command=lambda: format_encrypted_password(password_generated_entry, user_key_entry, encode_entry))
    encode_pass_button.place(relx=0.15, rely=0.45, anchor=tk.CENTER)

    # textbox for encoded password.
    encode_entry = Text(root, height=3, width=50)
    encode_entry.place(relx=0.65, rely=0.45, anchor=tk.CENTER)

    # button that utilized format_decrypted_password()
    decode_pass_button = tk.Button(root, text="Decode Password", width=20, pady=5, fg="black",
                                bg="white", font=small_font, command=lambda: format_decrypted_password(decode_entry, user_key_entry, decode_entry_pass))
    decode_pass_button.place(relx=0.15, rely=0.65, anchor=tk.CENTER)

    # textbox for inserting encoded password to be decoded.
    decode_entry = Text(root, height=3, width=50)
    decode_entry.place(relx=0.65, rely=0.65, anchor=tk.CENTER)

    # textbox that produces decoded password.
    decode_entry_pass = Text(root, height=2, width=50)
    decode_entry_pass.place(relx=0.65, rely=0.75, anchor=tk.CENTER)
    decode_entry_pass.config(state="disabled")

    # key entry text boxes.
    user_key_entry = Text(root, height=1, width=55)
    user_key_entry.place(relx=0.50, rely=0.08, anchor=tk.CENTER)
    user_key_entry.config(state="disabled")

    # creates a button to allow the user to save key to a text file.
    add_key_button = tk.Button(root, text="Add Key", padx=10, pady=5, fg="black",
                                bg="white", font=small_font, command=lambda: update_key(temp_list, user_key_entry, decode_entry_pass,
                                    password_generated_entry, decode_entry, encode_entry))
    add_key_button.place(relx=0.5, rely=0.88, anchor=tk.CENTER)

    # label that indicates user's key for all of their passwords.
    first_pass_label = tk.Label(root, text="Key", font=small_font, bg="azure", width=8)
    first_pass_label.place(relx=0.90, rely=0.08, anchor=tk.CENTER)

    # make it so that when the user tries to close the root window, on_closing function is called.
    root.protocol("WM_DELETE_WINDOW", on_closing)
    center_window(root_register)
    # initializes and opens the first window of the program, which is the registration window.
    root_register.mainloop()


if __name__ == "__main__":
    main()
