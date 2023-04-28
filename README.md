# PasswordManager

- A password management application that Uses SSL/TLS for secure communication and MySQL for storage

- User provided passwords are salted and hashed before being stored in the database

- User can then generate and store as many passwords as they want belonging to their account
  - These passwords are encrypted with a unique key for the user and can be decrypted so the user can retrieve the original password
  
- Fernet library is used for encryption/decryption and BCrypt is used to salt and hash account passwords

- CustomTKinter was used to develop the GUI
