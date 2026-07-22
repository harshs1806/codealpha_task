import hashlib

# Demo user data
stored_username = "user@example.com"
stored_password_hash = hashlib.sha256("MySecurePass123!".encode()).hexdigest()
two_step_pin = "482913"

def login():
    username = input("Enter username: ")
    password = input("Enter password: ")
    pin = input("Enter 2-step verification PIN: ")

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if username == stored_username and password_hash == stored_password_hash and pin == two_step_pin:
        print("Login successful")
    else:
        print("Invalid credentials")

login()