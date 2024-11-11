'''

Ann Ubaka 
Eltonia Leonard
Brittany Lee

April 20th, 2024

## IoT Group Projecy Project Overview

This project enhances the existing functionality of Uncle Roger's garage system by implementing features for multiple users (admin and subusers) and integrating a database to log user credentials and activity.

## Dependencies

- `pyrebase`: Firebase SDK for Python
- `RPi.GPIO`: GPIO library for Raspberry Pi
- `gpiozero`: Simple API for controlling GPIO devices
- `flask`: Web framework for Python
- `smtplib`: Library for sending emails via SMTP
- `secrets`: Library for generating cryptographically strong random numbers
- `string`: Library for string manipulations
- `hashlib`: Library for secure hashing algorithms
- `time`: Library for time-related functions
- `datetime`: Library for manipulating dates and times

## Setup and Configuration

This project requires a Firebase account and Raspberry Pi setup. Ensure the following configurations:

- Firebase:
  - Set up a Firebase project and note down the configuration details.
- Raspberry Pi:
  - Install necessary Python libraries (`pyrebase`, `RPi.GPIO`, `gpiozero`, `flask`, etc.).
  - Connect GPIO pins for LEDs and buzzer as per the provided pin mapping.

## Usage

1. **Home Page (`/`):**
   - Displays the current state of the garage door.
   - If not logged in, prompts for login.

2. **Login (`/login`):**
   - Allows users to log in using their email and password.
   - Implements a lockout mechanism after 3 failed login attempts.

3. **Sign Up (`/signup`):**
   - Enables users to create a new account.
   - Includes validation for password length and role-based permissions.

4. **Main Page (`/main`):**
   - Provides an interface for users to interact with the garage system.
   - Shows subusers for admin accounts.

5. **Open Door (`/open`):**
   - Opens the garage door.
   - Sends a notification email to the owner's email address.

6. **Close Door (`/close`):**
   - Closes the garage door.

7. **2FA PIN Verification (`/verify_pin`):**
   - Verifies the two-factor authentication (2FA) PIN sent to the user's email.

8. **Unlock Account (`/locked_out`):**
   - Allows locked-out users to unlock their accounts using a PIN sent to their email.

9. **Logout (`/logout`):**
   - Logs out the user ad redirects to the home page.

## Additional Functions

- `coolDown()`: Implements a cooldown period to prevent system overload.
- `generateSalt()`: Generates a random salt for password hashing.
- `send_msg()`: Sends a notification email to the owner's email address.
- `send_pin(pin)`: Sends a PIN to the ower's email address.
- `generateRandomCode()`: Generates a random PIN code for various purposes.
'''

# import required modules
import pyrebase
from collections.abc import MutableMapping

config = {
    "apiKey": "AIzaSyCzTpHnHuga6e06oGcwHdbtBChuxi3zXOY",
    "authDomain": "automatedgarage-836a3.firebaseapp.com",
    "databaseURL": "https://automatedgarage-836a3-default-rtdb.firebaseio.com",
    "projectId": "automatedgarage-836a3",
    "databaseURL": "https://automatedgarage-836a3-default-rtdb.firebaseio.com",
    "storageBucket": "automatedgarage-836a3.appspot.com",
    "messagingSenderId": "25785864055",
    "appId": "1:25785864055:web:02ed9e2fe0d9fae5d69b72"
}

firebase = pyrebase.initialize_app(config)
database = firebase.database()
auth = firebase.auth()


import RPi.GPIO as GPIO
from gpiozero import LED, Buzzer
import string
from hashlib import sha256
from signal import pause
from time import sleep
from datetime import datetime, timedelta
from flask import Flask, render_template, request, flash, redirect, session
import secrets
import smtplib
import emailcred
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(16)

red_LED_GPIO = 23
green_LED_GPIO = 24

red_LED = LED(red_LED_GPIO) 
green_LED = LED(green_LED_GPIO)

garageBuzzer = Buzzer(16)

# Create a dictionary called pins to store the pin number, name, and pin state:
pins = {
   23 : {'var_name' : red_LED, 'state' : False, 'discription' : 'The Red LED'},
   24 : {'var_name' : green_LED, 'state' : False, 'discription' : 'The Green LED'}
   }

# Assign each pin as an LED and turn it off
for pin in pins:
    led_name = pins[pin]['var_name']
    led_name.off()

@app.route('/open')
def openDoor():
    """
    Opens the garage door.
    """
    green_LED.off()  # Turn off the LED that signifies a closed door
    garageBuzzer.beep(0.5, 0.5, 10, False)
    session['state'] = 'open'
    print(session['state'])
    red_LED.on()
    
    send_msg()
    coolDown()
    
    # Update the last time the garage door was opened by the user
    if 'user' in session:
         try:
            user_id = session.get('user')['localId']
                        
            last_opened_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S %p')
            
            database.child("users").child(user_id).update({'last_attempt_to_open_garage': last_opened_time})
         except Exception as e:
             print("Error:", e)

    
    templateData = {
    'state' : session['state']
    }
    return render_template('main.html', **templateData)

@app.route('/close')
# Function to close the garage door
def closeDoor():
    """
    Closes the garage door.
    """
    red_LED.off()  # Turn off the LED that signifies an opened door
    garageBuzzer.beep(0.5, 0.5, 10, False)
    session['state'] = 'closed'
    green_LED.on()
    coolDown()
    
    templateData = {
    'state' : session['state']
    }
    return render_template('main.html', **templateData)

# Cool down function to prevent system from getting overwhelmed
def coolDown():
    """
    Implements a cooldown period.
    """
    flash("Cooling down...")
    sleep(10)
    flash("Ready for next action!\n")
    
def generateSalt():
    """
    Generates a random salt for password hashing.
    """
    global salt
    alphabet = string.ascii_letters + string.digits
    salt = ''.join(secrets.choice(alphabet) for i in range(16))
    return salt
 
def send_msg():
    """
    Sends a notification email to the owner's email address.
    """
    print('Preparing SMTP connection...')
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(emailcred.FROM, emailcred.PASS)
        actionMessage = ''.join(['\nHello! Your garage was opened at ', time.strftime('%I:%M:%S %p'), ' by ', session.get('user')['username']])
        flash("Notification sent to owner's email address\n")
        server.sendmail(emailcred.FROM, emailcred.TO, actionMessage)
        server.quit()
    except Exception as e:
        print("Failed to send email notification:", e) 
  
def send_pin(pin):
    """
    Sends a PIN to the owner's email address.
    """
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(emailcred.FROM, emailcred.PASS)
        pinMessage = "Your pin is [" + pin + "]. It will expire in one minute."
        print('PIN sent to email address\n')
        server.sendmail(emailcred.FROM, emailcred.TO, pinMessage)
        server.quit()
        timeStart = datetime.now()
        
        # Storing timeStart in session
        session['timeStart'] = timeStart

    except Exception as e:
        print("Failed to send PIN email:", e)

def generateRandomCode():
    nums = string.digits
    random_pin = ''.join(secrets.choice(nums) for i in range(5))
    return random_pin
                
@app.route("/") # Binds to the respective webpage 
def home():
    if session.get('locked_out'):
        return render_template('locked_out.html')
    elif not session.get('logged_in'):
        return render_template('login.html')
    else:    
        state = session.get('state')
        templateData = {
            'state': state,
        }
        return render_template('main.html', **templateData)

@app.route('/login', methods=['POST'])
def do_admin_login(): 
        email = request.form.get('email')
        password = request.form.get('login_password')
        
        try:
            # Check password length
            if len(password) < 8:  
                flash("Password must be at least 8 characters long.")
                return redirect('/')
            
            # Sign in the user with email and password
            user = auth.sign_in_with_email_and_password(email, password)
            
            # Update the last login timestamp for the user
            user_id = user['localId']
            
            encoded_user_id = user_id.replace('.', ',')  # Replace '.' with ',' or use another encoding method

            last_login_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S %p')
            database.child("users").child(encoded_user_id).update({'last_login': last_login_time})

            # Retrieve user data from Firebase Realtime Database
            user_data = database.child("users").child(user['localId']).get().val()

            # Store user data in session
            session['user'] = user_data
            
            # Reset failed login attempts counter
            session.pop('attempts_counter', None)

            return redirect('/verify_pin')

        except Exception as e:
        # Handle login failure
            print("Login error:", e)
            
            attempts_counter = session.get('attempts_counter', 0)
            attempts_counter += 1

            if attempts_counter >= 3:  # Lock user out after 3 failed attempts
                flash("You have exceeded the maximum number of login attempts. Your account has been locked.")
                session['attempts_counter'] = 0  # Reset attempts counter
                session['locked_out'] = True  # Set locked_out flag
                return redirect('/locked_out')
            else:
                flash("Invalid email or password. Attempt %d out of 3." % attempts_counter)
                session['attempts_counter'] = attempts_counter
                return redirect('/')

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    sign_up_password = request.form['sign_up_password']
    email = request.form['email']
    role = request.form['role']
    
    admin_email_if_subuser = request.form['admin_email']
    special_pin_if_admin = request.form['special_pin_admin']
    pin_to_get_authorized = request.form['special_pin']
    
    password_salt = generateSalt()
    
    salted_input_password = sign_up_password + password_salt
    
    
    admin_pin_salt = generateSalt()
    salted_special_pin_if_admin = special_pin_if_admin + admin_pin_salt

    hashed_salted_input_password = sha256(salted_input_password.encode()).hexdigest()
    hashed_salted_admin_pin_for_authorization = sha256(salted_special_pin_if_admin.encode()).hexdigest()


    # Check password length
    if len(sign_up_password) < 8: 
        flash("Password must be at least 8 characters long.")
        return render_template('login.html')

    # Check if the provided role is "sub_user" and if an admin email is provided
    if role == "sub_user" and admin_email_if_subuser:
        # Query the database to check if the provided admin email exists
        db_emails = database.child('users').order_by_child('email').get()
        email_exists = False
        
        for db_email in db_emails.each():
            if db_email.val()['email'] == admin_email_if_subuser:
                email_exists = True
                admin_data = db_email.val()
                break
        
        if not email_exists:
            flash("Admin email not found.")
            return render_template('login.html')
        
        # Check if the provided PIN matches the admin's PIN
        attempted_pin_with_salt = pin_to_get_authorized + admin_data['special_pin_salt']
        hashed_attempted_pin_with_salt = sha256(attempted_pin_with_salt.encode()).hexdigest()

        if admin_data['hashed_salted_admin_pin_for_authorization'] != hashed_attempted_pin_with_salt:
            flash("Incorrect PIN.")
            return render_template('login.html')
            
    try:
        # Create user in Firebase Authentication
        user = auth.create_user_with_email_and_password(email, sign_up_password)

        # Additional user data to store in the database
        user_data = {
            'localId': user['localId'],
            'email': email,
            'username': username,
            'role': role,  # Role or permission level of the sub-user
            'admin_email_if_subuser': admin_email_if_subuser,
            'joining_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S %p'),  # Joining date of the sub-user
            'last_login': None,
            'pin_to_get_authorized': pin_to_get_authorized,
            'last_attempt_to_open_garage': None,
            'salt': password_salt,
            'hashed_salted_input_password': hashed_salted_input_password,
            'special_pin_salt': admin_pin_salt,
            'hashed_salted_admin_pin_for_authorization': hashed_salted_admin_pin_for_authorization
        }

        # Store user data in the database under the 'users' node with the user's localId as the key
        database.child('users').child(user['localId']).set(user_data)
        
        # Store user data in session
        session['user'] = user_data
        
        print(session['user'])
        
        # Perform 2FA after successful sign-up
        return redirect('/verify_pin')

    except Exception as e:
        print("Sign up error:", e)

        # Handle sign-up failure, display an error message on the sign-up page
        return render_template('login.html', error=str(e)), 400

@app.route('/verify_pin', methods=['GET', 'POST'])
def pin_verification():
    if request.method == 'GET':
        print("Attempting to verify 2FA pin here.")
        random_pin_2FA = session.get('random_pin_2fa')
        
        # Store the random pin in session
        session['random_pin_2FA'] = random_pin_2FA
        
        # Record the start time before sending the PIN
        session['v_pin_start_time'] = datetime.now()
        
        return render_template('verify_pin.html')

    if request.method == 'POST':
        timeStart = session.get('v_pin_start_time')
        
        random_pin_2FA = session.get('random_pin_2FA')
        
        attemptedPin = request.form.get('oneTimePin')
        timeEnd = datetime.now()

        # Check if the pin is still valid
        if (timeEnd - timeStart).total_seconds() < 60:
            if attemptedPin == random_pin_2FA:
                session['logged_in'] = True
                
                # Clear attempts_counter from session
                session.pop('attempts_counter', None)
                return main()
            else:
                flash("Incorrect PIN.\n")
                session['logged_in'] = False

        else:
            flash("The pin expired.\n")
            session['logged_in'] = False
        
    return render_template('verify_pin.html')

@app.route('/locked_out', methods=['GET','POST'])
def unlockAccount():
    if request.method == 'GET':
        print("Attempting to verify unlock pin here.")
        random_pin_unlock = session.get('new_random_pin_unlock')

        # Store the random pin in session
        session['random_pin_unlock'] = random_pin_unlock
        
        # Record the start time before sending the PIN
        session['u_pin_start_time'] = datetime.now()
        
        return render_template('locked_out.html')
    
    if request.method == 'POST':
        timeStart = session.get('u_pin_start_time')
        
        random_pin_unlock = session.get('random_pin_unlock')
        
        attemptedPin = request.form.get('oneTimePin')
        timeEnd = datetime.now()
        
        # Check if the pin is still valid
        if (timeEnd - timeStart).total_seconds() < 60:
            if attemptedPin == random_pin_unlock:
                
                # Clear attempts_counter from session
                session.pop('attempts_counter', None)
                session['logged_in'] = False
                session['locked_out'] = False
                return main()
            else:
                flash("Incorrect PIN.\n")
                session['logged_in'] = False

        else:
            flash("The pin expired.\n")
            session['logged_in'] = False
    return render_template('locked_out.html')

@app.route('/generate_2fa_pin', methods=['GET'])
def generate_2fa_pin():
    # Generate a new PIN for 2FA
    random_pin_2fa = generateRandomCode()

    # Store the new random 2FA PIN in session
    session['random_pin_2fa'] = random_pin_2fa
    
    # Record the start time before sending the PIN
    session['v_pin_start_time'] = datetime.now()
    
    # Send the new random 2FA PIN to the user via email
    send_pin(random_pin_2fa)
    print("New 2FA PIN Sent to Email")

    flash("New 2FA PIN generated and sent to email. Caution: The pin will expire within one minute.")
    return redirect('/verify_pin')

@app.route('/generate_unlock_pin', methods=['GET'])
def generate_unlock_pin():
    # Generate a new PIN for unlocking the account
    random_pin_unlock = generateRandomCode()

    # Store the new random PIN for unlocking in session
    session['new_random_pin_unlock'] = random_pin_unlock

    # Record the start time before sending the PIN
    session['u_pin_start_time'] = datetime.now()
    
    # Send the new random PIN to the user via email
    send_pin(random_pin_unlock)
    print("New Unlock PIN Sent to Email")

    flash("New Unlock PIN generated and sent to email. Caution: The pin will expire within one minute.")
    return redirect('/locked_out')

@app.route("/logout")
def logout():
    session['logged_in'] = False
    return home()

@app.route("/main")
def main():
    if session.get('locked_out'):
        return render_template('locked_out.html')
    elif not session.get('logged_in'):
        return render_template('login.html')
    else:
        # Fetch user data from the session
        admin_email = session.get('user')['email'] 
                
        try:
            subusers = database.child("users").order_by_child("admin_email_if_subuser").equal_to(admin_email).get()
            subuser_list = [subuser.val() for subuser in subusers.each()]

            if subuser_list:
                templateData = {'subusers': subuser_list}
                return render_template('main.html', **templateData)
            
            else:
                templateData = {'subusers': ["No subusers found for the admin."]}
                return render_template('main.html', **templateData)
            
        except Exception as e:
            print("Error:", e)
            flash("An error occurred. Please try again later.")
            return redirect('/')

if __name__ == "__main__":
   app.run(host='0.0.0.0', port=80, debug=True)

