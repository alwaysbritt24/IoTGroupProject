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

firebase=pyrebase.initialize_app(config)

db= firebase.database()
auth = firebase.auth()

#retieve data
users= db.child("users").get()

for users in users.each():
    print(users.val())
  