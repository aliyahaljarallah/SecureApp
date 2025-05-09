# SecureApp

# Overview

# The application supports:
- User registration and login
- User dashboard with comment posting
- Admin dashboard with access control
- Focuses on 5 security issues:
  1. SQL Injection
  2. Weak Password Storage
  3. Cross-Site Scripting (XSS)
  4. Access Control
  5. Insecure Communication (lack of HTTPS)
 
# Steps to Run the Application on mac devices
1. Create a Virtual Environment
python3 -m venv venv
source venv/bin/activate  

2. Run the App
python app.py

3. open your browser and go to https://127.0.0.1:5000


# How to Test Security Features:

SQL Injection: login with this username: ' OR 1=1 -- and password: anything(ex:1)

Weak Password Storage: check the dataBase in the terminal sqlite3 instance/database.db SELECT * FROM user;

Cross-Site Scripting: Go to the comment section in the Dashboared and type <script>alert('You have been hacked!')</script>

Access Control: Try visiting /admin as a regular user.

Insecure Communication: you will see the lock next to URL.
