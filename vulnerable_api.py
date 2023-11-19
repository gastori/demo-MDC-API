from flask import Flask, request, jsonify
#Integrating Flask-Security-Too a vulnerable OSS pkg (CVE-2021-32618)
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin
from flask_sqlalchemy import SQLAlchemy
import sqlite3

app = Flask(__name__)

#Configure the Database for Users and Roles
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security_demo.db'
app.config['SECRET_KEY'] = 'super-secret'
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_PASSWORD_SALT'] = 'some_salt'

db = SQLAlchemy(app)
#Defining the roles_users Table
roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

#Define User and Role Models
class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False)  # Add this line
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))


#Initialize Flask-Security-Too
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

#Create a Function to Initialize the Database
#@app.before_first_request
#def create_user():
    #db.create_all()
    #if not User.query.first():
        #user_datastore.create_user(email='test@example.com', password='password')
        #db.session.commit()

# Dummy database setup
# WARNING: The database and its setup are insecure by design for this demonstration.
def init_db():
    conn = sqlite3.connect('demo.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT, price REAL)''')
    c.execute('''INSERT INTO items (name, price) VALUES ('Sample Item', 19.99)''')
    conn.commit()
    conn.close()

init_db()

#Main route
@app.route('/')
def home():
    return 'Welcome to the Vulnerable Flask API!'

# Dummy API key and admin user (intentionally insecure)
API_KEY = '12345-SECRET'
ADMIN_USER = 'admin'

#SQL Injection Vulnerability
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    # Insecure SQL query execution
    conn = sqlite3.connect('demo.db')
    c = conn.cursor()
    c.execute(f"SELECT * FROM items WHERE name LIKE '%{query}%'")
    items = c.fetchall()
    conn.close()
    return jsonify(items)

#Cross-Site Scripting (XSS) Vulnerability
@app.route('/feedback', methods=['POST'])
def feedback():
    user_input = request.form['comment']
    # Reflecting back user input without sanitization
    return f"Thanks for your feedback: {user_input}"

#Insecure Direct Object References (IDOR)
@app.route('/item/<int:item_id>', methods=['GET'])
def get_item(item_id):
    # Accessing items directly without authorization checks
    conn = sqlite3.connect('demo.db')
    c = conn.cursor()
    c.execute(f"SELECT * FROM items WHERE id = {item_id}")
    item = c.fetchone()
    conn.close()
    return jsonify(item)

#Sensitive Data Exposure
@app.route('/config', methods=['GET'])
def config():
    # Exposing sensitive data intentionally
    return jsonify({"api_key": API_KEY, "admin_user": ADMIN_USER})

#Missing Function Level Access Control
@app.route('/admin/create_item', methods=['POST'])
def create_item():
    # Admin functionality without role check
    name = request.form['name']
    price = request.form['price']
    conn = sqlite3.connect('demo.db')
    c = conn.cursor()
    c.execute(f"INSERT INTO items (name, price) VALUES ('{name}', {price})")
    conn.commit()
    conn.close()
    return jsonify({"status": "Item created"})

#Running the Application
if __name__ == '__main__':
    app.run(debug=True)
