# upike_parking/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
import os
import secrets
import stripe
import logging
from logging.handlers import RotatingFileHandler

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(16))
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Database and external service configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://upike_parking_db_user:password@localhost:5432/upike_parking_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['STRIPE_PUBLIC_KEY'] = os.getenv('STRIPE_PUBLIC_KEY', 'your-stripe-public-key')
app.config['STRIPE_SECRET_KEY'] = os.getenv('STRIPE_SECRET_KEY', 'your-stripe-secret-key')
app.config['PREFERRED_URL_SCHEME'] = 'https'

# Initialize Stripe
stripe.api_key = app.config['STRIPE_SECRET_KEY']

# Initialize SQLAlchemy and Migrate
db = SQLAlchemy(app)
migrate = Migrate(app, db, render_as_batch=True)  # Enable batch mode for PostgreSQL compatibility

# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'landing'

# User loader function
@login_manager.user_loader
def load_user(user_id):
    from .models import Student, Admin
    app.logger.debug(f"Loading user with ID: {user_id}")
    try:
        # Check if the user_id is for a Student (numeric ID)
        if user_id.isdigit():
            student = Student.query.get(int(user_id))
            if student:
                app.logger.debug(f"Loaded student: {student.email}")
                return student
        # Otherwise, treat it as an Admin username (string)
        admin = Admin.query.get(user_id)
        if admin:
            app.logger.debug(f"Loaded admin: {admin.username}")
            return admin
        app.logger.warning(f"No user found for ID: {user_id}")
        return None
    except Exception as e:
        app.logger.error(f"Error loading user {user_id}: {str(e)}")
        return None

# Import models and routes
from .models import Student, Admin, Ticket, Appeal
from .routes import *

# Logging setup
logs_dir = os.path.join(BASE_DIR, 'logs')
os.makedirs(logs_dir, exist_ok=True)
if not app.debug:
    handler = RotatingFileHandler(os.path.join(logs_dir, 'upike_parking.log'), maxBytes=1000000, backupCount=5)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

# Log startup
app.logger.info('UPIKE Parking app startup')

if __name__ == '__main__':
    app.run(debug=True)