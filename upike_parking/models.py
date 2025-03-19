# upike_parking/models.py
from . import db
from flask_login import UserMixin
from datetime import datetime

class Student(UserMixin, db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    permit_number = db.Column(db.String(20), unique=True, nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    permit_type = db.Column(db.String(20), nullable=False)
    residence = db.Column(db.String(100))
    first_name = db.Column(db.String(50), default="Unknown")
    last_name = db.Column(db.String(50), default="Unknown")
    vehicle_color = db.Column(db.String(20), nullable=False)
    license_plate_number = db.Column(db.String(20), nullable=False)
    license_plate_state = db.Column(db.String(2), nullable=False)
    vehicle_year = db.Column(db.Integer, nullable=False)
    make = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(256), nullable=False)
    tickets = db.relationship('Ticket', backref='student', lazy=True)
    appeals = db.relationship('Appeal', backref='student', lazy=True)

    def get_id(self):
        return str(self.id)

class Admin(UserMixin, db.Model):
    __tablename__ = 'admins'
    username = db.Column(db.String(50), primary_key=True)
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='Parking Officer')
    officer_number = db.Column(db.String(20), nullable=True)
    tickets = db.relationship('Ticket', backref='admin', lazy=True)

    def get_id(self):
        return self.username

class Ticket(db.Model):
    __tablename__ = 'tickets'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    admin_username = db.Column(db.String(50), db.ForeignKey('admins.username'), nullable=False)
    issue_date = db.Column(db.DateTime, default=datetime.utcnow)
    reason = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Pending')
    appeals = db.relationship('Appeal', backref='ticket', lazy=True)

class Appeal(db.Model):
    __tablename__ = 'appeals'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.id'), nullable=False)
    appeal_text = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')
    media_data = db.Column(db.LargeBinary, nullable=True)
    media_type = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    decision_date = db.Column(db.DateTime, nullable=True, default=None)