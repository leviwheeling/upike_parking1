# upike_parking/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, FileField, IntegerField, FloatField, TelField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional, Regexp, NumberRange

class StudentLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AdminSignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    role = SelectField('Role', choices=[('Admin', 'Admin'), ('Admin Officer', 'Admin Officer'), ('Parking Officer', 'Parking Officer')], validators=[DataRequired()])
    officer_number = StringField('Security Key', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class AdminLoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class SignupForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    permit_number = StringField('Permit Number', validators=[DataRequired(), Length(min=5, max=20)])
    phone_number = TelField('Phone Number', validators=[DataRequired(), Regexp(r'^\+?1?\d{10,15}$', message="Phone number must be between 10 and 15 digits")])
    permit_type = SelectField('Permit Type', choices=[('Resident', 'Resident'), ('Commuter', 'Commuter'), ('Staff', 'Staff')], validators=[DataRequired()])
    residence = StringField('Residence (if applicable)', validators=[Optional()])
    first_name = StringField('First Name', validators=[Optional()])
    last_name = StringField('Last Name', validators=[Optional()])
    vehicle_color = StringField('Vehicle Color', validators=[DataRequired()])
    license_plate_number = StringField('License Plate Number', validators=[DataRequired()])
    license_plate_state = StringField('License Plate State', validators=[DataRequired(), Length(min=2, max=2)])
    vehicle_year = IntegerField('Vehicle Year', validators=[DataRequired(), NumberRange(min=1900, max=2025)])
    make = StringField('Make', validators=[DataRequired()])
    model = StringField('Model', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class UpdateForm(FlaskForm):
    email = StringField('Email', validators=[Optional(), Email()])
    permit_number = StringField('Permit Number', validators=[Optional(), Length(min=5, max=20)])
    phone_number = TelField('Phone Number', validators=[Optional(), Regexp(r'^\+?1?\d{10,15}$', message="Phone number must be between 10 and 15 digits")])
    permit_type = SelectField('Permit Type', choices=[('Resident', 'Resident'), ('Commuter', 'Commuter'), ('Staff', 'Staff')], validators=[Optional()])
    residence = StringField('Residence (if applicable)', validators=[Optional()])
    first_name = StringField('First Name', validators=[Optional()])
    last_name = StringField('Last Name', validators=[Optional()])
    vehicle_color = StringField('Vehicle Color', validators=[Optional()])
    license_plate_number = StringField('License Plate Number', validators=[Optional()])
    license_plate_state = StringField('License Plate State', validators=[Optional(), Length(min=2, max=2)])
    vehicle_year = IntegerField('Vehicle Year', validators=[Optional(), NumberRange(min=1900, max=2025)])
    make = StringField('Make', validators=[Optional()])
    model = StringField('Model', validators=[Optional()])
    password = PasswordField('Password', validators=[Optional(), Length(min=6)])
    submit = SubmitField('Update')

class TicketForm(FlaskForm):
    student_id = IntegerField('Student ID', validators=[DataRequired()])
    reason = StringField('Reason', validators=[DataRequired()])
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0)])
    submit = SubmitField('Issue Ticket')

class EditTicketForm(FlaskForm):
    reason = StringField('Reason', validators=[DataRequired()])
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0)])
    status = SelectField('Status', choices=[('Pending', 'Pending'), ('Paid', 'Paid'), ('Appealed', 'Appealed')], validators=[DataRequired()])
    submit = SubmitField('Update Ticket')

class AppealForm(FlaskForm):
    appeal_text = TextAreaField('Appeal Text', validators=[DataRequired()])
    media_data = FileField('Upload Media (Optional)', validators=[Optional()])
    submit = SubmitField('Submit Appeal')

class SearchForm(FlaskForm):
    first_name = StringField('First Name', validators=[Optional()])
    last_name = StringField('Last Name', validators=[Optional()])
    phone_number = TelField('Phone Number', validators=[Optional()])
    make = StringField('Vehicle Make', validators=[Optional()])
    model = StringField('Vehicle Model', validators=[Optional()])
    vehicle_color = StringField('Vehicle Color', validators=[Optional()])
    permit_number = StringField('Permit Number', validators=[Optional()])
    license_plate_number = StringField('License Plate Number', validators=[Optional()])
    submit = SubmitField('Search')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    role = SelectField('Role', choices=[('Admin', 'Admin'), ('Admin Officer', 'Admin Officer'), ('Parking Officer', 'Parking Officer')], validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    officer_number = StringField('Security Key', validators=[Optional()])
    submit = SubmitField('Create User')

class ReportForm(FlaskForm):
    report_type = SelectField('Report Type', choices=[
        ('tickets_issued', 'Tickets Issued'),
        ('appeals_status', 'Appeals Status'),
        ('revenue', 'Revenue Collected')
    ], validators=[DataRequired()])
    date_range = SelectField('Date Range', choices=[
        ('last_7_days', 'Last 7 Days'),
        ('last_30_days', 'Last 30 Days'),
        ('last_year', 'Last Year')
    ], validators=[DataRequired()])
    submit = SubmitField('Generate Report')