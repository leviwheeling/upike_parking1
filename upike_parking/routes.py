# upike_parking/routes.py
from flask import render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, cast, String
from datetime import datetime, timedelta
import io
import magic
from . import app, db
from .models import Student, Admin, Ticket, Appeal
from .forms import StudentLoginForm, AdminSignupForm, AdminLoginForm, SignupForm, UpdateForm, TicketForm, EditTicketForm, AppealForm, SearchForm, LoginForm, UserForm, ReportForm
import stripe
import os

ALLOWED_EXTENSIONS = {'.heic', '.jpg', '.png', '.jpeg'}

def allowed_file(filename):
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS

# Consolidated landing route for both students and admins
@app.route('/', methods=['GET', 'POST'])
def landing():
    if current_user.is_authenticated:
        app.logger.debug(f"Authenticated user: {current_user.__class__.__name__}, ID: {current_user.get_id()}")
        if isinstance(current_user, Admin):
            if current_user.role == 'Admin Officer':
                return redirect(url_for('admin_officer_dashboard'))
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('student_dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        student = Student.query.filter_by(email=form.email.data).first()
        if student and check_password_hash(student.password, form.password.data):
            login_user(student, remember=True)
            app.logger.info(f"Student {student.email} logged in successfully.")
            next_page = request.args.get('next')
            app.logger.debug(f"Redirecting to next_page: {next_page} or student_dashboard")
            return redirect(next_page) if next_page else redirect(url_for('student_dashboard'))
        flash('Invalid email or password. Please use the admin login page if you are an admin.', 'danger')
        app.logger.warning(f"Failed login attempt for email: {form.email.data}")
    return render_template('landing.html', form=form)

@app.route('/student/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('student_dashboard'))
    form = SignupForm()
    if form.validate_on_submit():
        app.logger.info(f"Student signup attempt with data: email={form.email.data}, first_name={form.first_name.data}, last_name={form.last_name.data}")
        student = Student(
            email=form.email.data,
            permit_number=form.permit_number.data,
            phone_number=form.phone_number.data,
            permit_type=form.permit_type.data,
            residence=form.residence.data,
            first_name=form.first_name.data or "Unknown",
            last_name=form.last_name.data or "Unknown",
            vehicle_color=form.vehicle_color.data,
            license_plate_number=form.license_plate_number.data,
            license_plate_state=form.license_plate_state.data,
            vehicle_year=form.vehicle_year.data,
            make=form.make.data,
            model=form.model.data,
            password=generate_password_hash(form.password.data)
        )
        try:
            db.session.add(student)
            db.session.commit()
            app.logger.info(f"Student {form.email.data} successfully created with ID {student.id}.")
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('landing'))
        except Exception as e:
            db.session.rollback()
            error_str = str(e).lower()
            if 'unique constraint "students_email_key"' in error_str:
                flash('Error: This email is already registered.', 'danger')
            elif 'unique constraint "students_permit_number_key"' in error_str:
                flash('Error: This permit number is already in use.', 'danger')
            elif 'unique constraint "students_pkey"' in error_str:
                flash('Error: Database ID conflict. Please contact support.', 'danger')
            else:
                app.logger.error(f"Error creating student {form.email.data}: {str(e)}")
                flash(f'Error: {str(e)}', 'danger')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                app.logger.warning(f"Validation error in {field}: {error}")
                flash(f"Error in {field}: {error}", 'danger')
    return render_template('signup.html', form=form)

@app.route('/student/dashboard', methods=['GET', 'POST'])
@login_required
def student_dashboard():
    if not isinstance(current_user, Student):
        app.logger.warning(f"Unauthorized access to student dashboard by user: {current_user.__class__.__name__}")
        flash('Unauthorized access. Only students can view this dashboard.', 'danger')
        return redirect(url_for('landing'))
    form = UpdateForm(obj=current_user)
    if form.validate_on_submit():
        student = db.session.get(Student, current_user.id)
        if form.email.data:
            student.email = form.email.data
        if form.permit_number.data:
            student.permit_number = form.permit_number.data
        if form.phone_number.data:
            student.phone_number = form.phone_number.data
        if form.permit_type.data:
            student.permit_type = form.permit_type.data
        student.residence = form.residence.data or None
        if form.first_name.data:
            student.first_name = form.first_name.data
        if form.last_name.data:
            student.last_name = form.last_name.data
        if form.vehicle_color.data:
            student.vehicle_color = form.vehicle_color.data
        if form.license_plate_number.data:
            student.license_plate_number = form.license_plate_number.data
        if form.license_plate_state.data:
            student.license_plate_state = form.license_plate_state.data
        if form.vehicle_year.data:
            student.vehicle_year = int(form.vehicle_year.data)
        if form.make.data:
            student.make = form.make.data
        if form.model.data:
            student.model = form.model.data
        if form.password.data:
            student.password = generate_password_hash(form.password.data)
        try:
            db.session.commit()
            flash('Info updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating student {current_user.email}: {str(e)}")
            flash(f'Error: {str(e)}', 'danger')
    tickets = Ticket.query.filter_by(student_id=current_user.id).all()
    appeals = Appeal.query.filter_by(student_id=current_user.id).all()
    return render_template('dashboard.html', student=current_user, tickets=tickets, appeals=appeals, form=form, stripe_public_key=app.config['STRIPE_PUBLIC_KEY'])

@app.route('/appeal_ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def appeal_ticket(ticket_id):
    if not isinstance(current_user, Student):
        flash('Unauthorized access. Only students can appeal tickets.', 'danger')
        return redirect(url_for('landing'))
    ticket = db.session.get(Ticket, ticket_id)
    if not ticket or ticket.student_id != current_user.id or ticket.status != 'Pending':
        flash('Cannot appeal this ticket.', 'danger')
        return redirect(url_for('student_dashboard'))
    form = AppealForm()
    if form.validate_on_submit():
        media_data = None
        media_type = None
        if form.media_data.data:
            file = form.media_data.data
            if allowed_file(file.filename):
                mime = magic.Magic(mime=True)
                file_type = mime.from_buffer(file.read(1024))
                file.seek(0)
                if file_type in ['image/heic', 'image/jpeg', 'image/png']:
                    media_data = file.read()
                    media_type = file_type
                else:
                    flash('Invalid file type. Allowed: .heic, .jpg, .png, .jpeg', 'danger')
                    return render_template('appeal.html', form=form, ticket=ticket)
            else:
                flash('Invalid file extension. Allowed: .heic, .jpg, .png, .jpeg', 'danger')
                return render_template('appeal.html', form=form, ticket=ticket)
        appeal = Appeal(
            student_id=current_user.id,
            ticket_id=ticket_id,
            appeal_text=form.appeal_text.data,
            status='pending',
            media_data=media_data,
            media_type=media_type
        )
        ticket.status = 'Appealed'
        try:
            db.session.add(appeal)
            db.session.commit()
            flash('Appeal submitted successfully!', 'success')
            return redirect(url_for('student_dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error submitting appeal for ticket {ticket_id}: {str(e)}")
            flash(f'Error: {str(e)}', 'danger')
    return render_template('appeal.html', form=form, ticket=ticket)

@app.route('/appeal_media/<int:appeal_id>')
@login_required
def appeal_media(appeal_id):
    appeal = db.session.get(Appeal, appeal_id)
    if not appeal or not appeal.media_data:
        app.logger.warning(f"Media not found for appeal ID: {appeal_id}")
        return "Media not found", 404
    return send_file(
        io.BytesIO(appeal.media_data),
        mimetype=appeal.media_type,
        as_attachment=False
    )

@app.route('/pay_ticket/<int:ticket_id>', methods=['POST'])
@login_required
def pay_ticket(ticket_id):
    if not isinstance(current_user, Student):
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('landing'))
    ticket = db.session.get(Ticket, ticket_id)
    if not ticket or ticket.student_id != current_user.id or ticket.status == 'Paid':
        flash('Invalid ticket or already paid.', 'danger')
        return redirect(url_for('student_dashboard'))
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'unit_amount': int(ticket.amount * 100),
                    'product_data': {
                        'name': f'Ticket {ticket.id}',
                        'description': ticket.reason,
                    },
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=url_for('payment_success', ticket_id=ticket.id, _external=True),
            cancel_url=url_for('student_dashboard', _external=True),
        )
        return jsonify({'session_id': session.id})
    except Exception as e:
        app.logger.error(f'Stripe payment error for ticket {ticket_id}: {str(e)}')
        flash(f'Payment error: {str(e)}', 'danger')
        return redirect(url_for('student_dashboard'))

@app.route('/payment_success/<int:ticket_id>')
@login_required
def payment_success(ticket_id):
    if not isinstance(current_user, Student):
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('landing'))
    ticket = db.session.get(Ticket, ticket_id)
    if ticket and ticket.student_id == current_user.id and ticket.status != 'Paid':
        ticket.status = 'Paid'
        try:
            db.session.commit()
            flash('Payment successful! Ticket marked as Paid.', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error marking ticket {ticket_id} as paid: {str(e)}")
            flash(f'Error: {str(e)}', 'danger')
    else:
        flash('Invalid ticket or already paid.', 'danger')
    return redirect(url_for('student_dashboard'))

@app.route('/logout')
@login_required
def logout():
    user_type = current_user.__class__.__name__
    user_id = current_user.get_id()
    logout_user()
    app.logger.info(f"{user_type} with ID {user_id} logged out successfully.")
    flash('Logged out successfully.', 'success')
    return redirect(url_for('landing'))

@app.route('/admin/signup', methods=['GET', 'POST'])
def admin_signup():
    return redirect(url_for('admin_login'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        if isinstance(current_user, Admin):
            if current_user.role == 'Admin':
                return redirect(url_for('admin_officer_dashboard'))
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('student_dashboard'))

    login_form = AdminLoginForm(prefix="login")  # Prefix to avoid field name conflicts
    signup_form = AdminSignupForm(prefix="signup")

    # Handle Login
    if request.method == 'POST' and 'submit' in request.form:
        app.logger.debug(f"POST request received for admin_login. Form data: {request.form}")
        
        if login_form.validate_on_submit():
            app.logger.debug("Login form validated successfully.")
            username = login_form.username.data
            password = login_form.password.data
            admin = Admin.query.get(username)
            submit_type = request.form.get('submit')

            if admin and check_password_hash(admin.password, password):
                if submit_type == 'officer_login':
                    if admin.role in ['Parking Officer', 'Admin Officer']:
                        login_user(admin, remember=True)
                        app.logger.info(f"{admin.role} {admin.username} logged in successfully.")
                        flash('Login successful!', 'success')
                        return redirect(url_for('admin_dashboard'))
                    else:
                        flash('Only Parking Officers or Admin Officers can use this login tab.', 'danger')
                        app.logger.warning(f"User {admin.username} with role {admin.role} attempted Officer login.")
                elif submit_type == 'admin_login':
                    if admin.role == 'Admin':
                        login_user(admin, remember=True)
                        app.logger.info(f"Admin {admin.username} logged in successfully.")
                        flash('Login successful!', 'success')
                        return redirect(url_for('admin_officer_dashboard'))
                    else:
                        flash('Only Admins can use this login tab.', 'danger')
                        app.logger.warning(f"User {admin.username} with role {admin.role} attempted Admin login.")
            else:
                flash('Invalid username or password.', 'danger')
                app.logger.warning(f"Failed login attempt for admin username: {username}")
        else:
            app.logger.warning("Login form validation failed.")
            for field, errors in login_form.errors.items():
                for error in errors:
                    flash(f"Error in {field}: {error}", 'danger')
                    app.logger.warning(f"Validation error in {field}: {error}")
            app.logger.debug(f"Login form errors: {login_form.errors}")

    # Handle Signup
    if request.method == 'POST' and 'signup_submit' in request.form:
        app.logger.debug(f"POST request received for admin signup. Form data: {request.form}")
        
        if signup_form.validate_on_submit():
            app.logger.debug("Signup form validated successfully.")
            officer_key = os.getenv('OFFICER_KEY', 'default-officer-key')
            if signup_form.officer_number.data != officer_key:
                flash('Invalid secret key.', 'danger')
            elif Admin.query.get(signup_form.username.data):
                flash('Username already exists.', 'danger')
            else:
                admin = Admin(
                    username=signup_form.username.data,
                    first_name=signup_form.first_name.data,
                    last_name=signup_form.last_name.data,
                    password=generate_password_hash(signup_form.password.data),
                    role=signup_form.role.data,
                    officer_number=signup_form.officer_number.data
                )
                try:
                    db.session.add(admin)
                    db.session.commit()
                    flash('Admin account created! Please log in.', 'success')
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f"Error creating admin {signup_form.username.data}: {str(e)}")
                    flash(f'Error: {str(e)}', 'danger')
        else:
            app.logger.warning("Signup form validation failed.")
            for field, errors in signup_form.errors.items():
                for error in errors:
                    flash(f"Error in {field}: {error}", 'danger')
                    app.logger.warning(f"Validation error in {field}: {error}")
            app.logger.debug(f"Signup form errors: {signup_form.errors}")

    return render_template('admin_login.html', login_form=login_form, signup_form=signup_form)

@app.route('/admin/edit_officer/<string:username>', methods=['POST'])
@login_required
def edit_officer(username):
    if not isinstance(current_user, Admin) or current_user.role != 'Admin Officer':
        flash('Unauthorized access. Only Admin Officers can edit officers.', 'danger')
        return redirect(url_for('admin_officer_dashboard' if isinstance(current_user, Admin) and current_user.role == 'Admin Officer' else 'admin_dashboard'))
    admin = Admin.query.get(username)
    if not admin:
        flash('Officer not found.', 'danger')
        return redirect(url_for('admin_officer_dashboard'))
    if admin.username == current_user.username:
        flash('You cannot edit your own account.', 'danger')
        return redirect(url_for('admin_officer_dashboard'))
    admin.first_name = request.form['first_name']
    admin.last_name = request.form['last_name']
    admin.role = request.form['role']
    admin.officer_number = request.form['officer_number'] or None
    if request.form['password']:
        admin.password = generate_password_hash(request.form['password'])
    try:
        db.session.commit()
        flash(f'Officer {username} updated successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating officer {username}: {str(e)}")
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('admin_officer_dashboard'))

@app.route('/admin/delete_officer/<string:username>', methods=['POST'])
@login_required
def delete_officer(username):
    if not isinstance(current_user, Admin) or current_user.role != 'Admin Officer':
        flash('Unauthorized access. Only Admin Officers can delete officers.', 'danger')
        return redirect(url_for('admin_officer_dashboard' if isinstance(current_user, Admin) and current_user.role == 'Admin Officer' else 'admin_dashboard'))
    admin = Admin.query.get(username)
    if not admin:
        flash('Officer not found.', 'danger')
        return redirect(url_for('admin_officer_dashboard'))
    if admin.username == current_user.username:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_officer_dashboard'))
    try:
        db.session.delete(admin)
        db.session.commit()
        flash(f'Officer {username} deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting officer {username}: {str(e)}")
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('admin_officer_dashboard'))

@app.route('/admin/create_student', methods=['POST'])
@login_required
def create_student():
    if not isinstance(current_user, Admin) or current_user.role != 'Admin Officer':
        flash('Unauthorized access. Only Admin Officers can create students.', 'danger')
        return redirect(url_for('admin_officer_dashboard' if isinstance(current_user, Admin) and current_user.role == 'Admin Officer' else 'admin_dashboard'))
    form = SignupForm()
    if form.validate_on_submit():
        student = Student(
            email=form.email.data,
            permit_number=form.permit_number.data,
            phone_number=form.phone_number.data,
            permit_type=form.permit_type.data,
            residence=form.residence.data,
            first_name=form.first_name.data or "Unknown",
            last_name=form.last_name.data or "Unknown",
            vehicle_color=form.vehicle_color.data,
            license_plate_number=form.license_plate_number.data,
            license_plate_state=form.license_plate_state.data,
            vehicle_year=form.vehicle_year.data,
            make=form.make.data,
            model=form.model.data,
            password=generate_password_hash(form.password.data)
        )
        try:
            db.session.add(student)
            db.session.commit()
            flash(f'Student {form.email.data} created successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating student {form.email.data}: {str(e)}")
            flash(f'Error: {str(e)}', 'danger')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                app.logger.warning(f"Validation error in {field}: {error}")
                flash(f"Error in {field}: {error}", 'danger')
    return redirect(url_for('admin_officer_dashboard'))

@app.route('/admin/edit_student/<int:student_id>', methods=['POST'])
@login_required
def edit_student(student_id):
    if not isinstance(current_user, Admin) or current_user.role != 'Admin Officer':
        flash('Unauthorized access. Only Admin Officers can edit students.', 'danger')
        return redirect(url_for('admin_officer_dashboard' if isinstance(current_user, Admin) and current_user.role == 'Admin Officer' else 'admin_dashboard'))
    student = db.session.get(Student, student_id)
    if not student:
        flash('Student not found.', 'danger')
        return redirect(url_for('admin_officer_dashboard'))
    student.email = request.form['email']
    student.permit_number = request.form['permit_number']
    student.phone_number = request.form['phone_number']
    student.permit_type = request.form['permit_type']
    student.residence = request.form['residence'] or None
    student.first_name = request.form['first_name'] or "Unknown"
    student.last_name = request.form['last_name'] or "Unknown"
    student.vehicle_color = request.form['vehicle_color']
    student.license_plate_number = request.form['license_plate_number']
    student.license_plate_state = request.form['license_plate_state']
    student.vehicle_year = int(request.form['vehicle_year'])
    student.make = request.form['make']
    student.model = request.form['model']
    if request.form['password']:
        student.password = generate_password_hash(request.form['password'])
    try:
        db.session.commit()
        flash(f'Student {student.email} updated successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating student {student.email}: {str(e)}")
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('admin_officer_dashboard'))

@app.route('/admin/delete_student/<int:student_id>', methods=['POST'])
@login_required
def delete_student(student_id):
    if not isinstance(current_user, Admin) or current_user.role != 'Admin Officer':
        flash('Unauthorized access. Only Admin Officers can delete students.', 'danger')
        return redirect(url_for('admin_officer_dashboard' if isinstance(current_user, Admin) and current_user.role == 'Admin Officer' else 'admin_dashboard'))
    student = db.session.get(Student, student_id)
    if not student:
        flash('Student not found.', 'danger')
        return redirect(url_for('admin_officer_dashboard'))
    try:
        db.session.delete(student)
        db.session.commit()
        flash('Student deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting student ID {student_id}: {str(e)}")
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('admin_officer_dashboard'))

@app.route('/admin/delete_ticket/<int:ticket_id>', methods=['POST'])
@login_required
def delete_ticket(ticket_id):
    if not isinstance(current_user, Admin):
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('admin_officer_dashboard' if isinstance(current_user, Admin) and current_user.role == 'Admin Officer' else 'admin_dashboard'))
    ticket = db.session.get(Ticket, ticket_id)
    if not ticket:
        flash('Ticket not found.', 'danger')
        return redirect(url_for('admin_officer_dashboard' if isinstance(current_user, Admin) and current_user.role == 'Admin Officer' else 'admin_dashboard'))
    try:
        db.session.delete(ticket)
        db.session.commit()
        flash('Ticket deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting ticket {ticket_id}: {str(e)}")
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('admin_officer_dashboard' if isinstance(current_user, Admin) and current_user.role == 'Admin Officer' else 'admin_dashboard'))

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if not isinstance(current_user, Admin) or current_user.role not in ['Parking Officer', 'Admin Officer']:
        flash('Unauthorized access. Only Parking Officers or Admin Officers can view this dashboard.', 'danger')
        return redirect(url_for('admin_login'))
    
    ticket_form = TicketForm()
    search_form = SearchForm()
    edit_forms = {ticket.id: EditTicketForm(obj=ticket) for ticket in Ticket.query.all()}

    if request.method == 'POST' and 'ticket_id' in request.form:
        ticket_id = request.form['ticket_id']
        form = edit_forms[int(ticket_id)]
        if form.validate_on_submit():
            ticket = db.session.get(Ticket, int(ticket_id))
            # Officers can only view tickets, not edit (remove edit logic)
            flash('You do not have permission to edit tickets.', 'danger')
            return redirect(url_for('admin_dashboard'))

    if ticket_form.validate_on_submit():
        student = Student.query.get(int(ticket_form.student_id.data))
        if not student:
            flash('Student not found.', 'danger')
            return redirect(url_for('admin_dashboard'))
        ticket = Ticket(
            student_id=student.id,
            admin_username=current_user.username,
            reason=ticket_form.reason.data,
            amount=ticket_form.amount.data,
            status='Pending'
        )
        try:
            db.session.add(ticket)
            db.session.commit()
            flash('Ticket issued successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error issuing ticket: {str(e)}")
            flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST' and 'appeal_action' in request.form:
        appeal_id = int(request.form['appeal_id'])
        action = request.form['appeal_action']
        appeal = db.session.get(Appeal, appeal_id)
        ticket = db.session.get(Ticket, appeal.ticket_id) if appeal else None
        if appeal and ticket:
            appeal.status = action.lower()
            appeal.decision_date = datetime.utcnow()
            if action.lower() == 'approved':
                ticket.status = 'Paid'
                ticket.amount = 0.0  # Waive fine
            elif action.lower() == 'rejected':
                ticket.status = 'Pending'
            try:
                db.session.commit()
                flash(f'Appeal {appeal_id} {action.lower()} successfully.', 'success')
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error processing appeal {appeal_id}: {str(e)}")
                flash(f'Error: {str(e)}', 'danger')
        else:
            flash('Invalid appeal.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if search_form.validate_on_submit():
        first_name = search_form.first_name.data
        last_name = search_form.last_name.data
        phone_number = search_form.phone_number.data
        make = search_form.make.data
        model = search_form.model.data
        vehicle_color = search_form.vehicle_color.data
        permit_number = search_form.permit_number.data
        license_plate_number = search_form.license_plate_number.data

        query = Student.query
        if first_name:
            query = query.filter(Student.first_name.ilike(f'%{first_name}%'))
        if last_name:
            query = query.filter(Student.last_name.ilike(f'%{last_name}%'))
        if phone_number:
            query = query.filter(Student.phone_number.ilike(f'%{phone_number}%'))
        if make:
            query = query.filter(Student.make.ilike(f'%{make}%'))
        if model:
            query = query.filter(Student.model.ilike(f'%{model}%'))
        if vehicle_color:
            query = query.filter(Student.vehicle_color.ilike(f'%{vehicle_color}%'))
        if permit_number:
            query = query.filter(Student.permit_number.ilike(f'%{permit_number}%'))
        if license_plate_number:
            query = query.filter(Student.license_plate_number.ilike(f'%{license_plate_number}%'))
        
        students = query.all()
        if not students:
            flash('No students found with the provided search criteria.', 'warning')
    else:
        students = Student.query.all()

    all_tickets = Ticket.query.all()
    all_appeals = Appeal.query.all()
    return render_template('admin_dashboard.html',
                          ticket_form=ticket_form,
                          search_form=search_form,
                          students=students,
                          all_tickets=all_tickets,
                          edit_forms=edit_forms,
                          all_appeals=all_appeals)

@app.route('/admin_officer_dashboard', methods=['GET', 'POST'])
@login_required
def admin_officer_dashboard():
    if not isinstance(current_user, Admin) or current_user.role != 'Admin':
        flash('Unauthorized access. Only Admins can view this dashboard.', 'danger')
        return redirect(url_for('admin_login'))
    
    ticket_form = TicketForm()
    create_student_form = SignupForm()
    search_form = SearchForm()
    edit_forms = {ticket.id: EditTicketForm(obj=ticket) for ticket in Ticket.query.all()}
    user_form = UserForm()
    report_form = ReportForm()
    report_data = None

    if request.method == 'POST' and 'ticket_id' in request.form:
        ticket_id = request.form['ticket_id']
        form = edit_forms[int(ticket_id)]
        if form.validate_on_submit():
            ticket = db.session.get(Ticket, int(ticket_id))
            ticket.reason = form.reason.data
            ticket.amount = form.amount.data
            ticket.status = form.status.data
            try:
                db.session.commit()
                flash('Ticket updated successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error updating ticket {ticket_id}: {str(e)}")
                flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('admin_officer_dashboard'))

    if ticket_form.validate_on_submit():
        student = Student.query.get(int(ticket_form.student_id.data))
        if not student:
            flash('Student not found.', 'danger')
            return redirect(url_for('admin_officer_dashboard'))
        ticket = Ticket(
            student_id=student.id,
            admin_username=current_user.username,
            reason=ticket_form.reason.data,
            amount=ticket_form.amount.data,
            status='Pending'
        )
        try:
            db.session.add(ticket)
            db.session.commit()
            flash('Ticket issued successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error issuing ticket: {str(e)}")
            flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('admin_officer_dashboard'))

    if request.method == 'POST' and 'appeal_action' in request.form:
        appeal_id = int(request.form['appeal_id'])
        action = request.form['appeal_action']
        appeal = db.session.get(Appeal, appeal_id)
        ticket = db.session.get(Ticket, appeal.ticket_id) if appeal else None
        if appeal and ticket:
            appeal.status = action.lower()
            appeal.decision_date = datetime.utcnow()
            if action.lower() == 'approved':
                ticket.status = 'Paid'
                ticket.amount = 0.0  # Waive fine
            elif action.lower() == 'rejected':
                ticket.status = 'Pending'
            try:
                db.session.commit()
                flash(f'Appeal {appeal_id} {action.lower()} successfully.', 'success')
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error processing appeal {appeal_id}: {str(e)}")
                flash(f'Error: {str(e)}', 'danger')
        else:
            flash('Invalid appeal.', 'danger')
        return redirect(url_for('admin_officer_dashboard'))

    if create_student_form.validate_on_submit():
        student = Student(
            email=create_student_form.email.data,
            permit_number=create_student_form.permit_number.data,
            phone_number=create_student_form.phone_number.data,
            permit_type=create_student_form.permit_type.data,
            residence=create_student_form.residence.data,
            first_name=create_student_form.first_name.data or "Unknown",
            last_name=create_student_form.last_name.data or "Unknown",
            vehicle_color=create_student_form.vehicle_color.data,
            license_plate_number=create_student_form.license_plate_number.data,
            license_plate_state=create_student_form.license_plate_state.data,
            vehicle_year=create_student_form.vehicle_year.data,
            make=create_student_form.make.data,
            model=create_student_form.model.data,
            password=generate_password_hash(create_student_form.password.data)
        )
        try:
            db.session.add(student)
            db.session.commit()
            flash('Student created successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating student {create_student_form.email.data}: {str(e)}")
            flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('admin_officer_dashboard'))

    if request.method == 'POST' and 'action' in request.form and request.form['action'] == 'create_user':
        if user_form.validate_on_submit():
            admin = Admin(
                username=user_form.username.data,
                password=generate_password_hash(user_form.password.data),
                role=user_form.role.data,
                officer_number=user_form.officer_number.data or None
            )
            try:
                db.session.add(admin)
                db.session.commit()
                flash(f'Admin {admin.username} created successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error creating admin {user_form.username.data}: {str(e)}")
                flash(f'Error: {str(e)}', 'danger')
        else:
            for field, errors in user_form.errors.items():
                for error in errors:
                    flash(f"Error in {field}: {error}", 'danger')
        return redirect(url_for('admin_officer_dashboard'))

    if request.method == 'POST' and 'action' in request.form and request.form['action'] == 'delete_user':
        user_id = request.form.get('user_id')
        admin = db.session.get(Admin, user_id)
        if not admin:
            flash('Admin not found.', 'danger')
        elif admin.username == current_user.username:
            flash('You cannot delete your own account.', 'danger')
        else:
            try:
                db.session.delete(admin)
                db.session.commit()
                flash(f'Admin {admin.username} deleted successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error deleting admin {user_id}: {str(e)}")
                flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('admin_officer_dashboard'))

    if request.method == 'POST' and 'action' in request.form and request.form['action'] == 'generate_report':
        if report_form.validate_on_submit():
            report_type = report_form.report_type.data
            date_range = report_form.date_range.data

            today = datetime.utcnow()
            if date_range == 'last_7_days':
                start_date = today - timedelta(days=7)
            elif date_range == 'last_30_days':
                start_date = today - timedelta(days=30)
            else:  # last_year
                start_date = today - timedelta(days=365)

            if report_type == 'tickets_issued':
                tickets = Ticket.query.filter(Ticket.created_at >= start_date).all()
                report_data = {
                    "Total Tickets Issued": len(tickets),
                    "Pending Tickets": len([t for t in tickets if t.status == 'Pending']),
                    "Paid Tickets": len([t for t in tickets if t.status == 'Paid']),
                    "Appealed Tickets": len([t for t in tickets if t.status == 'Appealed'])
                }
            elif report_type == 'appeals_status':
                appeals = Appeal.query.filter(Appeal.created_at >= start_date).all()
                report_data = {
                    "Total Appeals": len(appeals),
                    "Pending Appeals": len([a for a in appeals if a.status == 'pending']),
                    "Approved Appeals": len([a for a in appeals if a.status == 'approved']),
                    "Rejected Appeals": len([a for a in appeals if a.status == 'rejected'])
                }
            elif report_type == 'revenue':
                paid_tickets = Ticket.query.filter(Ticket.status == 'Paid', Ticket.created_at >= start_date).all()
                total_revenue = sum(t.amount for t in paid_tickets if t.amount is not None)
                report_data = {
                    "Total Revenue": f"${total_revenue:.2f}",
                    "Number of Paid Tickets": len(paid_tickets)
                }
            flash('Report generated successfully!', 'success')
        else:
            for field, errors in report_form.errors.items():
                for error in errors:
                    flash(f"Error in {field}: {error}", 'danger')

    if search_form.validate_on_submit():
        first_name = search_form.first_name.data
        last_name = search_form.last_name.data
        phone_number = search_form.phone_number.data
        make = search_form.make.data
        model = search_form.model.data
        vehicle_color = search_form.vehicle_color.data
        permit_number = search_form.permit_number.data
        license_plate_number = search_form.license_plate_number.data

        query = Student.query
        if first_name:
            query = query.filter(Student.first_name.ilike(f'%{first_name}%'))
        if last_name:
            query = query.filter(Student.last_name.ilike(f'%{last_name}%'))
        if phone_number:
            query = query.filter(Student.phone_number.ilike(f'%{phone_number}%'))
        if make:
            query = query.filter(Student.make.ilike(f'%{make}%'))
        if model:
            query = query.filter(Student.model.ilike(f'%{model}%'))
        if vehicle_color:
            query = query.filter(Student.vehicle_color.ilike(f'%{vehicle_color}%'))
        if permit_number:
            query = query.filter(Student.permit_number.ilike(f'%{permit_number}%'))
        if license_plate_number:
            query = query.filter(Student.license_plate_number.ilike(f'%{license_plate_number}%'))
        
        students = query.all()
        if not students:
            flash('No students found with the provided search criteria.', 'warning')
    else:
        students = Student.query.all()

    all_users = Admin.query.all()
    all_tickets = Ticket.query.all()
    all_appeals = Appeal.query.all()
    all_students = Student.query.all()

    return render_template('admin_officer_dashboard.html',
                          students=students,
                          ticket_form=ticket_form,
                          create_student_form=create_student_form,
                          search_form=search_form,
                          all_tickets=all_tickets,
                          edit_forms=edit_forms,
                          all_appeals=all_appeals,
                          all_users=all_users,
                          all_students=all_students,
                          user_form=user_form,
                          report_form=report_form,
                          report_data=report_data)