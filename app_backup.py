from upike_parking import app, db  # Updated import
from upike_parking.models import Admin  # Updated import
from werkzeug.security import generate_password_hash
import os

with app.app_context():
    db.create_all()
    if not db.session.get(Admin, 'PSO001'):
        default_admin = Admin(
            admin_id='PSO001',
            first_name='Admin',
            last_name='User',
            password=generate_password_hash('admin123', method='pbkdf2:sha256')
        )
        db.session.add(default_admin)
        db.session.commit()

def create_app():
    return app

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5050)))