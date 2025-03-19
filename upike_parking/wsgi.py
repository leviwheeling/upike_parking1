# wsgi.py
import sys
import os
from gevent.pywsgi import WSGIServer  # For serving the app with gevent (optional, can be replaced with gunicorn)
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add the project directory to the Python path
project_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_dir)

logger.info(f"Added project directory to sys.path: {project_dir}")

try:
    from upike_parking import app, db
    logger.info("Successfully imported app and db from upike_parking")
except ImportError as e:
    logger.error(f"Error importing app and db: {e}")
    raise

try:
    from upike_parking.models import Admin
    logger.info("Successfully imported Admin from upike_parking.models")
except ImportError as e:
    logger.error(f"Error importing Admin: {e}")
    raise

try:
    from werkzeug.security import generate_password_hash
    logger.info("Successfully imported generate_password_hash from werkzeug.security")
except ImportError as e:
    logger.error(f"Error importing generate_password_hash: {e}")
    raise

# Application factory for WSGI
application = app

if __name__ == '__main__':
    logger.info("Running app directly for development (not recommended for production)")
    app.run(debug=True, host='0.0.0.0', port=5000)
else:
    logger.info("WSGI application initialized for production")
    # Optionally, you can start a WSGI server here if not using Gunicorn
    # Example with gevent (uncomment if needed):
    # http_server = WSGIServer(('0.0.0.0', int(os.environ.get('PORT', 5000))), application)
    # http_server.serve_forever()