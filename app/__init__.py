from flask import Flask
from .config import Config
from .session_store import SessionStore

session_store = SessionStore()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Store reference to session store
    app.session_store = session_store
    
    from .routes import main_bp
    app.register_blueprint(main_bp)
    
    return app
