import bcrypt
import json
import time
import sys
from pathlib import Path
from cryptography.fernet import Fernet
import keyring
import logging

class UserManager:
    def __init__(self):
        self.app_name = "Galdr"
        self.users_file = Path.home() / ".galdr" / "users.json"
        self.config_dir = Path.home() / ".galdr" / "users"
        self.logger = logging.getLogger(__name__)
        self.ensure_directories()
    
    def ensure_directories(self):
        """Create necessary directories for user data"""
        self.users_file.parent.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    def load_users(self):
        """Load users from encrypted storage"""
        try:
            if self.users_file.exists():
                with open(self.users_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load users: {e}")
        return {}
    
    def save_users(self, users):
        """Save users to encrypted storage"""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(users, f, indent=2)
            # Secure file permissions (Unix-like systems)
            if sys.platform != "win32":
                self.users_file.chmod(0o600)
        except Exception as e:
            self.logger.error(f"Failed to save users: {e}")
    
    def create_user(self, username, password, email, auth_type="local"):
        """Create new user with encrypted storage"""
        if self.user_exists(username):
            raise ValueError(f"User {username} already exists")
        
        # Hash password with bcrypt for local auth
        password_hash = None
        if auth_type == "local":
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        
        # Create user directory
        user_dir = self.config_dir / username
        user_dir.mkdir(exist_ok=True)
        
        # Store user credentials
        users = self.load_users()
        users[username] = {
            'password_hash': password_hash,
            'email': email,
            'auth_type': auth_type,
            'created_at': time.time(),
            'last_login': None,
            'user_dir': str(user_dir)
        }
        self.save_users(users)
        
        # Initialize user's configuration
        self.init_user_config(username)
        self.logger.info(f"Created user: {username} ({auth_type})")
        
        return True
    
    def authenticate(self, username, password):
        """Authenticate user credentials"""
        users = self.load_users()
        if username not in users:
            return False
        
        user = users[username]
        
        # Local authentication
        if user['auth_type'] == 'local':
            if not user.get('password_hash'):
                return False
            stored_hash = user['password_hash'].encode()
            if bcrypt.checkpw(password.encode(), stored_hash):
                self.update_last_login(username)
                return True
        
        return False
    
    def authenticate_sso(self, username, email, provider, provider_id):
        """Authenticate SSO user"""
        users = self.load_users()
        
        # Check if user exists with SSO
        if username in users:
            user = users[username]
            if (user['auth_type'] == f'sso_{provider}' and 
                user.get('provider_id') == provider_id):
                self.update_last_login(username)
                return True
        else:
            # Create new SSO user
            try:
                self.create_sso_user(username, email, provider, provider_id)
                return True
            except Exception as e:
                self.logger.error(f"Failed to create SSO user: {e}")
                return False
        
        return False
    
    def create_sso_user(self, username, email, provider, provider_id):
        """Create new SSO user"""
        user_dir = self.config_dir / username
        user_dir.mkdir(exist_ok=True)
        
        users = self.load_users()
        users[username] = {
            'password_hash': None,
            'email': email,
            'auth_type': f'sso_{provider}',
            'provider_id': provider_id,
            'created_at': time.time(),
            'last_login': time.time(),
            'user_dir': str(user_dir)
        }
        self.save_users(users)
        self.init_user_config(username)
    
    def user_exists(self, username):
        """Check if user exists"""
        users = self.load_users()
        return username in users
    
    def update_last_login(self, username):
        """Update user's last login timestamp"""
        users = self.load_users()
        if username in users:
            users[username]['last_login'] = time.time()
            self.save_users(users)
    
    def init_user_config(self, username):
        """Initialize user's configuration directory"""
        user_dir = self.config_dir / username
        
        # Create subdirectories
        (user_dir / "databases").mkdir(exist_ok=True)
        (user_dir / "exports").mkdir(exist_ok=True)
        (user_dir / "logs").mkdir(exist_ok=True)
        (user_dir / "tech_patterns").mkdir(exist_ok=True)
        
        # Copy default tech patterns
        default_patterns = Path("data/tech_patterns.yaml")
        user_patterns = user_dir / "tech_patterns" / "tech_patterns.yaml"
        
        if default_patterns.exists() and not user_patterns.exists():
            import shutil
            shutil.copy2(default_patterns, user_patterns)
    
    def get_user_info(self, username):
        """Get user information"""
        users = self.load_users()
        return users.get(username)
    
    def delete_user(self, username):
        """Delete user and all associated data"""
        users = self.load_users()
        if username in users:
            # Remove user directory
            user_dir = Path(users[username]['user_dir'])
            if user_dir.exists():
                import shutil
                shutil.rmtree(user_dir)
            
            # Remove from users file
            del users[username]
            self.save_users(users)
            
            self.logger.info(f"Deleted user: {username}")
            return True
        return False
