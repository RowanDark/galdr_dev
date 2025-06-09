import json
import keyring
import sys
from pathlib import Path
from cryptography.fernet import Fernet
import base64
import os

class SecureUserConfig:
    def __init__(self, username):
        self.username = username
        self.app_name = "Galdr"
        self.user_dir = Path.home() / ".galdr" / "users" / username
        self.config_file = self.user_dir / "config.json"
        self.db_file = self.user_dir / "databases" / "crawl_results.db"
        self.encryption_key = self._get_or_create_key()
    
    def _get_or_create_key(self):
        """Get or create encryption key for user data"""
        try:
            # Try to get existing key from keyring
            key_b64 = keyring.get_password(self.app_name, f"{self.username}_key")
            if key_b64:
                return base64.b64decode(key_b64.encode())
            else:
                # Create new key
                key = Fernet.generate_key()
                keyring.set_password(self.app_name, f"{self.username}_key", 
                                   base64.b64encode(key).decode())
                return key
        except Exception:
            # Fallback to file-based key (less secure)
            key_file = self.user_dir / ".key"
            if key_file.exists():
                return key_file.read_bytes()
            else:
                key = Fernet.generate_key()
                key_file.write_bytes(key)
                if sys.platform != "win32":
                    key_file.chmod(0o600)
                return key
    
    def save_config(self, config_data):
        """Save user configuration"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
        except Exception as e:
            print(f"Failed to save config: {e}")
    
    def load_config(self):
        """Load user configuration"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Failed to load config: {e}")
        return {}
    
    def save_email_config(self, smtp_config):
        """Encrypt and save email configuration"""
        try:
            # Encrypt sensitive email data
            fernet = Fernet(self.encryption_key)
            encrypted_config = {}
            
            for key, value in smtp_config.items():
                if key in ['password', 'username']:  # Encrypt sensitive fields
                    encrypted_config[key] = fernet.encrypt(str(value).encode()).decode()
                else:
                    encrypted_config[key] = value
            
            # Save to keyring or secure storage
            keyring.set_password(self.app_name, f"{self.username}_email", 
                               json.dumps(encrypted_config))
            return True
        except Exception as e:
            print(f"Failed to save email config: {e}")
            return False
    
    def load_email_config(self):
        """Load and decrypt email configuration"""
        try:
            encrypted_data = keyring.get_password(self.app_name, f"{self.username}_email")
            if not encrypted_data:
                return {}
            
            encrypted_config = json.loads(encrypted_data)
            fernet = Fernet(self.encryption_key)
            
            decrypted_config = {}
            for key, value in encrypted_config.items():
                if key in ['password', 'username']:  # Decrypt sensitive fields
                    decrypted_config[key] = fernet.decrypt(value.encode()).decode()
                else:
                    decrypted_config[key] = value
            
            return decrypted_config
        except Exception as e:
            print(f"Failed to load email config: {e}")
            return {}
    
    def save_totp_secret(self, secret):
        """Save TOTP secret securely"""
        try:
            fernet = Fernet(self.encryption_key)
            encrypted_secret = fernet.encrypt(secret.encode()).decode()
            keyring.set_password(self.app_name, f"{self.username}_totp", encrypted_secret)
            return True
        except Exception as e:
            print(f"Failed to save TOTP secret: {e}")
            return False
    
    def load_totp_secret(self):
        """Load TOTP secret"""
        try:
            encrypted_secret = keyring.get_password(self.app_name, f"{self.username}_totp")
            if not encrypted_secret:
                return None
            
            fernet = Fernet(self.encryption_key)
            return fernet.decrypt(encrypted_secret.encode()).decode()
        except Exception as e:
            print(f"Failed to load TOTP secret: {e}")
            return None
    
    def save_2fa_settings(self, settings):
        """Save 2FA preferences"""
        config = self.load_config()
        config['2fa_settings'] = settings
        self.save_config(config)
    
    def load_2fa_settings(self):
        """Load 2FA preferences"""
        config = self.load_config()
        return config.get('2fa_settings', {
            'enabled': False,
            'method': 'totp',  # 'totp' or 'sms'
            'phone_number': '',
            'backup_codes': []
        })
    
    def save_phone_number(self, phone_number):
        """Save encrypted phone number"""
        try:
            fernet = Fernet(self.encryption_key)
            encrypted_phone = fernet.encrypt(phone_number.encode()).decode()
            keyring.set_password(self.app_name, f"{self.username}_phone", encrypted_phone)
            return True
        except Exception as e:
            print(f"Failed to save phone number: {e}")
            return False
    
    def load_phone_number(self):
        """Load decrypted phone number"""
        try:
            encrypted_phone = keyring.get_password(self.app_name, f"{self.username}_phone")
            if not encrypted_phone:
                return None
            
            fernet = Fernet(self.encryption_key)
            return fernet.decrypt(encrypted_phone.encode()).decode()
        except Exception as e:
            print(f"Failed to load phone number: {e}")
            return None
    
    def get_user_database(self):
        """Return path to user's private database"""
        self.db_file.parent.mkdir(parents=True, exist_ok=True)
        return str(self.db_file)
    
    def get_tech_patterns_path(self):
        """Return path to user's tech patterns file"""
        return str(self.user_dir / "tech_patterns" / "tech_patterns.yaml")
    
    def get_exports_dir(self):
        """Return path to user's exports directory"""
        exports_dir = self.user_dir / "exports"
        exports_dir.mkdir(exist_ok=True)
        return str(exports_dir)
    
    def get_logs_dir(self):
        """Return path to user's logs directory"""
        logs_dir = self.user_dir / "logs"
        logs_dir.mkdir(exist_ok=True)
        return str(logs_dir)
