import getpass
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timedelta
import re

class Session:
    """Session management class"""
    def __init__(self, username, role):
        self.username = username
        self.role = role
        self.login_time = datetime.now()
        self.last_activity = datetime.now()
        self.is_active = True
    
    def refresh(self):
        """Refresh session activity"""
        self.last_activity = datetime.now()
    
    def is_expired(self, timeout_minutes=30):
        """Check if session expired"""
        if not self.is_active:
            return True
        elapsed = (datetime.now() - self.last_activity).total_seconds() / 60
        return elapsed > timeout_minutes

class SecureLogin:
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.max_attempts = 3
        self.locked_until = {}
        self.load_users()
        self.create_protected_file()
    
    def create_protected_file(self):
        """Create protected config file"""
        if not os.path.exists("users.json"):
            with open("users.json", "w") as f:
                json.dump({}, f)
    
    def load_users(self):
        """Load users with additional security data"""
        try:
            with open("users.json", "r") as f:
                self.users = json.load(f)
                
            # Add missing fields for existing users
            for user in self.users:
                if "failed_attempts" not in self.users[user]:
                    self.users[user]["failed_attempts"] = 0
                if "locked" not in self.users[user]:
                    self.users[user]["locked"] = False
                if "last_login" not in self.users[user]:
                    self.users[user]["last_login"] = None
                    
        except FileNotFoundError:
            # Create default admin
            self.users = {
                "admin": {
                    "password": hashlib.sha256("Admin@2024".encode()).hexdigest(),
                    "role": "admin",
                    "email": "admin@system.com",
                    "failed_attempts": 0,
                    "locked": False,
                    "last_login": None
                }
            }
            self.save_users()
    
    def save_users(self):
        """Save users to file"""
        with open("users.json", "w") as f:
            json.dump(self.users, f, indent=2, default=str)
    
    def validate_password(self, password):
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r"\d", password):
            return False, "Password must contain at least one number"
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character"
        return True, "Password is strong"
    
    def validate_email(self, email):
        """Validate email format"""
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(pattern, email) is not None
    
    def is_account_locked(self, username):
        """Check if account is locked"""
        if username in self.users:
            if self.users[username].get("locked", False):
                return True
            if self.users[username].get("failed_attempts", 0) >= self.max_attempts:
                self.users[username]["locked"] = True
                self.save_users()
                return True
        return False
    
    def register(self):
        """Enhanced registration"""
        print("\n" + "="*50)
        print("         📝 REGISTRATION")
        print("="*50)
        
        # Username
        while True:
            username = input("Choose username (min 3 chars): ").strip()
            if len(username) < 3:
                print("❌ Username must be at least 3 characters!")
                continue
            if username in self.users:
                print("❌ Username already exists!")
                continue
            if not re.match(r"^[a-zA-Z0-9_]+$", username):
                print("❌ Username can only contain letters, numbers, and underscore!")
                continue
            break
        
        # Email
        while True:
            email = input("Email address: ").strip()
            if not self.validate_email(email):
                print("❌ Invalid email format!")
                continue
            # Check if email already used
            for user in self.users.values():
                if user.get("email") == email:
                    print("❌ Email already registered!")
                    continue
            break
        
        # Password
        while True:
            password = getpass.getpass("Choose password: ")
            valid, message = self.validate_password(password)
            if not valid:
                print(f"❌ {message}")
                continue
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("❌ Passwords don't match!")
                continue
            break
        
        # Save user
        self.users[username] = {
            "password": hashlib.sha256(password.encode()).hexdigest(),
            "role": "user",
            "email": email,
            "failed_attempts": 0,
            "locked": False,
            "last_login": None,
            "created_at": datetime.now().isoformat()
        }
        self.save_users()
        print(f"\n✅ User '{username}' registered successfully!")
        return True
    
    def login(self):
        """Enhanced login with session management"""
        print("\n" + "="*50)
        print("         🔐 LOGIN")
        print("="*50)
        
        username = input("Username: ").strip()
        
        if username not in self.users:
            print("❌ Invalid credentials!")
            time.sleep(1)  # Prevent timing attacks
            return False
        
        # Check if account is locked
        if self.is_account_locked(username):
            print("❌ Account is locked! Please contact administrator.")
            return False
        
        # Check if already logged in
        if username in self.sessions:
            session = self.sessions[username]
            if session.is_active:
                print(f"⚠️  User '{username}' is already logged in!")
                choice = input("Force login? (y/n): ").lower()
                if choice != 'y':
                    return False
                else:
                    # End existing session
                    self.sessions[username].is_active = False
        
        # Login attempts
        password = getpass.getpass("Password: ")
        hashed = hashlib.sha256(password.encode()).hexdigest()
        
        if hashed == self.users[username]["password"]:
            # Successful login
            self.users[username]["failed_attempts"] = 0
            self.users[username]["locked"] = False
            self.users[username]["last_login"] = datetime.now().isoformat()
            
            # Create session
            self.sessions[username] = Session(username, self.users[username]["role"])
            
            self.save_users()
            print(f"\n✅ Welcome back, {username}!")
            print(f"📅 Last login: {self.users[username]['last_login']}")
            return True
        else:
            # Failed login attempt
            self.users[username]["failed_attempts"] = self.users[username].get("failed_attempts", 0) + 1
            remaining = self.max_attempts - self.users[username]["failed_attempts"]
            
            if remaining <= 0:
                self.users[username]["locked"] = True
                print("❌ Account locked due to too many failed attempts!")
            else:
                print(f"❌ Incorrect password! {remaining} attempts remaining")
            
            self.save_users()
            return False
    
    def logout(self, username=None):
        """Logout user and close session"""
        if not username:
            username = self.get_current_user()
        
        if username and username in self.sessions:
            self.sessions[username].is_active = False
            del self.sessions[username]
            print(f"👋 Goodbye, {username}!")
            return True
        return False
    
    def get_current_user(self):
        """Get the first active session user (simplified)"""
        for username, session in self.sessions.items():
            if session.is_active:
                return username
        return None
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions"""
        expired = []
        for username, session in self.sessions.items():
            if session.is_expired():
                expired.append(username)
        
        for username in expired:
            self.sessions[username].is_active = False
            del self.sessions[username]
            print(f"⏰ Session expired for: {username}")
    
    def admin_panel(self):
        """Admin panel for user management"""
        if not self.get_current_user():
            print("❌ Please login as admin!")
            return
        
        current = self.get_current_user()
        if self.users[current]["role"] != "admin":
            print("❌ Admin privileges required!")
            return
        
        while True:
            print("\n" + "="*50)
            print("         👑 ADMIN PANEL")
            print("="*50)
            print("1. List all users")
            print("2. Unlock user account")
            print("3. Delete user")
            print("4. Change user role")
            print("5. View system logs")
            print("6. Back to main menu")
            
            choice = input("\nChoose option (1-6): ").strip()
            
            if choice == "1":
                print("\n📋 USER LIST:")
                for username, data in self.users.items():
                    status = "🔒 LOCKED" if data.get("locked") else "✅ ACTIVE"
                    role = data.get("role", "user")
                    last_login = data.get("last_login", "Never")
                    print(f"  • {username} [{role}] - {status}")
                    print(f"    Last login: {last_login}")
            
            elif choice == "2":
                username = input("Username to unlock: ").strip()
                if username in self.users:
                    self.users[username]["locked"] = False
                    self.users[username]["failed_attempts"] = 0
                    self.save_users()
                    print(f"✅ Account '{username}' unlocked!")
                else:
                    print("❌ User not found!")
            
            elif choice == "3":
                username = input("Username to delete: ").strip()
                if username == current:
                    print("❌ Cannot delete your own account!")
                    continue
                if username in self.users:
                    confirm = input(f"Delete '{username}'? (y/n): ").lower()
                    if confirm == 'y':
                        del self.users[username]
                        if username in self.sessions:
                            del self.sessions[username]
                        self.save_users()
                        print(f"✅ User '{username}' deleted!")
                else:
                    print("❌ User not found!")
            
            elif choice == "4":
                username = input("Username: ").strip()
                if username in self.users:
                    print(f"Current role: {self.users[username]['role']}")
                    new_role = input("New role (user/admin): ").strip()
                    if new_role in ["user", "admin"]:
                        self.users[username]["role"] = new_role
                        self.save_users()
                        print(f"✅ Role updated to '{new_role}'!")
                    else:
                        print("❌ Invalid role!")
                else:
                    print("❌ User not found!")
            
            elif choice == "5":
                print("\n📊 SYSTEM LOGS:")
                print("Active sessions:", len([s for s in self.sessions.values() if s.is_active]))
                print(f"Total users: {len(self.users)}")
                locked = sum(1 for u in self.users.values() if u.get("locked"))
                print(f"Locked accounts: {locked}")
                
                print("\nRecent activity:")
                for username, data in self.users.items():
                    if data.get("last_login"):
                        print(f"  • {username}: Last login {data['last_login']}")
            
            elif choice == "6":
                break
            
            else:
                print("❌ Invalid option!")

def main():
    app = SecureLogin()
    
    while True:
        # Cleanup expired sessions
        app.cleanup_expired_sessions()
        
        current_user = app.get_current_user()
        
        print("\n" + "="*50)
        print("      🏦 SECURE LOGIN SYSTEM")
        print("="*50)
        
        if current_user:
            print(f"👤 Logged in: {current_user} [{app.users[current_user]['role']}]")
            print("\n1. My Profile")
            print("2. Change Password")
            print("3. Admin Panel")
            print("4. Logout")
            print("5. Exit")
            
            choice = input("\nChoose option (1-5): ").strip()
            
            if choice == "1":
                print(f"\n📋 PROFILE:")
                print(f"Username: {current_user}")
                print(f"Role: {app.users[current_user]['role']}")
                print(f"Email: {app.users[current_user].get('email', 'N/A')}")
                print(f"Created: {app.users[current_user].get('created_at', 'N/A')}")
                print(f"Last login: {app.users[current_user].get('last_login', 'Never')}")
                input("\nPress Enter to continue...")
            
            elif choice == "2":
                print("\n" + "="*50)
                print("      🔑 CHANGE PASSWORD")
                print("="*50)
                old = getpass.getpass("Current password: ")
                
                if hashlib.sha256(old.encode()).hexdigest() != app.users[current_user]["password"]:
                    print("❌ Incorrect password!")
                    input("Press Enter to continue...")
                    continue
                
                while True:
                    new = getpass.getpass("New password: ")
                    valid, message = app.validate_password(new)
                    if not valid:
                        print(f"❌ {message}")
                        continue
                    confirm = getpass.getpass("Confirm new password: ")
                    if new != confirm:
                        print("❌ Passwords don't match!")
                        continue
                    break
                
                app.users[current_user]["password"] = hashlib.sha256(new.encode()).hexdigest()
                app.save_users()
                print("✅ Password changed successfully!")
                input("Press Enter to continue...")
            
            elif choice == "3":
                app.admin_panel()
            
            elif choice == "4":
                app.logout(current_user)
                input("Press Enter to continue...")
            
            elif choice == "5":
                app.logout(current_user)
                print("👋 Goodbye!")
                sys.exit(0)
            
            else:
                print("❌ Invalid option!")
                input("Press Enter to continue...")
        
        else:
            print("\n1. Login")
            print("2. Register")
            print("3. Exit")
            
            choice = input("\nChoose option (1-3): ").strip()
            
            if choice == "1":
                app.login()
                input("\nPress Enter to continue...")
            
            elif choice == "2":
                app.register()
                input("\nPress Enter to continue...")
            
            elif choice == "3":
                print("👋 Goodbye!")
                sys.exit(0)
            
            else:
                print("❌ Invalid option!")
                input("Press Enter to continue...")

if __name__ == "__main__":
    main()
