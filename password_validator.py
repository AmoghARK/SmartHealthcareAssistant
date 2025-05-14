# password_validator.py
import re

class PasswordValidator:
    def __init__(self):
        # Default password requirements
        self.min_length = 8
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_digit = True
        self.require_special = True
    
    def validate(self, password):
        """
        Validate a password against the requirements
        Returns (is_valid, strength, message)
        """
        if not password:
            return False, 0, "Password is required"
        
        # Check minimum length
        if len(password) < self.min_length:
            return False, 0, f"Password must be at least {self.min_length} characters"
        
        # Check for uppercase
        has_uppercase = bool(re.search(r'[A-Z]', password)) if self.require_uppercase else True
        # Check for lowercase
        has_lowercase = bool(re.search(r'[a-z]', password)) if self.require_lowercase else True
        # Check for digit
        has_digit = bool(re.search(r'\d', password)) if self.require_digit else True
        # Check for special character
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)) if self.require_special else True
        
        # Calculate password strength (0-100)
        strength = 0
        if len(password) >= self.min_length:
            strength += 25
        if has_uppercase:
            strength += 25
        if has_lowercase:
            strength += 25
        if has_digit:
            strength += 15
        if has_special:
            strength += 10
        
        # Check if all requirements are met
        if not all([has_uppercase, has_lowercase, has_digit, has_special]):
            missing = []
            if not has_uppercase:
                missing.append("uppercase letter")
            if not has_lowercase:
                missing.append("lowercase letter")
            if not has_digit:
                missing.append("number")
            if not has_special:
                missing.append("special character")
            
            return False, strength, f"Password must include at least one {', '.join(missing)}"
        
        return True, strength, "Password is strong"
    
    def get_strength_color(self, strength):
        """Return a color based on password strength"""
        if strength < 25:
            return "red"
        elif strength < 50:
            return "orange"
        elif strength < 75:
            return "blue"
        else:
            return "green"
