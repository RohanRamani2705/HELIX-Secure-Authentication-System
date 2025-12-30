HELIX Cybersecurity System

HELIX is an advanced cybersecurity-focused authentication system built using **Flask**, **SQLite**, and **modern web security practices**.  
It combines strong authentication, multi-factor verification, trusted device management, encrypted logging, and intrusion detection into a single cohesive platform.


Features:

Authentication & Account Security:
- Secure user signup with **email verification**
- Strong password enforcement (uppercase, lowercase, number, symbol)
- Password hashing (SHA-256)
- Password history to prevent reuse
- Automatic session timeout (auto logout)

Multi-Factor Authentication (MFA):
- Email-based OTP for:
  - New device login
  - Account unlock
  - Password reset
- Trusted device recognition using secure cookies

Security Questions:
- 3 mandatory security questions during signup
- Enforced uniqueness of questions
- Ability to update security questions anytime
- Used for secure account recovery

Intrusion Detection:
- Failed login attempt tracking
- Automatic account lock after suspicious activity
- Camera-based **liveness verification**
- Intruder image capture and per-user gallery

Device Management:
- View all trusted devices
- Remove individual devices
- One-click logout from **all devices**

Security Logs:
- Encrypted event and detail storage (AES via Fernet)
- IP address and geo-location tracking
- User-level logs
- Admin-level global logs

QR Security Badge:
- Encrypted QR code generation
- Time-limited token validation
- QR verification endpoint

UI & UX:
- Neon cyberpunk-style UI
- Responsive layouts
- Animated effects
- Password strength indicators


Project Structure:

helix-security-system/
│
├── app.py # Main Flask application
├── security.db # SQLite database (generated at runtime)
│
├── static/
│ └── style.css # Global neon UI styles
│
├── templates/
│ ├── login.html
│ ├── signup.html
│ ├── verify.html
│ ├── mfa.html
│ ├── dashboard.html
│ ├── security_settings.html
│ ├── change_password.html
│ ├── change_security_questions.html
│ ├── trusted_devices.html
│ ├── logs.html
│ ├── gallery.html
│ ├── qr.html
│ ├── qr_verify.html
│ ├── forgot.html
│ ├── reset.html
│ ├── unlock.html
│ ├── unlock_mfa.html
│ └── verify_identity.html
│
├── intruders/ # Captured intruder images (auto-created)
├── qr_codes/ # Generated QR images (auto-created)






Tech Stack

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS (custom neon UI)
- **Database:** SQLite
- **Security:**
  - SHA-256 hashing
  - AES encryption (Fernet)
  - Email OTP (SMTP)
  - Camera-based liveness detection
- **Other Libraries:**
  - OpenCV
  - Cryptography
  - qrcode
  - requests


How to Run the Project?

1) Install Dependencies:

   pip install flask cryptography opencv-python qrcode requests

2️) Run the Application: 
   
   python app.py


HTTPS certificates are generated automatically

App runs at:
https://127.0.0.1:5000


Default Behavior Notes:

First registered user becomes Admin
Account locks after multiple failed login attempts
Camera denial during liveness verification locks the account
Logs are encrypted at rest
QR tokens expire after 5 minutes


Important Security Notes:

Email credentials in app.py should be replaced with environment variables before production use
This project is intended for educational and demonstration purposes
Not recommended for direct production deployment without hardening


Future Enhancements (Ideas):

Face recognition comparison
WebAuthn / hardware keys
Role-based dashboards
OAuth / SSO integration
Rate limiting & CAPTCHA
Docker support


Author: Rohan Manoj Ramani

License:

All rights reserved. 

This project is provided for educational and demonstration purposes only.
Unauthorized copying, modification, or redistribution is not permitted.


