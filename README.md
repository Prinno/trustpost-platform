# TruePost Backend (Django + DRF)

Normal Users are stored in a separate table and authenticated via JWT. Django's built-in User/Admin/Superuser remain unchanged and login via Django Admin only.

## Setup

1. Create and activate a virtual environment

```
python -m venv .venv
. .venv/Scripts/Activate.ps1
```

2. Install dependencies

```
pip install -r requirements.txt
```

3. Apply migrations

```
python manage.py makemigrations normal_users
python manage.py migrate
```

4. Run server

```
python manage.py runserver
```

## API Base

- Base: `http://localhost:8000/api/auth/`
- Endpoints:
  - POST `register/` { email?, phone?, password }
  - POST `login/` { email? or phone?, password } → { access, refresh, user }
  - POST `refresh/` { refresh } → { access }
  - POST `logout/` { refresh }
  - POST `request-email-verification/` { email }
  - GET `verify-email/?token=...`
  - POST `request-phone-otp/` { phone }
  - POST `verify-phone-otp/` { phone, code }
  - POST `password-reset/request/` { email? or phone? }
  - POST `password-reset/confirm/` { token? or (phone, code), new_password }
  - GET `me/` (Authorization: Bearer <access>)

## Notes
- Email backend defaults to console; configure SMTP in production.
- Phone OTP is printed to server logs; integrate SMS provider in production.
- JWT tokens are issued only for Normal Users and validated by a custom DRF auth class.
- Admins and Super Admins should use `/admin/`.