# Deployment Guide (Build & Run)

This document describes how to deploy and run the CETRA application from source
in a development environment.

The instructions assume a Linux-based system (native Linux, WSL, or virtual
machine).

---

## 1. Dependencies

See `docs/dependencies.md`.

## 2. Prerequisites (.env)

See `docs/prerequisites.md`.

## 3. Install Dependencies

Install the required Python packages using pip:

```bash
pip install -r requirements.txt
```

## 4. Setup & Run

1. **Migrate Database**: Run `python manage.py migrate` to apply changes to the
   database.
2. **Run Tests (Optional)**: Run `python manage.py test` to ensure the system is
   stable.
3. **Create User**: Execute
   `python manage.py createsuperuser --username=joe --email=joe@example.com` to
   create a user in the Django database.
   - Follow the terminal instructions.
   - Bypass password strength validation when prompted.
4. **Start Server**: Run `python manage.py runserver` to launch the program.
   - Open your browser to the localhost address (usually
     http://127.0.0.1:8000).
   - Log in with the credentials you entered during the `createsuperuser` step.
5. **Security Note**: For security, too many incorrect login attempts will
   trigger a temporary lockout with a 60-second countdown before you can try
   again.
