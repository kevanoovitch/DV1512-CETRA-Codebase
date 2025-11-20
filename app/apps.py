from django.apps import AppConfig

try:
    from app.backend.db_initializer import ensure_tables
except ImportError:
    ensure_tables = None


class AppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app'

    def ready(self):
        # Ensure the auxiliary SQLite tables exist before the app starts using them.
        if ensure_tables:
            ensure_tables()
