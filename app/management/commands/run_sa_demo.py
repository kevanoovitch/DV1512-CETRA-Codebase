from django.core.management.base import BaseCommand, CommandError

from app.backend.api import preform_secure_annex_scan, print_secure_annex_scan
from app import config


class Command(BaseCommand):
    help = "Run the Secure Annex scan pipeline for a given extension ID."

    DEFAULT_EXTENSION = "deljjimclpnhngmikaiiodgggdniaooh"

    def add_arguments(self, parser):
          parser.add_argument(
              "extension_id",
              nargs="?",
              default=self.DEFAULT_EXTENSION,
              help=f"Chrome Web Store extension ID (default: {self.DEFAULT_EXTENSION}).",
          )
          parser.add_argument(
              "--extension",
              dest="extension_opt",
              help="Override the default/positional extension ID.",
          )



    def handle(self, *args, **options):
        extension_id = options.get("extension_opt") or options.get("extension_id")
        if not extension_id:
            raise CommandError("Provide an extension ID (positional or --extension).")

        self.stdout.write(f"Running Secure Annex scan for {extension_id!r}…")
        preform_secure_annex_scan(extension_id)

        if config.DEV_MODE:
            self.stdout.write(self.style.WARNING("DEV_MODE enabled; using cached report."))

        self.stdout.write("Rendering Secure Annex findings:")
        print_secure_annex_scan(extension_id)

        self.stdout.write(self.style.SUCCESS("Secure Annex demo complete."))