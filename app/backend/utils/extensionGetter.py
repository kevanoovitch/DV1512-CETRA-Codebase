import requests
import logging
import os

logger = logging.getLogger(__name__)

def download_crx(extension_id):
    try:
        # Build folder + file path
        upload_dir = os.path.join("..", "uploaded")
        output_file = os.path.join(upload_dir, extension_id + ".crx")

        # Ensure folder exists
        os.makedirs(upload_dir, exist_ok=True)

        # CRX download URL
        url = (
            "https://clients2.google.com/service/update2/crx?"
            "response=redirect&os=linux&arch=x86-64&os_arch=x86-64&nacl_arch=x86-64&"
            "prod=chromecrx&prodchannel=unknown&prodversion=9999.0.9999.0&"
            "acceptformat=crx2,crx3&x=id%3D" + extension_id + "%26uc"
        )

        logger.info("Downloading CRX for extension ID: %s", extension_id)

        response = requests.get(url, allow_redirects=True)

        if response.status_code != 200:
            logger.error("Download failed with status code %s", response.status_code)
            return -1

        with open(output_file, "wb") as f:
            f.write(response.content)

        logger.info("Saved CRX file to %s", output_file)
        return output_file

    except Exception:
        logger.exception("Exception occurred during CRX download")
        return None
