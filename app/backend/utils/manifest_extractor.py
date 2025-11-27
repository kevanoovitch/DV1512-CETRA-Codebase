import os
import pathlib
import zipfile
import json
import logging
logger = logging.getLogger(__name__)

def extract_extension_manifest(file_name: str):
    try:
        logger.info("Retrieving extension information")

        archive = zipfile.ZipFile(file_name, "r")
        manifest_data = archive.read("manifest.json")
        manifest = json.loads(manifest_data)

        # Collect useful fields
        result = {
            "name": manifest.get("name"),
            "version": manifest.get("version"),
            "description": manifest.get("description"),

            # Permissions
            "permissions": manifest.get("permissions", []),
            "optional_permissions": manifest.get("optional_permissions", []),

            # Host permissions (MV3)
            "host_permissions": manifest.get("host_permissions", []),

            # Content scripts URL patterns
            "content_scripts": [
                cs.get("matches", [])
                for cs in manifest.get("content_scripts", [])
            ],

            # External domains
            "externally_connectable": manifest.get("externally_connectable", {}),
        }

        return result

    except Exception as e:
        logger.exception("Exception from extension_retriever: %s", e)
        return {}
