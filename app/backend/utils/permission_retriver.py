import os
import pathlib
import zipfile
import json
import logging
logger = logging.getLogger(__name__)
def extension_retriver(file_name: str):
    try:
        logger.info("Retreiving permission info")
        file_extension = pathlib.Path(file_name).suffix
        archive = zipfile.ZipFile(file_name, 'r')
        manifest_file = archive.read('manifest.json')
        manifest_json=json.loads(manifest_file)
        return manifest_json["permissions"]
    except Exception as e:
        logger.exception("Exception from extension_retriver: %s", e)
        return []