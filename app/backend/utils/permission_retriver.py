import os
import pathlib
import zipfile
import json

def extension_retriver(file_name: str):
    try:
        file_extension = pathlib.Path(file_name).suffix
        archive = zipfile.ZipFile(file_name, 'r')
        manifest_file = archive.read('manifest.json')
        manifest_json=json.loads(manifest_file)
        return manifest_json["permissions"]
    except e:
        print("Exception from extension_retriver:",e)
        return None