import base64, hashlib, io, json, zipfile, struct
from pathlib import Path
from typing import Optional

MAGIC_CRX2 = b"Cr24"
MAGIC_CRX3 = b"CrX3"
MAGIC_ZIP  = b"PK\x03\x04"

class ExtensionIDConverter:
    
    def convert_file_to_id(self, file_path: str | Path) -> str:
        """
        takes a string or a file path as argument and converts either a crx or zip to a id string
        """
        # if a crx file convert to zip

        #convert to path obj
        file_path = Path(file_path) 

        #put into detect method 
        file_type = self._detect_file_type(file_path)

        #if unknown 
        if file_type == "unknown":
            raise ValueError("File type is unknown")
        elif file_type in ("crx2","crx3"):
            zip_bytes = self._convert_crx_to_zip(file_path)

            ext_id = self._convert_zip_to_id(zip_bytes)
            if ext_id:
                return ext_id
            
            #If crx2 try again
            if file_type == "crx2":
                der = self._extract_crx2_pubkey_der(file_path)

                if der:
                    ext_id = self._extension_id_from_der_pubkey(der)
                    return ext_id
            raise ValueError(
                "Could not derive extension ID. For CRX3 you typically need "
                "manifest.json['key'] or an external source (store URL / installed ID)."
            )
        elif file_type == "zip":
            ext_id = self._convert_zip_to_id(file_path)
            if not ext_id:
                raise ValueError("manifest.json has no 'key'; cannot derive ID from ZIP")
            return ext_id

        
    

    def _detect_file_type(self, file_path:Path) -> str:
        with file_path.open("rb") as f: 
            magic = f.read(4)
        if magic == MAGIC_CRX2:
            return "crx2"
        if magic == MAGIC_CRX3:
            return "crx3"
        if magic == MAGIC_ZIP:
            return "zip"
        return "unknown"


    def _convert_crx_to_zip(self, crx_file_path):
        off = self._crx_zip_offset(crx_file_path)
        data = crx_file_path.read_bytes()
        if off >= len(data):
            raise ValueError("CRX header length exceeds file size")
        return data[off:] 
   
    def _crx_zip_offset(self, crx_path: Path) -> int:
        with crx_path.open("rb") as f:
            magic = f.read(4)
            if magic == MAGIC_CRX2:
                _ver = struct.unpack("<I", f.read(4))[0]
                pub_len, sig_len = struct.unpack("<II", f.read(8))
                return 16 + pub_len + sig_len
            elif magic == MAGIC_CRX3:
                _ver = struct.unpack("<I", f.read(4))[0]
                header_size = struct.unpack("<I", f.read(4))[0]
                return 12 + header_size
            else:
                raise ValueError("Not a CRX file")
            
    def _extract_crx2_pubkey_der(self, crx_file:Path) -> Optional[bytes]:
        """
        CRX2 stores the dev public key in the header so this function tries to read that
        """ 
        with crx_file.open("rb") as f:
            if f.read(4) != MAGIC_CRX2:
                return None
            _ver = struct.unpack("<I", f.read(4))[0]
            pub_len, sig_len = struct.unpack("<II", f.read(8))
            pub = f.read(pub_len)
            if len(pub) != pub_len:
                return None
            return pub

    def _extension_id_from_der_pubkey(self, der:bytes) -> str:
        h = hashlib.sha256(der).hexdigest()
        return self._hex_to_chrome_id(h)
    
    def _hex_to_chrome_id(self, hexstr: str) -> str:
        table = "abcdefghijklmnop"
        return "".join(table[int(h,16)] for h in hexstr[:32])

    def _convert_zip_to_id(self,zip_src: Path | bytes) -> Optional[str]:
        """Opens a zip path or raw bytes and, reads manifest.json for the key"""
        try: 
            if isinstance(zip_src, bytes):
                with zipfile.ZipFile(io.BytesIO(zip_src)) as zf:
                    with zf.open("manifest.json") as fh:
                        manifest = json.load(fh)
            else:
                with zipfile.ZipFile(zip_src) as zf:
                    with zf.open("manifest.json") as fh:
                        manifest = json.load(fh)
            
        except KeyError:
            # manifest.json missing entirely
            return None
                
        key_b64 = manifest.get("key")
        if not key_b64:
            return None
        
        try:
            der = base64.b64decode(key_b64)
        except Exception as e:
            raise ValueError(f"manifest.json 'key' is not valid base64: {e}")

        return self._extension_id_from_der_pubkey(der)