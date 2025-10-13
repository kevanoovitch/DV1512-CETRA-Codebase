import base64, hashlib, io, json, zipfile, struct
from pathlib import Path
from typing import Optional

MAGIC_CRX2 = b"Cr24"
MAGIC_ZIP  = b"PK\x03\x04"

class ExtensionIDConverter:
    
    def convert_file_to_id(self, file_path: str | Path) -> Optional[str]:
        try:
            p = Path(file_path)
            if not p.exists():
                return None

            kind = self._detect_file_type(p)

            if kind == "zip":
                # _convert_zip_to_id already returns Optional[str]
                return self._convert_zip_to_id(p)

            if kind in ("crx2", "crx3"):
                # First try manifest.json inside the ZIP payload
                try:
                    zip_bytes = self._convert_crx_to_zip(p)
                except Exception:
                    return None

                ext_id = self._convert_zip_to_id(zip_bytes)
                if ext_id:
                    return ext_id

                if kind == "crx3":
                    ext_id = self._extension_id_from_crx3_header(p)
                    if ext_id:
                        return ext_id
                else:  # crx2
                    der = self._extract_crx2_pubkey_der(p)
                    if der:
                        return self._extension_id_from_der_pubkey(der)

                return None  # CRX but couldn't derive ID

            # unknown or unsupported file type
            return None

        except Exception:
            return None

        
    

    def _detect_file_type(self, file_path: Path) -> str:
        with file_path.open("rb") as f:
            magic = f.read(4)
            if magic != b"Cr24":
                # Could still be a raw ZIP
                return "zip" if magic == b"PK\x03\x04" else "unknown"
            version = int.from_bytes(f.read(4), "little")
            if version == 2:
                return "crx2"
            if version == 3:
                return "crx3"
            return "unknown"



    def _convert_crx_to_zip(self, crx_file_path):
        off = self._crx_zip_offset(crx_file_path)
        data = crx_file_path.read_bytes()
        if off >= len(data):
            raise ValueError("CRX header length exceeds file size")
        return data[off:] 
   
    def _crx_zip_offset(self, crx_path: Path) -> int:
        with crx_path.open("rb") as f:
            if f.read(4) != b"Cr24":
                raise ValueError("Not a CRX file")
            version = int.from_bytes(f.read(4), "little")
            if version == 2:
                pub_len = int.from_bytes(f.read(4), "little")
                sig_len = int.from_bytes(f.read(4), "little")
                return 16 + pub_len + sig_len
            elif version == 3:
                header_size = int.from_bytes(f.read(4), "little")
                return 12 + header_size
            else:
                raise ValueError(f"Unsupported CRX version: {version}")

            
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
        
    def _extension_id_from_der_pubkey(self, der: bytes) -> str:
        digest = hashlib.sha256(der).digest()
        crx_id_16 = digest[:16]        # first 128 bits
        return self._bytes_to_chrome_id(crx_id_16)

    
    def _bytes_to_chrome_id(self, b: bytes) -> str:
        table = "abcdefghijklmnop"  # 0..15
        out = []
        for x in b:
            out.append(table[(x >> 4) & 0xF])
            out.append(table[x & 0xF])
        return "".join(out)


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
    
    
    def _extract_crx3_id_bytes(self, crx_file: Path) -> Optional[bytes]:
        with crx_file.open("rb") as f:
            if f.read(4) != b"Cr24":
                return None
            version = int.from_bytes(f.read(4), "little")
            if version != 3:
                return None
            header_size = int.from_bytes(f.read(4), "little")
            header = f.read(header_size)

        # Look for protobuf key=(field#1, wiretype=2) i.e. 0x0A,
        # then varint length 16 (0x10), then 16 bytes of ID.
        i, n = 0, len(header)
        while i + 2 + 16 <= n:
            if header[i] == 0x0A:              # field #1, length-delimited
                if header[i + 1] == 0x10:      # length = 16 (fits in one varint byte)
                    cid = header[i + 2 : i + 2 + 16]
                    if len(cid) == 16:
                        return cid
                    # continue scanning if somehow short
            i += 1
        return None

    
    def _extension_id_from_crx3_header(self, crx_file: Path) -> Optional[str]:
        cid = self._extract_crx3_id_bytes(crx_file)
        return self._bytes_to_chrome_id(cid) if cid else None
