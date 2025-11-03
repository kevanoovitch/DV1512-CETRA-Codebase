import base64, hashlib, io, json, zipfile, struct
from pathlib import Path
from typing import Optional

MAGIC_ZIP        = b"PK\x03\x04"
MAGIC_CRX        = b"Cr24"     # real-world CRX (v2 and v3)
MAGIC_CRX3_ALT   = b"CrX3"    

class ExtensionIDConverter:

    def convert_file_to_id(self, file_path: str | Path) -> Optional[str]:
            p = Path(file_path)
            if not p.exists():
                return None

            kind = self._detect_file_type(p)

            if kind == "zip":
                # _convert_zip_to_id already returns Optional[str]
                return self._convert_zip_to_id(p)

            if kind in ("crx2", "crx3"):
                try:
                    zip_bytes = self._convert_crx_to_zip(p)
                except Exception as e:
                    raise ValueError(f"Invalid CRX header: {e}")

                # Try manifest key inside the embedded ZIP first
                try:
                    return self._convert_zip_to_id(zip_bytes)
                except ValueError:
                    # fall through to header-based derivation
                    pass

                if kind == "crx3":
                    cid = self._extension_id_from_crx3_header(p)
                    if cid:
                        return cid
                    raise ValueError("Could not derive extension ID")
                else:  # crx2
                    der = self._extract_crx2_pubkey_der(p)
                    if der:
                        return self._extension_id_from_der_pubkey(der)
                    raise ValueError("Could not derive extension ID")


            # unknown or unsupported file type
            return None


    def _detect_file_type(self, file_path: Path) -> str:
        with file_path.open("rb") as f:
            magic = f.read(4)
            if magic == MAGIC_ZIP:
                return "zip"
            if magic in (MAGIC_CRX, MAGIC_CRX3_ALT):
                # read version to distinguish
                ver_bytes = f.read(4)
                if len(ver_bytes) != 4:
                    return "unknown"
                version = int.from_bytes(ver_bytes, "little")
                if version == 2:
                    return "crx2"
                if version == 3:
                    return "crx3"
                return "unknown"
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
            if magic not in (MAGIC_CRX, MAGIC_CRX3_ALT):
                raise ValueError("Not a CRX file")
            version = int.from_bytes(f.read(4), "little")
            if version == 2:
                pub_len = int.from_bytes(f.read(4), "little")
                sig_len = int.from_bytes(f.read(4), "little")
                return 16 + pub_len + sig_len
            if version == 3:
                header_size = int.from_bytes(f.read(4), "little")
                return 12 + header_size
            raise ValueError(f"Unsupported CRX version: {version}")




    def _extract_crx2_pubkey_der(self, crx_file:Path) -> Optional[bytes]:
        """
        CRX2 stores the dev public key in the header so this function tries to read that
        """
        with crx_file.open("rb") as f:
            if f.read(4) != MAGIC_CRX:
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


    def _convert_zip_to_id(self, zip_src: Path | bytes) -> Optional[str]:
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
            raise ValueError("manifest.json has no 'key'")

        key_b64 = manifest.get("key")
        if not key_b64:
            raise ValueError("manifest.json has no 'key'")

        try:
            der = base64.b64decode(key_b64, validate=True)
        except Exception as e:
            raise ValueError(f"manifest.json 'key' is not valid base64: {e}")

        return self._extension_id_from_der_pubkey(der)



    def _extract_crx3_id_bytes(self, crx_file: Path) -> Optional[bytes]:
        with crx_file.open("rb") as f:
            magic = f.read(4)
            if magic not in (MAGIC_CRX, MAGIC_CRX3_ALT):
                return None
            version = int.from_bytes(f.read(4), "little")
            if version != 3:
                return None
            header_size = int.from_bytes(f.read(4), "little")
            header = f.read(header_size)
        # scan header for field #1 (0x0A), length 16 (0x10)
        i, n = 0, len(header)
        while i + 18 <= n:
            if header[i] == 0x0A and header[i+1] == 0x10:
                cid = header[i+2:i+18]
                if len(cid) == 16:
                    return cid
            i += 1
        return None




    def _extension_id_from_crx3_header(self, crx_file: Path) -> Optional[str]:
        cid = self._extract_crx3_id_bytes(crx_file)
        return self._bytes_to_chrome_id(cid) if cid else None
