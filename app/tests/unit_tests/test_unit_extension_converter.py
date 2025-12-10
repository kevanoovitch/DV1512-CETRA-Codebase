
import io, json, zipfile, struct, hashlib, base64, tempfile
from unittest import TestCase
from pathlib import Path

from app.backend.utils.ExtensionIDConverter import ExtensionIDConverter


# --- Builders & helpers --- # 

def _chrome_id_from_bytes(b: bytes) -> str:
    table = "abcdefghijklmnop"
    hex32 = hashlib.sha256(b).hexdigest()[:32]
    return "".join(table[int(h,16)] for h in hex32)

def _zip_bytes(manifest:dict) -> bytes: 
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, separators=(",",":")))
    return buf.getvalue()    

def _crx2_bytes(zip_bytes: bytes, pubkey_bytes:bytes | None = None) -> bytes:
    magic = b"Cr24"
    ver = struct.pack("<I", 2)
    pub = pubkey_bytes or b""
    sig = b""
    header = magic + ver + struct.pack("<II", len(pub), len(sig)) + pub + sig
    return header + zip_bytes

def _crx3_bytes(zip_bytes: bytes, header_blob: bytes = b"x") -> bytes:
    magic = b"CrX3"
    ver = struct.pack("<I", 3)
    header = magic + ver + struct.pack("<I", len(header_blob)) + (header_blob)
    return header + zip_bytes

# --- Tests --- #

class TestExtensionIDConveter(TestCase):
    def test_zip_with_key(self):
        key = b"DER_KEY_FOR_TEST"
        manifest = {
            "name":"x", "version": "1.0", "manifest_version":3,
            "key": base64.b64encode(key).decode() 
        }
        zbytes = _zip_bytes(manifest)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tf:
            p = Path(tf.name)
            tf.write(zbytes)
        try:
            got = ExtensionIDConverter().convert_file_to_id(p)
            # Raw zips are no longer supported for ID derivation; expect None.
            self.assertIsNone(got)
        finally:
            p.unlink(missing_ok=True)

    def test_zip_without_key_raise(self):
        manifest= {"name": "x", "version":"1.0", "manifest_version":3}
        zbytes = _zip_bytes(manifest)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tf:
            p = Path(tf.name); tf.write(zbytes)
        try: 
            got = ExtensionIDConverter().convert_file_to_id(p)
            self.assertIsNone(got)
        finally:    
            p.unlink(missing_ok=True)

    def test_crx2_manifest_key(self):
        key = b"K2"
        manifest = {
            "name" : "x", "version":"1.0", "manifest_version":2,
             "key": base64.b64encode(key).decode("ascii")
        }
        z = _zip_bytes(manifest)
        crx = _crx2_bytes(z, pubkey_bytes=b"IGNORED_IN_THIS_TEST")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".crx") as tf:
            p = Path(tf.name); tf.write(crx) 
        try:
            got = ExtensionIDConverter().convert_file_to_id(p)
            self.assertEqual(got, _chrome_id_from_bytes(key))
        finally:
            p.unlink(missing_ok=True)
    
    def test_crx2_no_key_uses_header_pubkey(self):
        header_pub = b"HEADER_DER_KEY"

        z = _zip_bytes({"name":"x", "version":"1.0","manifest_version":2})
        crx = _crx2_bytes(z,pubkey_bytes=header_pub)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".crx") as tf:
            p = Path(tf.name); 
            tf.write(crx)
        try: 
            got = ExtensionIDConverter().convert_file_to_id(p)
            self.assertEqual(got, _chrome_id_from_bytes(header_pub))
        finally:
            p.unlink(missing_ok=True)
        
    def test_crx3_with_key(self):
        key = b"C3"
        manifest = {
            "name":"x", "version": "1.0", "manifest_version":3,
             "key": base64.b64encode(key).decode("ascii")
        }
        z = _zip_bytes(manifest)
        crx = _crx3_bytes(z)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".crx") as tf:
            p = Path(tf.name); tf.write(crx)
        try: 
            got = ExtensionIDConverter().convert_file_to_id(p)
            self.assertEqual(got, _chrome_id_from_bytes(key))
        finally:
            p.unlink(missing_ok=True)

    def test_crx3_without_key_raises(self):
        z = _zip_bytes({"name": "x", "version":"1.0", "manifest_version":3})
        crx = _crx3_bytes(z)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".crx") as tf: 
            tf.write(crx)
            p = Path(tf.name)
        try: 
            with self.assertRaisesRegex(ValueError, "Could not derive extension ID"):
                ExtensionIDConverter().convert_file_to_id(p)
        finally:
            p.unlink(missing_ok=True)
