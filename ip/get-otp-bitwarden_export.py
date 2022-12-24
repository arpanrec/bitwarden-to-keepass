# pip install python-gnupg pyotp
import pyotp
import gnupg
import tempfile
import json

gpg_key_file = 'dump/0x6C2A3CBC.asc'
bw_encrypted_gpg_file = 'dump/bitwarden_export.json.gpg'

temporary_directory = tempfile.TemporaryDirectory()

gpg = gnupg.GPG(gnupghome=temporary_directory.name)
gpg.encoding = 'utf-8'
with open(gpg_key_file) as f:
    key_data = f.read()
import_result = gpg.import_keys(key_data)

with open(bw_encrypted_gpg_file, 'rb') as encrypted_file:
    result = gpg.decrypt_file(
        encrypted_file, always_trust=True)

bw_exported_json_str = result.data.decode("utf-8")
bw_exported_json = json.loads(bw_exported_json_str)

for item in bw_exported_json['items']:
    otp_seed = item['login']['totp']
    if otp_seed is not None:
        print("\n" + otp_seed)
        if otp_seed.startswith('otpauth'):
            totp_obj = pyotp.parse_uri(otp_seed)
        else:
            totp_obj = pyotp.TOTP(otp_seed)
        print(f'{item["name"]} ::: {totp_obj.now()}')

temporary_directory.cleanup()
