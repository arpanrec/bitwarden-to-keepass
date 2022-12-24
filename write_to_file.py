import gnupg
import os
import tempfile


class EncryptAndWriteToFile:

    def __init__(self, keyid) -> None:
        self.keyid = keyid
        dirpath = tempfile.mkdtemp()
        self.gpg = gnupg.GPG(gnupghome=os.path.abspath(dirpath))
        self.gpg.encoding = 'utf-8'
        self.gpg.recv_keys('hkps://keys.openpgp.org', keyid)
        self.gpg.trust_keys([keyid], 'TRUST_ULTIMATE')

    def write(self, data, path):
        encrypted_ascii_data = self.gpg.encrypt(data, self.keyid)
        write_obj = WriteToFile()
        write_obj.write(str(encrypted_ascii_data), f'{path}.asc')


class WriteToFile:

    def write(self, data, path):
        if isinstance(data, str):
            mode = 'w'
        elif isinstance(data, bytes):
            mode = 'wb'
        else:
            raise Exception('Type Unable to Write %s' % type(data))

        with open(path, mode) as file_attach:
            file_attach.write(data)
