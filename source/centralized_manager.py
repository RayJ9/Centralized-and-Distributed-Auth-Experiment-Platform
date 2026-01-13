import os
from .ca_core import CACore

class CentralizedManager:
    def __init__(self, storage_dir="centralized_storage"):
        self.storage_dir = storage_dir
        self.key_path = os.path.join(storage_dir, "root_key.pem")
        self.cert_path = os.path.join(storage_dir, "root_cert.pem")
        
        if not os.path.exists(storage_dir):
            os.makedirs(storage_dir)

    def initialize_ca(self):
        private_key = CACore.generate_private_key()
        cert = CACore.create_self_signed_cert(private_key, common_name="Centralized Root CA")
        
        CACore.save_to_file(self.key_path, CACore.serialize_private_key(private_key))
        CACore.save_to_file(self.cert_path, CACore.serialize_cert(cert))

    def issue_certificate(self, csr, output_path):
        with open(self.key_path, 'rb') as f:
            ca_key = CACore.load_private_key(f.read())
        with open(self.cert_path, 'rb') as f:
            ca_cert = CACore.load_cert_from_file(self.cert_path)
            
        user_cert = CACore.sign_csr(ca_cert, ca_key, csr)
        
        CACore.save_to_file(output_path, CACore.serialize_cert(user_cert))
        return user_cert
