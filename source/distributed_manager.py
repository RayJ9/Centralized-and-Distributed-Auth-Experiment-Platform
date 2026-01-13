import os
import json
from .ca_core import CACore
from .sss import ShamirSecretSharing

class DistributedManager:
    def __init__(self, storage_dir="distributed_storage", n=5, k=3):
        self.storage_dir = storage_dir
        self.n = n
        self.k = k
        self.cert_path = os.path.join(storage_dir, "distributed_root_cert.pem")
        
        if not os.path.exists(storage_dir):
            os.makedirs(storage_dir)

    def initialize_ca(self):
        private_key = CACore.generate_private_key()
        secret_int = CACore.private_key_to_int(private_key)
        
        cert = CACore.create_self_signed_cert(private_key, common_name="Distributed Threshold CA")
        CACore.save_to_file(self.cert_path, CACore.serialize_cert(cert))
        
        shares = ShamirSecretSharing.split(secret_int, self.n, self.k)
        
        for idx, share_val in shares:
            node_dir = os.path.join(self.storage_dir, f"node_{idx}")
            if not os.path.exists(node_dir):
                os.makedirs(node_dir)
            
            share_file = os.path.join(node_dir, "share.json")
            with open(share_file, 'w') as f:
                json.dump({"id": idx, "value": share_val}, f)
            
        # Securely delete key from memory
        del private_key
        del secret_int

    def sign_request(self, csr, node_ids, output_path):
        """
        Attempts to sign a CSR using shares from the specified nodes.
        Returns True if successful, False otherwise.
        """
        if len(node_ids) < self.k:
            return False

        collected_shares = []
        for nid in node_ids:
            share_path = os.path.join(self.storage_dir, f"node_{nid}", "share.json")
            if not os.path.exists(share_path):
                continue
                
            with open(share_path, 'r') as f:
                data = json.load(f)
                collected_shares.append((data['id'], data['value']))
        
        if len(collected_shares) < self.k:
             return False
             
        recovered_int = ShamirSecretSharing.combine(collected_shares)
        recovered_key = CACore.int_to_private_key(recovered_int)
        
        with open(self.cert_path, 'rb') as f:
            ca_cert = CACore.load_cert_from_file(self.cert_path)
            
        user_cert = CACore.sign_csr(ca_cert, recovered_key, csr)
        CACore.save_to_file(output_path, CACore.serialize_cert(user_cert))
        
        del recovered_int
        del recovered_key
        
        return True
