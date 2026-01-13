import os
import time
import random
import shutil
import math
from .ca_core import CACore
from .sss import ShamirSecretSharing
from .centralized_manager import CentralizedManager
from .distributed_manager import DistributedManager

class SimulationConfig:
    def __init__(self, M=6, T=30, p=0.001, V1=75.0, V2=0.1, total_certs=60, total_periods=100):
        self.M = M
        self.T = T
        self.p = p
        self.V1 = V1
        self.V2 = V2
        self.total_certs = total_certs
        self.total_periods = total_periods
        # Derived K (Threshold): Defaulting to roughly 1/3 or at least 2
        # If M=6, K=2. If M=3, K=1 (unsafe) -> max(2, ...)
        self.K = max(2, int(M // 3))
        
        # Ensure certs per node is integer-ish?
        # If M doesn't divide total_certs, some nodes get more?
        # For simplicity, we just distribute evenly and handle remainder if any,
        # but the original code assumed divisibility.
        # We will keep it simple: certs_per_node = total_certs // M
        self.certs_per_node = total_certs // M
        
        self.base_dir = "platform_verification"

def ensure_dir(path):
    if os.path.exists(path):
        try:
            shutil.rmtree(path)
        except Exception as e:
            print(f"Warning: Failed to clean {path}: {e}")
    try:
        os.makedirs(path)
    except FileExistsError:
        pass

class RealCentralizedSystem:
    def __init__(self, config, run_id):
        self.config = config
        self.root_dir = os.path.join(config.base_dir, f"run_{run_id}", "centralized")
        self.nodes = []
        
        if not os.path.exists(self.root_dir):
            os.makedirs(self.root_dir)
        
        # Initialize M CA Nodes
        for i in range(config.M):
            node_dir = os.path.join(self.root_dir, f"node_{i}")
            if not os.path.exists(node_dir):
                os.makedirs(node_dir)
            self.nodes.append(CentralizedManager(storage_dir=node_dir))

    def update_all(self):
        # Centralized Cost = V2 * Sum of certs stored/updated
        # certs_per_node * M is roughly total_certs
        # To be precise:
        total_certs_managed = self.config.certs_per_node * self.config.M
        weighted_cost = self.config.V2 * total_certs_managed
        
        for i, node_mgr in enumerate(self.nodes):
            # 1. Rotate CA Key
            node_mgr.initialize_ca()
            
            # 2. Re-issue User Certs
            for j in range(self.config.certs_per_node):
                cert_id = i * self.config.certs_per_node + j
                user_key = CACore.generate_private_key()
                csr = CACore.create_csr(user_key, f"User_{cert_id}")
                out_path = os.path.join(node_mgr.storage_dir, f"user_{cert_id}.pem")
                node_mgr.issue_certificate(csr, out_path)
                
        return weighted_cost

class RealDistributedSystem:
    def __init__(self, config, run_id):
        self.config = config
        self.root_dir = os.path.join(config.base_dir, f"run_{run_id}", "distributed")
        self.storage_dir = os.path.join(self.root_dir, "storage")
        
        if not os.path.exists(self.root_dir):
            os.makedirs(self.root_dir)
        if not os.path.exists(self.storage_dir):
            os.makedirs(self.storage_dir)
        
        self.manager = DistributedManager(storage_dir=self.storage_dir, n=config.M, k=config.K)

    def update_all(self):
        # Distributed Cost = V2 * Sum of certs stored across all nodes
        # Each node stores ALL certs (Full Replication)
        raw_update_ops = self.config.total_certs * self.config.M
        weighted_cost = self.config.V2 * raw_update_ops
        
        # 1. Rotate Root Key
        self.manager.initialize_ca()
        
        # 2. Re-issue User Certs (Threshold Sign)
        # Quorum: first K nodes (1..K)
        quorum = list(range(1, self.config.K + 1))
        
        for j in range(self.config.total_certs):
            user_key = CACore.generate_private_key()
            csr = CACore.create_csr(user_key, f"User_{j}")
            
            temp_path = os.path.abspath(os.path.join(self.root_dir, f"user_{j}_temp.pem"))
            if not os.path.exists(os.path.dirname(temp_path)):
                os.makedirs(os.path.dirname(temp_path))
            
            success = self.manager.sign_request(csr, quorum, temp_path)
            
            if not success:
                print(f"[ERROR] Failed to sign user_{j} in distributed mode!")
                continue

            # 3. Storage Replication
            for node_id in range(1, self.config.M + 1):
                node_storage_path = os.path.join(self.storage_dir, f"node_{node_id}", "certs")
                if not os.path.exists(node_storage_path):
                    os.makedirs(node_storage_path)
                
                final_path = os.path.join(node_storage_path, f"user_{j}.pem")
                shutil.copy(temp_path, final_path)
            
            if os.path.exists(temp_path):
                os.remove(temp_path)
            
        return weighted_cost

def run_experiment(config, run_id_suffix=""):
    """
    Runs a single experiment with the provided configuration.
    Returns a dict with results.
    """
    poisson_lambda = config.p * config.T
    
    # Use a unique run ID based on T and suffix to separate files
    run_id = f"{config.T}_{run_id_suffix}"
    
    # Setup
    sys_central = RealCentralizedSystem(config, run_id)
    sys_dist = RealDistributedSystem(config, run_id)
    
    # Stats
    total_risk_central = 0.0
    total_risk_dist = 0.0
    total_ops_central = 0.0
    total_ops_dist = 0.0
    
    # Loop Periods
    for t in range(1, config.total_periods + 1):
        # 1. Update Phase
        c_cost = sys_central.update_all()
        total_ops_central += c_cost
        
        d_cost = sys_dist.update_all()
        total_ops_dist += d_cost
        
        # 2. Attack Phase
        # Centralized
        c_compromised_nodes = set()
        c_period_leakage = 0.0
        
        for node_id in range(config.M):
            time_cursor = 0.0
            while True:
                inter_arrival = random.expovariate(poisson_lambda)
                time_cursor += inter_arrival
                if time_cursor > 1.0: 
                    break
                if node_id not in c_compromised_nodes:
                    c_compromised_nodes.add(node_id)
                    leakage_duration = 1.0 - time_cursor
                    # Leakage = Duration * (Certs per node)
                    c_period_leakage += (leakage_duration * config.certs_per_node)
        
        c_weighted_risk = config.V1 * c_period_leakage
        total_risk_central += c_weighted_risk
        
        # Distributed
        d_compromised_nodes = set()
        system_compromised_at = None
        attack_events = []
        
        for node_id in range(1, config.M + 1): # Nodes are 1..M in distributed logic now?
            # DistributedManager uses 1-based indexing for shares (node_1..node_M)
            # Attack logic should match.
            time_cursor = 0.0
            while True:
                inter_arrival = random.expovariate(poisson_lambda)
                time_cursor += inter_arrival
                if time_cursor > 1.0:
                    break
                attack_events.append((time_cursor, node_id))
        
        attack_events.sort()
        
        for at_time, node_id in attack_events:
            d_compromised_nodes.add(node_id)
            if len(d_compromised_nodes) >= config.K:
                if system_compromised_at is None:
                    system_compromised_at = at_time
                    break
        
        d_period_leakage = 0.0
        if system_compromised_at is not None:
            leakage_duration = 1.0 - system_compromised_at
            # Distributed: All certs leaked
            d_period_leakage += (leakage_duration * config.total_certs)
            
        d_weighted_risk = config.V1 * d_period_leakage
        total_risk_dist += d_weighted_risk
        
    # Calculate Unit Time Costs
    total_time = config.total_periods * config.T
    
    unit_update_central = total_ops_central / total_time
    unit_update_dist = total_ops_dist / total_time
    
    unit_risk_central = total_risk_central / config.total_periods
    unit_risk_dist = total_risk_dist / config.total_periods

    unit_total_central = unit_update_central + unit_risk_central
    unit_total_dist = unit_update_dist + unit_risk_dist

    return {
        "T": config.T,
        "M": config.M,
        "p": config.p,
        "V1": config.V1,
        "V2": config.V2,
        "C_Risk": unit_risk_central,
        "C_Total": unit_total_central,
        "D_Risk": unit_risk_dist,
        "D_Total": unit_total_dist
    }
