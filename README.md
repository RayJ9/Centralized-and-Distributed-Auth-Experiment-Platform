# Centralized vs Distributed Authentication experiment platform

## Introduction
To verify our findings, we constructed an authentication experiment platform. This platform supports both centralized and distributed architectures, leveraging OpenSSL for standard certificate life-cycle management while integrating a dedicated threshold signature module to execute distributed collaborative signing. Furthermore, the platform emulates stochastic failure events which lead to certificate compromise, allowing to quantify the total system cost based on actual certificate exposure time and the volume of certificates synchronization during updates.

## Modules
- **source/ca_core.py**: Encapsulates low-level cryptographic operations for X.509 certificate generation, signing, and verification using the cryptography library.
- **source/sss.py**: Implements the Shamir Secret Sharing (SSS) algorithm for distributed key splitting and recovery.
- **source/centralized_manager.py**: Manages key rotation and certificate issuance logic for the traditional centralized CA architecture.
- **source/distributed_manager.py**: Handles distributed CA logic with threshold signatures, managing key shares across multiple nodes.
- **source/simulation_engine.py**: Orchestrates the simulation lifecycle, including system updates, Poisson-based attack simulation, and cost calculation.
- **main.py**: The interactive entry point providing parameter configuration, variable sweeping experiments, and result visualization.

## Usage
1. Ensure Python is installed.
2. Run the main script from the `pki_project` directory:
   ```bash
   python main.py
   ```
3. Follow the on-screen prompts to configure parameters and run experiments.
