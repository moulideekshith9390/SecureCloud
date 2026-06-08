# SecureCloud Database Proxy

**Category:** Security, Distributed Systems

A distributed database proxy implementing zero-trust encrypted query execution over cloud storage using AES-GCM and Merkle Hash Trees, with RBAC and session controls for concurrent users.

## Overview

SecureCloud is a security-first database proxy that intercepts and encrypts all queries before they reach cloud storage backends. It implements a zero-trust architecture where no data is ever stored or transmitted in plaintext, and every query is cryptographically authenticated and integrity-verified.

## Key Features

- **AES-GCM Encryption**: All query payloads and results are encrypted using AES-256-GCM, providing both confidentiality and authenticated encryption (integrity + authenticity in a single pass).
- - **Merkle Hash Trees**: Query execution logs and data blocks are organized into Merkle trees, enabling efficient and tamper-evident integrity verification of any subset of stored data.
  - - **Zero-Trust Architecture**: Every request is authenticated regardless of origin — including internal service calls — following a "never trust, always verify" model.
    - - **Role-Based Access Control (RBAC)**: Fine-grained permission system with predefined roles (Admin, ReadOnly, ReadWrite, Auditor) mapped to specific query types and data scopes.
      - - **Session Management**: Stateful session tokens with expiry, rotation, and invalidation for safe concurrent user access.
        - - **Concurrent User Support**: Thread-safe session store with lock-free reads and minimal contention for high-throughput multi-user environments.
         
          - ## Architecture
         
          - The system is composed of four layered components sitting between the client and cloud storage:
         
          - 1. Auth / RBAC module — authenticates requests and enforces role permissions
            2. 2. Session Manager — issues, validates, and invalidates session tokens
               3. 3. Query Processor — performs AES-GCM encryption and decryption of all query payloads
                  4. 4. Merkle Integrity Layer — builds and verifies the hash tree for tamper detection
                    
                     5. All encrypted data is stored in a pluggable Cloud Storage Backend (AWS S3, Google Cloud Storage, or Azure Blob Storage).
                    
                     6. ## Project Structure
                    
                     7.     SecureCloud/
                     8.     +-- src/
                     9.     |   +-- proxy/
                     10.     |   |   +-- proxy_server.py        # Main proxy server entry point
                     11.     |   |   +-- query_handler.py       # Query parsing and routing
                     12.     |   +-- crypto/
                     13.     |   |   +-- aes_gcm.py             # AES-256-GCM encrypt/decrypt
                     14.     |   |   +-- merkle_tree.py         # Merkle Hash Tree implementation
                     15.     |   +-- auth/
                     16.     |   |   +-- rbac.py                # Role-Based Access Control
                     17.     |   |   +-- session_manager.py     # Session lifecycle management
                     18.     |   +-- storage/
                     19.     |   |   +-- cloud_adapter.py       # Cloud storage abstraction layer
                     20.     |   +-- utils/
                     21.     |       +-- logger.py              # Audit logging
                     22.     +-- tests/
                     23.     |   +-- test_aes_gcm.py
                     24.     |   +-- test_merkle_tree.py
                     25.     |   +-- test_rbac.py
                     26.     |   +-- test_session_manager.py
                     27.     +-- requirements.txt
                    
                     28. ## Technical Details
                    
                     29. ### AES-GCM Encryption
                    
                     30. Each query payload is encrypted with a unique 96-bit nonce using AES-256-GCM. The 128-bit authentication tag is stored alongside the ciphertext, ensuring any tampering is detected before decryption. Key derivation uses PBKDF2-HMAC-SHA256 with per-session salts.
                    
                     31. ### Merkle Hash Trees
                    
                     32. Data blocks written to cloud storage are hashed (SHA-256) and inserted into a Merkle tree. The root hash is stored in a trusted metadata store. On read, the proxy recomputes the proof path and verifies consistency — detecting any unauthorized modification to stored data, including partial or targeted corruption.
                    
                     33. ### RBAC Model
                    
                     34. Roles are defined as sets of allowed operations scoped to resource namespaces. Permissions are evaluated at query parse time, before encryption, to prevent privilege escalation through crafted ciphertext.
                    
                     35. | Role       | SELECT | INSERT | UPDATE | DELETE | ADMIN |
                     36. |------------|--------|--------|--------|--------|-------|
                     37. | Admin      | Yes    | Yes    | Yes    | Yes    | Yes   |
                     38. | ReadWrite  | Yes    | Yes    | Yes    | No     | No    |
                     39. | ReadOnly   | Yes    | No     | No     | No     | No    |
                     40. | Auditor    | Yes    | No     | No     | No     | No    |
                    
                     41. ### Session Controls
                    
                     42. Sessions are issued as signed JWT-like tokens with embedded role claims, expiry timestamps, and a rotation nonce. The session store uses an in-memory concurrent hashmap with periodic TTL sweeps. Session invalidation is propagated across all proxy instances via a pub/sub channel.
                    
                     43. ## Getting Started
                    
                     44. ### Prerequisites
                    
                     45. - Python 3.10+
                         - - `cryptography` library
                           - - Cloud SDK (AWS / GCP / Azure) configured
                            
                             - ### Installation
                            
                             -     git clone https://github.com/moulideekshith9390/SecureCloud.git
                             -     cd SecureCloud
                             -     pip install -r requirements.txt
                            
                             - ### Running the Proxy
                            
                             -     python -m src.proxy.proxy_server --config config.yaml --port 5432
                            
                             - ### Running Tests
                            
                             -     pytest tests/ -v
                            
                             - ## Security Considerations
                            
                             - - All encryption keys are ephemeral and derived per session; no long-lived plaintext keys are stored on disk.
                               - - The proxy is stateless with respect to query data — it never logs query content, only anonymized metadata for auditing.
                                 - - Merkle root hashes should be pinned to an external trusted store (HSM or signed ledger) for full tamper evidence.
                                   - - In production, deploy behind mTLS with client certificate verification for all proxy connections.
                                    
                                     - ## Technologies Used
                                    
                                     - - **Language**: Python 3.10+
                                       - - **Cryptography**: AES-256-GCM via `cryptography` library (OpenSSL backend)
                                         - - **Data Integrity**: SHA-256 Merkle Hash Trees
                                           - - **Auth**: RBAC + JWT-style session tokens
                                             - - **Cloud**: Pluggable adapter for AWS S3, Google Cloud Storage, Azure Blob Storage
                                               - - **Concurrency**: Python `asyncio` + thread-safe session store
