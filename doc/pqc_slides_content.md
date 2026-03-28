# Presentation Title: The Post-Quantum Trust Spine
## Subtitle: Solving the PQC Performance Gap with Merkle Tree Certificates (MTC)

---

### Section 1: The Quantum Threat & Cryptographic Agility

**Slide 1: Post-Quantum PKI Trust Model**
*   **The Threat:** Cryptanalytically relevant quantum computers (CRQCs) threaten current public-key encryption methods like RSA and ECC using algorithms like Shor's.
*   **The Goal:** Post-Quantum Cryptography (PQC) aims to develop encryption that remains secure against quantum threats.
*   **Network Compatibility:** PQC solutions must stay compatible with existing global networks.

**Slide 2: "Harvest Now, Decrypt Later"**
*   **The Urgency:** Adversaries are currently stealing and storing encrypted data to decrypt it once quantum technology matures.
*   **Why Wait?:** Organizations must act now to secure their communications.
*   **Target Data:** This is particularly critical for data requiring long-term confidentiality.

**Slide 3: The Definition of Cryptographic Agility**
*   **The Core Concept:** Cryptographic agility refers to an organization's capability to replace vulnerable cryptographic assets without causing system disruptions.
*   **The PQC Mandate:** The migration to PQC brings a strict new focus to this concept.
*   **Operational Goal:** Ensures systems can securely transition while maintaining operational interoperability.

---

### Section 2: The PQC Performance "Wall"

**Slide 4: The "Drop-in" Trap (Algorithm Sizes)**
*   **The Math:** Traditional ECC signatures are highly efficient, at roughly 64 bytes.
*   **The PQC Bloat:** New NIST-approved post-quantum signatures (FIPS 204) are massive.
*   **Public Key & Signature Sizes:**
    *   ML-DSA-44 (Level 2): ~2.4 KB signature, 1,312 B public key.
    *   ML-DSA-65 (Level 3): ~3.3 KB signature, 1,952 B public key.
    *   ML-DSA-87 (Level 5): ~4.6 KB signature, 2,592 B public key.
*   **The Trap:** Simply swapping classical algorithms for PQC "drop-ins" is not viable due to this extreme size discrepancy.

**Slide 5: The Handshake Bloat & The 14.7 KB TCP Problem**
*   **The "Handshake Monster":** A standard PQC certificate chain (Leaf + SubCA + SCTs) balloons from ~1.3 KB up to 18 KB – 36 KB.
*   **Key Transmission:** The handshake requires transmitting at least 1 public key in the leaf certificate and 1 public key in the SubCA certificate.
*   **The TCP Bottleneck:** This massive chain exceeds the standard 14.7 KB TCP Initial Congestion Window.
*   **The Performance Penalty:** Exceeding this limit triggers a mandatory Round-Trip Time (RTT) penalty, severely degrading global web performance.

**Slide 6: The 5-Signature Handshake in Public PKI**
*   **The Current WebPKI:** A standard TLS handshake today often carries up to 5 signatures.
*   **The Breakdown:** Includes the Handshake, Leaf, SubCA, and two SCTs.
*   **The PQC Risk:** If each of these becomes a massive ML-DSA block, the handshake bloats to an unmanageable 20 KB+.

---

### Section 3: Merkle Tree Certificates (MTC) Architecture

**Slide 7: Introducing Merkle Tree Certificates**
*   **The Standard:** Developed by the IETF plants working group (draft-ietf-plants-merkle-tree-certs-02).
*   **The Paradigm Shift:** A certificate is valid because it exists in a public, verifiable log, rather than just possessing a CA signature.
*   **The Innovation:** Replaces heavy cryptographic signatures with lightweight "Inclusion Proofs".

**Slide 8: Moving from Signatures to Proofs**
*   **The Mechanism:** Multiple certificates are hashed and combined into a tree structure culminating in a Merkle Tree Head (MTH).
*   **Inclusion Proof:** To prove validity, the server provides a verification path—a sequence of sibling hashes—instead of a massive signature.
*   **Handshake Consolidation:** The inclusion proof simultaneously acts as both the CA signature and the SCT.

**Slide 9: Inside the MTC Leaf (TBSCertificateLogEntry)**
*   **The ASN.1 Structure:** Defines the exact To-Be-Signed (TBS) data.
*   **The Public Key Hash Optimization:** Instead of embedding the full, bloated Post-Quantum public key (~1.9 KB for ML-DSA-65) directly into the tree, the leaf only stores a lightweight `subjectPublicKeyInfoHash`.

**Slide 10: Logarithmic Scaling & The Math**
*   **The 2^20 Model:** A perfect binary tree containing exactly 1,048,576 certificates has exactly 21 levels and 2,097,151 total nodes.
*   **The Size Win:** An inclusion proof for this massive tree requires exactly 20 sibling hashes.
*   **80% Data Reduction:** 20 hashes equate to ~640 bytes, allowing the chain to fit cleanly inside the 14.7 KB TCP window.

---

### Section 4: Real-World Application & Cross-Sector Mandates

**Slide 11: Landmark Caching**
*   **The Concept:** Pre-sharing the Merkle Tree Head (MTH) between endpoints.
*   **The Strategy:** For example, vehicles download the latest MTH from the OEM Cloud via Wi-Fi.
*   **The Benefit:** Endpoints already possess the "Trust Anchor" prior to transit, removing the need to transmit intermediate signatures during the active handshake.

**Slide 12: The 6-8 KB Optimized Handshake**
*   **The Formula:** Lower-tier PQC (ML-DSA-44) + Landmark Caching + MTC Proofs.
*   **The Result:** The entire mutual authentication process shrinks to roughly 6-8 KB.
*   **Performance:** Safely preserves critical network latency.

**Slide 13: The Definition of a C509 Certificate (CBOR)**
*   **The CDDL Structure:** Standardized by the IETF cose working group (draft-ietf-cose-cbor-encoded-cert-17).
*   **Structural Shift:** Replaces heavy ASN.1/DER encoding with Concise Binary Object Representation (CBOR).
*   **The Objective:** Radically shrinks structural metadata for highly constrained environments.

**Slide 14: IoT & Industrial Constraints (UAS & GNSS)**
*   **The Challenge:** Industrial IoT devices and Unmanned Aircraft Systems (UAS) lack the memory to handle massive PQC signatures or heavy ASN.1 parsing.
*   **The Solution:** C509 specifically targets constrained IoT deployments to provide essential structural compression.

**Slide 15: Banking & Financial Services Mandates**
*   **Regulatory Action:** Financial institutions are mandated to conduct "Forensic Cryptographic Discovery".
*   **The Composite Safety Net:** Banks rely on Composite ML-DSA to maintain strict compliance with existing financial regulations while actively layering on quantum resistance.

**Slide 16: Healthcare & Systemic Compliance**
*   **Data Lifespan:** Medical data requires decades of protection, making it a prime HNDL target.
*   **Regulatory Frameworks:** EU Member States prioritize health and finance in their NIS2 and DORA PQC roadmaps.

---

### Section 5: Advanced Features & Revocation

**Slide 17: Traditional PKI Revocation vs. Index-Based Revocation**
*   **Traditional PKI:** Relies heavily on revocation by Serial Number, but not computationally "By Hash".
*   **MTC Numerical Revocation:** Because certificates are sequentially ordered as a leaf in the MTC log, MTC uses Index-Based Revocation (e.g., "Revoke Index 2 to 3").
*   **Instant Checks:** Relying parties perform a near-instant mathematical range check, requiring minimal data exchange.

**Slide 18: Root Key Rotation & Multiple CA Keys**
*   **Parallel Signing:** CAs can retain the exact same issuance log while signing its checkpoints and subtrees with both old and new keys in parallel.
*   **Seamless Transition:** Older relying parties verify older signatures, while newer parties verify the new ones.
*   **Bandwidth Optimization:** Avoids sending redundant data via a cosignature negotiation mechanism.

---

### Section 6: Parallel Work, Timelines & Future Work

**Slide 19: Parallel Work: Composite ML-DSA & Hybrid PQC**
*   **The Standard:** Developed by the IETF lamps working group (draft-ietf-lamps-pq-composite-sigs-15).
*   **The Concept:** Combines a classical algorithm (ECC/RSA) with a post-quantum algorithm (ML-DSA) within a single X.509 certificate.

**Slide 20: The Definition of a Composite Cryptographic Element**
*   **Atomic Design:** It presents a single public key and a single signature value.
*   **Backwards Compatibility:** Allows existing protocols to process the hybrid signature without needing explicit modification.

**Slide 21: The 2026-2027 WebPKI Transition**
*   **Chrome Policy:** Public HTTPS will transition exclusively to MTC, reserving traditional X.509 PQC for Private/Enterprise PKI.
*   **Late 2027:** Targeted launch of the Chrome Quantum-resistant Root Store (CQRS).

**Slide 22: NIST Deprecation Schedule (2030-2035)**
*   **2030:** Phased deprecation of legacy classical algorithms.
*   **2035:** Full disallowance of legacy classical algorithms providing 112 bits of security or utilizing RSA.
*   **Quantum-Safe Standards:** AES-256 remains considered quantum-resistant and safe.

**Slide 23: Future Work: Integrating C509, PQC, and MTC**
*   **The Convergence:** Combining CBOR metadata compression (C509) with MTC's cryptographic compression.
*   **The Goal:** Achieving the absolute minimum byte-size for Post-Quantum Mutual TLS (mTLS) to ensure seamless operation on highly constrained automotive and IoT networks.

**Slide 24: Questions**
*   Open floor for inquiries regarding the Post-Quantum transition.
*   Review specific algorithm sizes and protocol constraints.
*   Discuss organizational readiness and Cryptographic Agility strategies.
