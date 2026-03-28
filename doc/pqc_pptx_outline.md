# PPTX Outline: The Post-Quantum Trust Spine
## Subtitle: Solving the PQC Performance Gap with Merkle Tree Certificates (MTC)

---

**Slide Number: 1**
**Slide Title: Post-Quantum PKI Trust Model**
*   **The Threat:** Cryptanalytically relevant quantum computers (CRQCs) threaten current public-key encryption methods like RSA and ECC using algorithms like Shor's.
*   **The Goal:** Post-Quantum Cryptography (PQC) aims to develop encryption that remains secure against quantum threats.
*   **Network Compatibility:** PQC solutions must stay compatible with existing global networks and protocols.
*   **Visual Recommendation:** High-level architectural diagram showing traditional PKI transitioning to a post-quantum trust model.

---

**Slide Number: 2**
**Slide Title: "Harvest Now, Decrypt Later"**
*   **The Urgency:** Adversaries are currently stealing and storing encrypted data to decrypt it once quantum technology matures.
*   **Why Wait?:** Organizations must act now to secure their communications before cryptanalytically relevant quantum computers exist.
*   **Target Data:** Immediate transition is critical for data requiring long-term confidentiality (e.g., healthcare, financial, telemetry).
*   **Visual Recommendation:** Iconography depicting data theft alongside a time-delayed decryption lock.

---

**Slide Number: 3**
**Slide Title: The Definition of Cryptographic Agility**
*   **The Core Concept:** Cryptographic agility refers to an organization's capability to replace vulnerable cryptographic assets without causing system disruptions.
*   **The PQC Mandate:** The migration to PQC brings a strict new focus to this concept for all network operators.
*   **Operational Goal:** Ensures systems can securely transition to quantum-resistant standards while maintaining operational interoperability.
*   **Visual Recommendation:** Easy-to-understand flowchart demonstrating seamless cryptographic algorithm swapping without system downtime.

---

**Slide Number: 4**
**Slide Title: The "Drop-in" Trap (Algorithm Sizes)**
*   **The Math:** Traditional ECC signatures are highly efficient, at roughly 64 bytes.
*   **The PQC Bloat:** New NIST-approved post-quantum signatures (FIPS 204) are massive by comparison.
*   **Public Key & Signature Sizes:**
    *   ML-DSA-44 (Level 2): ~2.4 KB signature, 1,312 B public key.
    *   ML-DSA-65 (Level 3): ~3.3 KB signature, 1,952 B public key.
    *   ML-DSA-87 (Level 5): ~4.6 KB signature, 2,592 B public key.
*   **The Trap:** Simply swapping classical algorithms for PQC "drop-ins" is not viable due to this extreme size discrepancy.
*   **Visual Recommendation:** Bar chart comparing the byte sizes of ECC vs. ML-DSA-44, 65, and 87 public keys and signatures.

---

**Slide Number: 5**
**Slide Title: The Handshake Bloat & The 14.7 KB TCP Problem**
*   **The "Handshake Monster":** A standard PQC certificate chain (Leaf + SubCA + SCTs) balloons from ~1.3 KB up to 18 KB – 36 KB.
*   **Key Transmission:** The handshake requires transmitting at least 1 public key in the leaf certificate and 1 public key in the SubCA certificate.
*   **The TCP Bottleneck:** This massive chain natively exceeds the standard 14.7 KB TCP Initial Congestion Window.
*   **The Performance Penalty:** Exceeding this limit triggers a mandatory Round-Trip Time (RTT) penalty, severely degrading global web performance.
*   **Visual Recommendation:** Diagram showing a 36 KB certificate chain failing to fit into a 14.7 KB TCP window pipe.

---

**Slide Number: 6**
**Slide Title: The 5-Signature Handshake in Public PKI**
*   **The Current WebPKI:** A standard TLS handshake today often carries up to 5 signatures.
*   **The Breakdown:** Includes the Handshake, Leaf, SubCA, and two SCTs.
*   **The PQC Risk:** If each of these becomes a massive ML-DSA block, the handshake bloats to an unmanageable 20 KB+.
*   **Visual Recommendation:** A breakdown graphic showing the 5 individual signatures stacking up to exceed bandwidth limits.

---

**Slide Number: 7**
**Slide Title: Introducing Merkle Tree Certificates**
*   **The Standard:** Developed by the IETF plants working group (draft-ietf-plants-merkle-tree-certs).
*   **The Paradigm Shift:** A certificate is valid because it exists in a public, verifiable log, rather than just possessing a CA signature.
*   **The Innovation:** Replaces heavy cryptographic signatures with lightweight "Inclusion Proofs".
*   **Visual Recommendation:** Diagram of a Merkle Tree showing the Merkle Tree Head (MTH), verification path, and leaf inclusion proof.

---

**Slide Number: 8**
**Slide Title: Inside the MTC Leaf (TBSCertificateLogEntry)**
*   **The ASN.1 Structure:** Defines the exact To-Be-Signed (TBS) data in the MTC architecture.
*   **The Public Key Hash Optimization:** Instead of embedding the full, bloated Post-Quantum public key directly into the tree, the leaf only stores a lightweight `subjectPublicKeyInfoHash`.
*   **Preserving PKI Semantics:** Retains standard issuer, subject, and validity fields to remain fully compatible with existing X.509 routing logic.
*   **Visual Recommendation:** Code snippet of the ASN.1 `TBSCertificateLogEntry` structure with `subjectPublicKeyInfoHash` highlighted.

---

**Slide Number: 9**
**Slide Title: Logarithmic Scaling & The Math**
*   **The 2^20 Model:** A perfect binary tree containing exactly 1,048,576 certificates has exactly 21 levels and 2,097,151 total nodes.
*   **The Size Win:** An inclusion proof for this massive tree requires exactly 20 sibling hashes.
*   **80% Data Reduction:** 20 hashes equate to ~640 bytes using SHA-256.
*   **Performance Restored:** This data reduction allows the entire chain to fit cleanly inside the 14.7 KB TCP window.
*   **Visual Recommendation:** Table mapping tree size (1 million certificates) to the proof size (20 hashes / 640 bytes).

---

**Slide Number: 10**
**Slide Title: Landmark Caching**
*   **The Concept:** Pre-sharing the Merkle Tree Head (MTH) between endpoints.
*   **CT Log Overhead:** The standard PQC certificates do not have a CT Log, further reducing network transmission overhead.
*   **The Strategy:** Endpoints download the latest MTH from the infrastructure via an out-of-band or background fetch.
*   **The Benefit:** Endpoints already possess the "Trust Anchor" prior to transit, removing the need to transmit intermediate signatures during the active handshake.
*   **Visual Recommendation:** Flowchart demonstrating an endpoint fetching the MTH out-of-band prior to initiating the TLS handshake.

---

**Slide Number: 11**
**Slide Title: The Definition of a C509 Certificate (CBOR)**
*   **The CDDL Structure:** Standardized by the IETF cose working group (draft-ietf-cose-cbor-encoded-cert-17).
*   **Structural Shift:** Replaces heavy ASN.1/DER encoding with Concise Binary Object Representation (CBOR).
*   **The Objective:** Radically shrinks structural metadata for highly constrained environments.
*   **Visual Recommendation:** Side-by-side visual comparing traditional ASN.1/DER metadata size to CBOR (C509) metadata size.

---

**Slide Number: 12**
**Slide Title: IoT & Industrial Constraints (UAS & GNSS)**
*   **The Challenge:** Industrial IoT devices and Unmanned Aircraft Systems (UAS) lack the memory to handle massive PQC signatures or heavy ASN.1 metadata parsing.
*   **The Hardware Limits:** Similar to automotive systems, these devices operate under strict RAM limitations.
*   **The Solution:** C509 specifically targets constrained IoT deployments to provide essential structural compression.
*   **Visual Recommendation:** Icons representing drones (UAS) and IoT sensors linked to a compact C509 certificate footprint.

---

**Slide Number: 13**
**Slide Title: Banking & Financial Services Mandates**
*   **Regulatory Action:** Financial institutions are mandated to conduct "Forensic Cryptographic Discovery".
*   **Sector Standards:** Driven by guidelines from FS-ISAC, X9, and the Bank for International Settlements (BIS).
*   **The Composite Safety Net:** Banks rely on Composite ML-DSA to maintain strict compliance with existing financial regulations while actively layering on quantum resistance.
*   **Visual Recommendation:** Financial compliance roadmap graphic featuring FS-ISAC, X9, and G7 guidelines.

---

**Slide Number: 14**
**Slide Title: Healthcare & Systemic Compliance**
*   **Data Lifespan:** Medical data requires decades of protection, making it a prime HNDL target.
*   **Regulatory Frameworks:** EU Member States prioritize health and finance in their NIS2 and DORA PQC roadmaps.
*   **Systemic Defense:** Mandates target high-risk use cases to ensure systemic resilience across the sector.
*   **Visual Recommendation:** Shield icon protecting medical records overlaid with a multi-decade compliance timeline.

---

**Slide Number: 15**
**Slide Title: Traditional PKI Revocation vs. Index-Based Revocation**
*   **Traditional PKI:** Revocation is handled by Serial Number, but not computationally "By Hash".
*   **MTC Numerical Revocation:** Because certificates are sequentially ordered as a leaf in the MTC log, MTC uses Index-Based Revocation (e.g., "Revoke Index 2 to 3").
*   **Instant Checks:** Relying parties perform a near-instant mathematical range check, requiring minimal data exchange.
*   **Visual Recommendation:** Comparison graphic illustrating traditional CRL structures vs. MTC index range checks.

---

**Slide Number: 16**
**Slide Title: Root Key Rotation & Multiple CA Keys**
*   **Parallel Signing:** CAs can retain the exact same issuance log while signing checkpoints and subtrees with both old and new keys in parallel.
*   **Seamless Transition:** Older relying parties verify older signatures, while newer parties verify the new algorithmic signatures.
*   **Bandwidth Optimization:** A cosignature negotiation mechanism avoids sending redundant data over the network.
*   **Visual Recommendation:** Diagram showing a single MTC log being signed simultaneously by an RSA key and a new ML-DSA key.

---

**Slide Number: 17**
**Slide Title: Parallel Work: Composite ML-DSA & Hybrid PQC**
*   **The Standard:** Developed by the IETF lamps working group (draft-ietf-lamps-pq-composite-sigs-15).
*   **The Concept:** Combines a classical algorithm (ECC/RSA) with a post-quantum algorithm (ML-DSA) within a single X.509 certificate.
*   **Compliance Bridge:** Provides a stepping stone to deploy post-quantum algorithms on top of existing hardened and certified traditional implementations.
*   **Visual Recommendation:** Diagram illustrating a classical signature and an ML-DSA signature wrapped together inside a composite construct.

---

**Slide Number: 18**
**Slide Title: The Definition of a Composite Cryptographic Element**
*   **Atomic Design:** Incorporates multiple component cryptographic elements of the same type into a single, multi-algorithm scheme.
*   **Presentation:** It presents a single public key and a single signature value to the relying party.
*   **Backwards Compatibility:** Allows existing protocols to process the hybrid signature without needing explicit protocol modification.
*   **Visual Recommendation:** Visual showing two distinct keys (e.g., ECDSA and ML-DSA) fusing into one atomic cryptographic element.

---

**Slide Number: 19**
**Slide Title: The 2026-2027 WebPKI Transition**
*   **Chrome Policy:** Public HTTPS will transition exclusively to MTC, reserving traditional X.509 PQC for Private/Enterprise PKI.
*   **Ecosystem Pivot:** Existing Certificate Transparency (CT) operators transition to bootstrapping public MTC infrastructure.
*   **Late 2027:** Targeted launch of the Chrome Quantum-resistant Root Store (CQRS).
*   **Visual Recommendation:** Timeline graphic spanning 2026 to 2027 marking MTC testing and the CQRS launch.

---

**Slide Number: 20**
**Slide Title: NIST Deprecation Schedule (2030-2035)**
*   **2030:** Phased deprecation of legacy classical algorithms (RSA 2048-bit, ECDSA, EdDSA, DH, ECDH).
*   **2035:** Full disallowance of legacy classical algorithms providing 112 bits of security or utilizing RSA.
*   **Quantum-Safe Standards:** AES-256 remains considered quantum-resistant and safe.
*   **Visual Recommendation:** Red/Yellow/Green timeline indicating classical algorithm deprecation by 2030 and full disallowance by 2035.

---

**Slide Number: 21**
**Slide Title: Future Work: Integrating C509, PQC, and MTC**
*   **The Convergence:** Combining CBOR metadata compression (C509) with MTC's cryptographic compression.
*   **Eliminating Parsing Overhead:** Utilizing natively signed C509 certificates to completely remove ASN.1 parsing requirements.
*   **The Goal:** Achieving the absolute minimum byte-size for Post-Quantum Mutual TLS (mTLS) to ensure seamless operation on highly constrained networks.
*   **Visual Recommendation:** Block stack showing MTC (bottom) + PQC (middle) + C509 (top) resulting in Optimized Constrained TLS.

---

**Slide Number: 22**
**Slide Title: Questions**
*   Open floor for inquiries regarding the Post-Quantum transition.
*   Review specific algorithm sizes, TCP constraints, and MTC proofs.
*   Discuss organizational readiness, discovery, and Cryptographic Agility strategies.
*   **Visual Recommendation:** Clean "Q&A" title graphic.
