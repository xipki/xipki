# The Post-Quantum Trust Spine: Solving the PQC Performance Gap with Merkle Tree Certificates (MTC)
## A Presentation Talk Track

--------------------------------------------------------------------------------

### Section 1: The Quantum Threat & Cryptographic Agility

**Slide 1: The Post-Quantum Cryptography (PQC) Need**
*   **Speaker Track:** "Welcome, everyone. We are here to discuss the foundational redesign of our digital trust infrastructure. The threat is straightforward: Cryptanalytically relevant quantum computers (CRQCs) threaten to break the current public-key encryption methods we rely on every day, such as RSA and ECC, using algorithms like Shor's. The goal of Post-Quantum Cryptography, or PQC, is to establish encryption that remains secure against these quantum threats while remaining compatible with the networks we already have."

**Slide 2: "Harvest Now, Decrypt Later"**
*   **Speaker Track:** "You might ask, 'Why act now if these quantum computers don't exist yet?' The answer is the 'Harvest Now, Decrypt Later' threat. Adversaries are currently stealing and storing encrypted data today with the explicit intent to decrypt it once quantum technology matures. For any organization dealing with data that requires long-term confidentiality—like healthcare records or automotive telemetry—the clock has already run out. We must act now."

**Slide 3: The Definition of Cryptographic Agility**
*   **Speaker Track:** "This brings us to Cryptographic Agility. This isn't just about swapping out a key; it refers to an organization's capability to completely replace vulnerable cryptographic assets without causing system disruptions. The PQC mandate forces a strict new focus on this concept. We must transition securely while maintaining operational interoperability."

**Transition:** "But as we start migrating, we immediately hit a massive performance wall."

--------------------------------------------------------------------------------

### Section 2: The PQC Performance "Wall"

**Slide 4: The "Drop-in" Trap (Algorithm Sizes)**
*   **Speaker Track:** "We cannot just treat PQC algorithms as 'drop-in' replacements for our classical algorithms. Traditional ECC signatures are highly efficient—roughly 64 bytes. The new NIST-approved post-quantum algorithms under FIPS 204 are massive in comparison. ML-DSA-44 (Level 2 security) is about 2.4 KB. ML-DSA-65 (Level 3) is ~3.3 KB, and ML-DSA-87 (Level 5) scales up to ~4.6 KB. Swapping them in blindly destroys network efficiency."

**Slide 5: The Handshake Bloat & The 14.7 KB TCP Problem**
*   **Speaker Track:** "Because of these sizes, a standard PQC certificate chain balloons from its classical ~1.3 KB size up to a 'Handshake Monster' of 18 KB to 36 KB. This directly exceeds the standard 14.7 KB TCP Initial Congestion Window. When you exceed this limit, you trigger a mandatory Round-Trip Time (RTT) penalty, forcing the connection to stall while waiting for acknowledgments, which severely degrades global web performance."

**Slide 6: The 5-Signature Handshake in Public PKI**
*   **Speaker Track:** "Why is it so big? Because a standard TLS handshake today often carries up to 5 signatures: the Handshake itself, the Leaf, the SubCA, and two SCTs for Certificate Transparency. If every single one of these becomes a massive ML-DSA block, the handshake bloats to over 20 KB."

**Transition:** "So, how do we fit a 36 KB elephant into a 14 KB mousehole? We change the architecture of trust entirely."

--------------------------------------------------------------------------------

### Section 3: Merkle Tree Certificates (MTC) Architecture

**Slide 7: Introducing Merkle Tree Certificates**
*   **Speaker Track:** "Enter Merkle Tree Certificates, or MTCs, standardized by the IETF plants working group. MTCs represent a paradigm shift: a certificate is no longer valid simply because it possesses a CA signature. Instead, it is valid because it exists in a public, verifiable log. This allows us to replace heavy cryptographic signatures with lightweight 'Inclusion Proofs'."

**Slide 8: The Handshake in Automotive PKI**
*   **Speaker Track:** "To understand the impact, let's look at automotive environments. Here, Mutual TLS (mTLS) is mandatory. In a standard 3-layer PKI structure, the server and client both send two certificates. If we compute this with PQC, we have 4 Public Keys (~7.6 KB), 4 Certificate Signatures (~13.2 KB), and 2 Handshake Signatures (~6.6 KB). That is ~36 KB of data, which risks critical network timeouts."

**Slide 9: Moving from Signatures to Proofs**
*   **Speaker Track:** "MTC solves this by combining multiple certificates into a tree structure, culminating in a single Merkle Tree Head (MTH). To prove validity, the server just provides a verification path of sibling hashes—an Inclusion Proof—instead of a massive signature. This brilliantly consolidates the handshake, allowing the proof to act as both the CA signature and the SCT simultaneously."

**Slide 10: Inside the MTC Leaf (TBSCertificateLogEntry)**
*   **Speaker Track:** "Inside the MTC Leaf, defined by the TBSCertificateLogEntry ASN.1 structure, we find another massive optimization. Instead of embedding the full, bloated ~1.9 KB post-quantum public key directly into the tree, the MTC leaf only stores a lightweight hash of it—the subjectPublicKeyInfoHash. This strips the cryptographic bloat while preserving standard X.509 routing."

**Slide 11: Logarithmic Scaling & The Math**
*   **Speaker Track:** "The math here is incredibly elegant. In a perfect binary tree containing exactly 1,048,576 certificates, you have 21 levels. An inclusion proof for this massive tree requires exactly 20 sibling hashes. Using SHA-256, those 20 hashes equate to just ~640 bytes. We achieve an 80% data reduction, effortlessly bringing the chain back inside the 14.7 KB TCP window."

**Transition:** "Let's take this theoretical math and apply it to the strictest physical networks in the world."

--------------------------------------------------------------------------------

### Section 4: Real-World Application & Cross-Sector Mandates

**Slide 12: The Automotive Challenge & "Double Bloat"**
*   **Speaker Track:** "Connected vehicles rely on Hardware Security Modules (HSMs) with strict RAM limitations—often under 256 KB. That 36 KB mTLS 'double bloat' exchange we calculated earlier threatens to cause 'Head-of-Line Blocking' on the vehicle's CAN-FD bus, potentially delaying safety-critical telemetry."

**Slide 13: Landmark Caching**
*   **Speaker Track:** "We mitigate this using Landmark Caching. By pre-sharing the Merkle Tree Head (MTH) between the vehicle and the OEM Cloud via Wi-Fi, the vehicle already possesses the 'Trust Anchor' while driving. The server no longer needs to transmit intermediate signatures."

**Slide 14: The 6-8 KB Optimized Handshake**
*   **Speaker Track:** "When we combine lower-tier PQC (ML-DSA-44), Landmark Caching, and MTC Proofs, the entire mutual authentication process shrinks to roughly 6-8 KB. This preserves safety-critical latency."

**Slide 15: The Definition of a C509 Certificate (CBOR)**
*   **Speaker Track:** "While MTC fixes cryptographic bloat, the IETF cose working group's C509 standard fixes structural bloat. It replaces heavy ASN.1/DER encoding with Concise Binary Object Representation (CBOR), using CDDL structures to drastically shrink metadata."

**Slide 16-18: Cross-Sector Mandates (IoT, Banking, Healthcare)**
*   **Speaker Track:** "This isn't just an automotive issue. In IoT, Unmanned Aircraft Systems rely on these exact C509 standards to survive. In Banking, the G7 Cyber Expert Group is mandating 'Forensic Cryptographic Discovery' and relying on Composite ML-DSA to maintain strict compliance. Meanwhile, Healthcare organizations are scrambling to meet EU NIS2 and DORA mandates to protect decades-long data lifespans from Harvest Now, Decrypt Later attacks."

**Transition:** "Before we look at the timeline, we have to address the elephant in the room: Revocation."

--------------------------------------------------------------------------------

### Section 5: Advanced Features & Revocation

**Slide 19: The Bottleneck of Traditional Revocation (CRL & OCSP)**
*   **Speaker Track:** "Traditional Certificate Revocation Lists (CRLs) and OCSP track revoked certificates by listing their individual, massive certificate hashes. With ML-DSA, downloading these lists becomes unmanageably large, scaling poorly and introducing severe TLS latency penalties."

**Slide 20: Index-Based Revocation**
*   **Speaker Track:** "Because MTCs are sequentially ordered as leaves in a log, we can use Index-Based Revocation. We simply revoke numerical ranges—like 'Revoke Index 2 to 3'. Relying parties perform a near-instant mathematical check, requiring almost zero data exchange."

**Slide 21: Root Key Rotation & Multiple CA Keys**
*   **Speaker Track:** "MTC also enables seamless Root Key Rotation. CAs can retain the exact same issuance log while signing its subtrees with both old and new keys in parallel. Through a cosignature negotiation mechanism, older clients verify old signatures while newer clients seamlessly upgrade to the new ones."

**Transition:** "So, what is the roadmap for all of this?"

--------------------------------------------------------------------------------

### Section 6: Parallel Work, Timelines & Future Work

**Slide 22 & 23: Parallel Work: Composite ML-DSA**
*   **Speaker Track:** "For organizations that need a safety net, the IETF lamps working group has developed the standard for Composite ML-DSA (draft-ietf-lamps-pq-composite-sigs-15). This combines a classical algorithm like ECC or RSA with ML-DSA within a single X.509 certificate. Because it presents as a single atomic element—one public key, one signature value—it offers protocol backwards compatibility without requiring explicit protocol modifications."

**Slide 24: The 2026-2027 WebPKI Transition**
*   **Speaker Track:** "The transition is happening now. Google Chrome's policy dictates that public HTTPS will transition exclusively to MTC, reserving traditional 'fat' X.509 PQC certificates for Private and Enterprise PKIs. By late 2027, the launch of the Chrome Quantum-resistant Root Store (CQRS) will enforce this."

**Slide 25: NIST Deprecation Schedule (2030-2035)**
*   **Speaker Track:** "Regulatory pressure is following closely behind. NIST has announced the phased deprecation of classical algorithms by 2030, with complete disallowance of legacy signatures and RSA key establishment by 2035. AES-256 remains quantum-resistant and safe."

**Slide 26: Future Work: Integrating C509, PQC, and MTC**
*   **Speaker Track:** "To conclude, the ultimate goal for constrained networks is convergence. By combining the CBOR metadata compression of C509 with the cryptographic compression of Merkle Tree Certificates, we achieve the absolute minimum byte-size for Post-Quantum Mutual TLS. This is the Post-Quantum Trust Spine that will ensure seamless, secure operations across the automotive, IoT, and enterprise sectors for decades to come."
