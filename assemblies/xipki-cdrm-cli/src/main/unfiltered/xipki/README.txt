*-- ca-setup: Scripts to setup CAs
    |
    +-- cacert-none: Scripts to setup CAs if CA certificates are not present
    |   |
    |   +-- setup-p11.script
    |   |   : Use PKCS#11 (e.g. HSM) to save the key and certificates
    |   |
    |   +-- setup-p11.script
    |       : Use PKCS#12 file to save the key and certificates
    |
    +-- cacert-present: scripts to setup CAs if CA certificates are not present
        |
        +-- setup-p11.script
        |   : Use PKCS#11 (e.g. HSM) to save the key and certificates
        |
        +-- setup-p11.script
            : Use PKCS#12 file to save the key and certificates

*-- client-script: Scripts to communicate with the CA server and OCSP responder
   |
   +- cmp-client-ca-client.script
   |  : Enroll certificates from Client CA via CMP protocol
   |
   +- cmp-server-ca-client.script
   |  : Enroll certificates from Server CA via CMP protocol
   |
   +- rest-client-ca-client.script
   |  : Enroll certificates from Client CA via REST API
   |
   +- rest-server-ca-client.script
   |  : Enroll certificates from Server CA via REST API
   |
   +- crl-ocsp-client.script
      : Suspend/unsuspend/revoke certificate.
      : Generate new CRL, get current CRL.
      : Get status via OCSP.
      : At the first run, the key and certificate for OCSP responder will be
        generated and instruction to setup OCSP responder will be printed.