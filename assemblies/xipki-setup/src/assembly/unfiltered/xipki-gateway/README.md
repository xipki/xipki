Deployment in Tomcat (10 and 11)
----
1. (Optional) Replace
  `org.xipki.pkix.auth.SimpleRequestorAuthenticator` with your own
   implementation in the following files:
  - `xipki/etc/cmp-gateway.json`
  - `xipki/etc/est-gateway.json`
  - `xipki/etc/rest-gateway.json`
  - `xipki/etc/scep-gateway.json`
  After the replacement, you may delete configuration file 
  `xipki/etc/simple-requestors.json`.

2. (Optional) If SCEP is supported:  
   You need to have two SCEP certificates with private keys. For the demo you may generate this
   certificate in the `xipki-mgmt-cli` via the command:  
   `source xipki/ca-setup/setup-scep-p12.script`,
   and then copy the generated files `scep-sign.p12` and `scep-enc.p12` to the folder `xipki/keycerts`.  
   By default, the SCEP key signs the responses and decrypts the requests. To use a separate
   key for the decryption, add the block `decryptors` to `xipki/etc/scep-gateway.json`
   (same structure as `signers`, only the type `pkcs12` is supported):
   ```json
   "decryptors":{
     "decryptors":[{
       "names":["subca"],
       "decryptor":{
         "type":"pkcs12",
         "conf":"password=CHANGEIT,keystore=file:keycerts/scep1-enc.p12"
       }
     }]
   }
   ```
   Instead of (or in addition to) `decryptors`, a `default` decryptor may be configured.
   The client selects the certificates by their keyUsage (RFC 8894): the signer certificate must
   have `digitalSignature` but not `keyEncipherment`, the decryptor certificate
   `keyEncipherment` but neither `digitalSignature` nor `contentCommitment`. Both certificates
   are returned in the GetCACert response.
3. (Optional) If ACME is supported (The server URL is https://<host>:<HTTPS-port>/acme/ or http://<host>:<HTTP-port>/acme/.):  
   1. Initialize the database configured in `acme-db.properties`:    
      In xipki-mgmt-cli, call `ca:sql --db-conf /path/to/acme-db.properties xipki/sql/acme-init.sql`
   2. Adapt the `acme`-block in the `tomcat/xipki/etc/acme-gateway.json`.
      For compatibility, DNSSEC verification for ACME `dns-01` challenge validation is disabled
      by default. It should be enabled in production if you use `dns-01`.
      To enable it, set the following fields in `tomcat/xipki/etc/acme-gateway.json`:
      - `allowPrivateChallengeTargets`: leave this as `false` unless you explicitly want
        `http-01` or `tls-alpn-01` to reach private/internal addresses
      - `dnssecValidation`: set to `true`
      - `dnssecTrustAnchorsFile`: set to the trust-anchor file, for example
        `etc/acme/root-trust-anchors.zone`
      - `dnsResolvers`: optional explicit recursive resolvers such as your internal DNS servers
      A sample trust-anchor file is provided in
      `tomcat/xipki/etc/acme/root-trust-anchors.zone`. The example `.zone` file is derived from
      the IANA "Trust Anchors and Rollovers" publication:
      https://www.iana.org/dnssec/files
4. Execute the command  
   `./install.sh -t <tomcat dir of proocol gaeway server>`.
