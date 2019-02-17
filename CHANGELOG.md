
# Change Log

See also <https://github.com/xipki/xipki/releases>

## 5.0.1
 - Release date: Feb 17, 2019
 - Validity other than {num}'y' will not be handled correctly. This has been fixed.
 - Increase the iteration count of PBKDF2 from 1000 to 10,000.
 - The flag 'crlUpdateInProcess' is not set correctly. This has been fixed.
 - OCSP-server DbCertStatusStore logic to detect issuer changes is wrong. This has been fixed.  

## 5.0.0
 - Release date: Dec 28, 2018
 - Optimized the file operations
 - Merged modules
 - Change the distributions
    - CA: from stand-alone karaf based appication to WAR package.
    - OCSP: from stand-alone karaf based appication to WAR package.
    - SDK: replaced by xipki-cli
    - CLI: Command Line Interface. Introduced in version 5.0.0.
 - Merged classes
 - Change the specification format of certificate profile from XML to JSON
 - Change the configuration format of CA, OCSP, PKCS#11 module, CMP client from XML to JSON
 - Add the remote management of CA via REST API
 - Add the remote management of OCSP via REST API
