# Change Log

See also <https://github.com/xipki/xipki/releases>

## 5.3.0
  - Release date: -
  - CA
    - Add support of RFC8410 (Edwards and Montgomery Curves).
  - OCSP
    - Add support of Ed25519 and Ed448 as signature algorithm.
  - CLI
    - Add support to generate keypair, generate CSR, and enrol certificates of edwards and montgomery curves.

## 5.2.0
  - Release date: Apr 27, 2019
  - CA
    - New feature to configure fixed value of subject RDN in the certificate profile
    - Make sure that the certificate serial number is randomly generated with at least 70 bit entropy and not weak by checking the NAF weight.
    - In the extension CertificatePolicies, the OID for User Notice is not correct. This has been fixed.
    - Add the management of the certificate of parenet CAs for given CA
    - Extension AuthorityKeyIdentifier embeds both KeyIdentifier and (authorityCertIssuer, authorityCertSerialNumber) in case of incorrect configuration. However exactly one of them is allowed. This has been fixed.
    - Add the native support of jurisdictionOfIncorporationCountryName, jurisdictionOfIncorporationLocalityName and jurisdictionOfIncorporationStateOrProvinceName
    - Add the native support of extensions IdentityCode, InsuranceNumber, ICRegistrationNumber, OrganizationCode and TaxationNumber defined in the chinese standard GM/T 0015
    - Add support of specification of extension admission in subject
    - Add CA/Browser certificate profiles.
    - Add support of Certificate Transparency (RFC 6962)
    - Increase the max. size of a certificate from 3000 to 4500 bytes.
  - OCSP
    - Add the configuration of OCSP response behaviour for unknown certificate
    - The OCSP cacher exhausts the database connections. This has been fixed.
  - CLI
    - Extend the command csr-p11 and csr-p12 to generate CSR with complex subject and extensions
    - Simplify and extend the configuration of custom extension
 
## 5.1.0
  - Release date: Mar 17, 2019
  - Relax the limitation of OCSP response in HTTP GET
  - New feature to add NextUpdate to OCSP Response, even if no NextUpdate is available. This is configurable.
  - Optimize the mechanism to generate CRL
  - Add example modules to demonstrate how to extend XiPKI OCSP server to use customized certificate status source.
  - Better mechanism to handle emailAddress in Subject / SubjectAltName
  - Add support of OCSP certificate status source published by EJBCA
  - Simplify the specification of customized extension in certificate profile.
  - If ca.war and ocsp.war are both in one tomcat instance, and one war cannot be started, the other too. This has been fixed.
  - Add support of certificate status source based on the database of XiPKI CA.

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
