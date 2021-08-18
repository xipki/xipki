/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.server;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.api.profile.*;
import org.xipki.ca.api.profile.Certprofile.*;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.BaseRequirements;
import org.xipki.security.ObjectIdentifiers.DN;
import org.xipki.security.ObjectIdentifiers.Extn;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.Validity;

import java.io.Closeable;
import java.math.BigInteger;
import java.util.*;

import static org.xipki.ca.server.CertprofileUtil.*;
import static org.xipki.util.Args.notNull;

/**
 * CertProfiel with identifier.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class IdentifiedCertprofile implements Closeable {

  private final CertprofileEntry dbEntry;
  private final Certprofile certprofile;

  public IdentifiedCertprofile(CertprofileEntry dbEntry, Certprofile certprofile)
      throws CertprofileException {
    this.dbEntry = notNull(dbEntry, "dbEntry");
    this.certprofile = notNull(certprofile, "certprofile");

    this.certprofile.initialize(dbEntry.getConf());
  } // constructor

  public NameId getIdent() {
    return dbEntry.getIdent();
  }

  public CertprofileEntry getDbEntry() {
    return dbEntry;
  }

  public X509CertVersion getVersion() {
    return certprofile.getVersion();
  }

  public List<SignAlgo> getSignatureAlgorithms() {
    return certprofile.getSignatureAlgorithms();
  }

  public Date getNotBefore(Date notBefore) {
    return certprofile.getNotBefore(notBefore);
  }

  public Validity getValidity() {
    return certprofile.getValidity();
  }

  public NotAfterMode getNotAfterMode() {
    return certprofile.getNotAfterMode();
  }

  public SubjectInfo getSubject(X500Name requestedSubject, SubjectPublicKeyInfo publicKeyInfo)
      throws CertprofileException, BadCertTemplateException {
    SubjectInfo subjectInfo = certprofile.getSubject(requestedSubject, publicKeyInfo);

    if (certprofile.getCertDomain() == CertDomain.CABForumBR) {
      X500Name subject = subjectInfo.getGrantedSubject();

      if (getCertLevel() == CertLevel.EndEntity) {
        // extract the policyIdentifier
        CertificatePolicies policies = certprofile.getCertificatePolicies();
        ASN1ObjectIdentifier policyId = null;
        if (policies != null) {
          for (PolicyInformation m : policies.getPolicyInformation()) {
            ASN1ObjectIdentifier pid = m.getPolicyIdentifier();
            if (BaseRequirements.id_domain_validated.equals(pid)
                || BaseRequirements.id_organization_validated.equals(pid)
                || BaseRequirements.id_individual_validated.equals(pid)) {
              policyId = pid;
              break;
            }
          }
        }

        // subject:street
        if (containsRdn(subject, DN.street)) {
          if (!containsRdn(subject, DN.O)
              && !containsRdn(subject, DN.givenName)
              && !containsRdn(subject, DN.surname)) {
            throw new BadCertTemplateException("subject:street is prohibited if the "
                + "subject:organizationName field, subject:givenName, and subject:surname field "
                + "are absent.");
          }
        }

        // subject:localityName
        if (containsRdn(subject, DN.localityName)) {
          if (!containsRdn(subject, DN.O)
              && !containsRdn(subject, DN.givenName)
              && !containsRdn(subject, DN.surname)) {
            throw new BadCertTemplateException("subject:localityName is prohibited if the "
                + "subject:organizationName field, subject:givenName, and subject:surname field "
                + "are absent.");
          }
        } else {
          if (!containsRdn(subject, DN.ST)
              && (containsRdn(subject, DN.O)
                  || containsRdn(subject, DN.givenName)
                  || containsRdn(subject, DN.surname))) {
            throw new BadCertTemplateException("subject:localityName is required if the "
                + "subject:organizationName field, subject:givenName field, or subject:surname "
                + "field are present and the subject:stateOrProvinceName field is absent.");
          }
        }

        // subject:stateOrProvinceName
        if (containsRdn(subject, DN.ST)) {
          if (!containsRdn(subject, DN.O)
              && !containsRdn(subject, DN.givenName)
              && !containsRdn(subject, DN.surname)) {
            throw new BadCertTemplateException("subject:stateOrProvinceName is prohibited if the "
                + "subject:organizationName field, subject:givenName, and subject:surname field "
                + "are absent.");
          }
        } else {
          if (!containsRdn(subject, DN.localityName)
              && (containsRdn(subject, DN.O)
                  || containsRdn(subject, DN.givenName)
                  || containsRdn(subject, DN.surname))) {
            throw new BadCertTemplateException("subject:stateOrProvinceName is required if the "
                + "subject:organizationName field, subject:givenName field, or subject:surname "
                +  "field are present and the subject:localityName field is absent.");
          }
        }

        // subject:postalCode
        if (containsRdn(subject, DN.postalCode)) {
          if (!containsRdn(subject, DN.O)
              && !containsRdn(subject, DN.givenName)
              && !containsRdn(subject, DN.surname)) {
            throw new BadCertTemplateException("subject:postalCode is prohibited if the "
                + "subject:organizationName field, subject:givenName, and subject:surname field "
                + "are absent.");
          }
        }

        // subject:countryCode
        if (!containsRdn(subject, DN.C)) {
          if (containsRdn(subject, DN.O)
              || containsRdn(subject, DN.givenName)
              || containsRdn(subject, DN.surname)) {
            throw new BadCertTemplateException("subject:countryCode is required if the "
                + "subject:organizationName field, subject:givenName, and subject:surname field "
                + "are present");
          }
        }

        if (BaseRequirements.id_domain_validated.equals(policyId)) {
          ASN1ObjectIdentifier[] excludeSubjectFields = new ASN1ObjectIdentifier[] {
              DN.O, DN.givenName, DN.surname, DN.street, DN.localityName, DN.ST, DN.postalCode};
          for (ASN1ObjectIdentifier m : excludeSubjectFields) {
            if (containsRdn(subject, m)) {
              throw new BadCertTemplateException("subject " + ObjectIdentifiers.getName(m)
                + " is prohibited in domain validated certificate");
            }
          }
        } else if (BaseRequirements.id_organization_validated.equals(policyId)) {
          ASN1ObjectIdentifier[] includeSubjectFields = new ASN1ObjectIdentifier[] {
              DN.O, DN.C};
          for (ASN1ObjectIdentifier m : includeSubjectFields) {
            if (!containsRdn(subject, m)) {
              throw new BadCertTemplateException("subject " + ObjectIdentifiers.getName(m)
                + " is required in organization validated certificate");
            }
          }

          if (!(containsRdn(subject, DN.localityName) || containsRdn(subject, DN.ST))) {
            throw new BadCertTemplateException("at least one of subject:localityName and "
                + "subject:stateOrProvinceName is required in organization validated certificate");
          }
        } else if (BaseRequirements.id_individual_validated.equals(policyId)) {
          ASN1ObjectIdentifier[] includeSubjectFields = new ASN1ObjectIdentifier[] {
              DN.C};
          for (ASN1ObjectIdentifier m : includeSubjectFields) {
            if (!containsRdn(subject, m)) {
              throw new BadCertTemplateException("subject " + ObjectIdentifiers.getName(m)
                + " is required in individual validated certificate");
            }
          }

          if (!(containsRdn(subject, DN.O)
              || (containsRdn(subject, DN.givenName) && containsRdn(subject, DN.surname)))) {
            throw new BadCertTemplateException("at least one of subject:organizationName and "
                + "(subject:givenName, subject:surName) is required in individual validated "
                + "certificate");
          }

          if (!(containsRdn(subject, DN.localityName) || containsRdn(subject, DN.ST))) {
            throw new BadCertTemplateException("at least one of subject:localityName and "
                + "subject:stateOrProvinceName is required in individual validated certificate");
          }
        }
      } else {
        ASN1ObjectIdentifier[] requiredTypes = new ASN1ObjectIdentifier[] {
            DN.CN, DN.O, DN.C};
        for (ASN1ObjectIdentifier m : requiredTypes) {
          if (!containsRdn(subject, DN.CN)) {
            throw new BadCertTemplateException("missing " + ObjectIdentifiers.getName(m)
              + " in subject");
          }
        }
      }
    }

    // check the country
    ASN1ObjectIdentifier[] countryOids = new ASN1ObjectIdentifier[] {
        ObjectIdentifiers.DN.C,
        ObjectIdentifiers.DN.countryOfCitizenship,
        ObjectIdentifiers.DN.countryOfResidence,
        ObjectIdentifiers.DN.jurisdictionOfIncorporationCountryName};

    for (ASN1ObjectIdentifier oid : countryOids) {
      RDN[] countryRdns = subjectInfo.getGrantedSubject().getRDNs(oid);
      if (countryRdns != null) {
        for (RDN rdn : countryRdns) {
          String textValue = IETFUtils.valueToString(rdn.getFirst().getValue());
          if (!SubjectDnSpec.isValidCountryAreaCode(textValue)) {
            String name = ObjectIdentifiers.getName(oid);
            if (name == null) {
              name = oid.getId();
            }

            throw new BadCertTemplateException("invalid country/area code '" + textValue
                + "' in subject attribute " + name);
          }
        }
      }
    }
    return subjectInfo;
  } // method getSubject

  private boolean containsRdn(X500Name subject, ASN1ObjectIdentifier o) {
    RDN[] rdns = subject.getRDNs(o);
    return rdns != null && rdns.length != 0;
  }

  /**
   * Get the extensions.
   *
   * @param requestedSubject
   *          Subject requested subject. Must not be {@code null}.
   * @param grantedSubject
   *          Granted subject. Must not be {@code null}.
   * @param requestedExtensions
   *          Extensions requested by the requestor. Could be {@code null}.
   * @param publicKeyInfo
   *          Subject public key. Must not be {@code null}.
   * @param publicCaInfo
   *          CA information. Must not be {@code null}.
   * @param crlSignerCert
   *          CRL signer certificate. Could be {@code null}.
   * @param notBefore
   *          NotBefore. Must not be {@code null}.
   * @param notAfter
   *          NotAfter. Must not be {@code null}.
   * @return the extensions of the certificate to be issued.
   */
  public ExtensionValues getExtensions(X500Name requestedSubject, X500Name grantedSubject,
      Extensions requestedExtensions, SubjectPublicKeyInfo publicKeyInfo, PublicCaInfo publicCaInfo,
      X509Cert crlSignerCert, Date notBefore, Date notAfter)
      throws CertprofileException, BadCertTemplateException {
    notNull(publicKeyInfo, "publicKeyInfo");
    ExtensionValues values = new ExtensionValues();

    Map<ASN1ObjectIdentifier, ExtensionControl> controls
        = new HashMap<>(certprofile.getExtensionControls());

    // CTLog extension will be processed by the CA
    controls.remove(Extn.id_SCTs);

    Map<ASN1ObjectIdentifier, Extension> requestedExtns = new HashMap<>();
    // remove the request extensions which are not permitted in the request
    if (requestedExtensions != null) {
      ASN1ObjectIdentifier[] oids = requestedExtensions.getExtensionOIDs();
      for (ASN1ObjectIdentifier m : oids) {
        ExtensionControl control = controls.get(m);
        if (control == null || control.isRequest()) {
          requestedExtns.put(m, requestedExtensions.getExtension(m));
        }
      }
    }

    // SubjectKeyIdentifier
    ASN1ObjectIdentifier extType = Extension.subjectKeyIdentifier;
    ExtensionControl extControl = controls.remove(extType);
    if (extControl != null) {
      SubjectKeyIdentifier value = certprofile.getSubjectKeyIdentifier(publicKeyInfo);
      addExtension(values, extType, value, extControl);
    }

    // Authority key identifier
    extType = Extension.authorityKeyIdentifier;
    extControl = controls.remove(extType);
    if (extControl != null) {
      AuthorityKeyIdentifier value = null;
      if (certprofile.useIssuerAndSerialInAki()) {
        GeneralNames x509CaIssuer = new GeneralNames(
            new GeneralName(publicCaInfo.getIssuer()));
        value = new AuthorityKeyIdentifier(x509CaIssuer, publicCaInfo.getSerialNumber());
      } else {
        byte[] ikiValue = publicCaInfo.getSubjectKeyIdentifer();
        if (ikiValue != null) {
          value = new AuthorityKeyIdentifier(ikiValue);
        }
      }

      addExtension(values, extType, value, extControl);
    }

    // IssuerAltName
    extType = Extension.issuerAlternativeName;
    extControl = controls.remove(extType);
    if (extControl != null) {
      GeneralNames value = publicCaInfo.getSubjectAltName();
      addExtension(values, extType, value, extControl);
    }

    // AuthorityInfoAccess
    extType = Extension.authorityInfoAccess;
    extControl = controls.remove(extType);
    CaUris caUris = publicCaInfo.getCaUris();

    if (extControl != null) {
      AuthorityInfoAccessControl aiaControl = certprofile.getAiaControl();

      List<String> caIssuers = null;
      if (aiaControl == null || aiaControl.isIncludesCaIssuers()) {
        caIssuers = caUris.getCacertUris();
        assertAllUrisHasProtocol(caIssuers, aiaControl.getCaIssuersProtocols());
      }

      List<String> ocspUris = null;
      if (aiaControl == null || aiaControl.isIncludesOcsp()) {
        ocspUris = caUris.getOcspUris();
        assertAllUrisHasProtocol(ocspUris, aiaControl.getOcspProtocols());
      }

      AuthorityInformationAccess value = null;
      if (CollectionUtil.isNotEmpty(caIssuers) || CollectionUtil.isNotEmpty(ocspUris)) {
        value = CaUtil.createAuthorityInformationAccess(
            caIssuers, ocspUris);
      }
      addExtension(values, extType, value, extControl);
    }

    if (controls.containsKey(Extension.cRLDistributionPoints)
        || controls.containsKey(Extension.freshestCRL)) {
      X500Name crlSignerSubject = (crlSignerCert == null) ? null : crlSignerCert.getSubject();
      X500Name x500CaPrincipal = publicCaInfo.getSubject();

      // CRLDistributionPoints
      extType = Extension.cRLDistributionPoints;
      extControl = controls.remove(extType);
      if (extControl != null) {
        CRLDistPoint value = null;
        List<String> uris = caUris.getCrlUris();
        if (CollectionUtil.isNotEmpty(uris)) {
          CrlDistributionPointsControl control = certprofile.getCrlDpControl();
          Set<String> protocols = control == null ? null : control.getProtocols();
          assertAllUrisHasProtocol(uris, protocols);
          value = CaUtil.createCrlDistributionPoints(uris,
              x500CaPrincipal, crlSignerSubject);
        }
        addExtension(values, extType, value, extControl);
      }

      // FreshestCRL
      extType = Extension.freshestCRL;
      extControl = controls.remove(extType);
      if (extControl != null) {
        CRLDistPoint value = null;
        List<String> uris = caUris.getDeltaCrlUris();
        if (CollectionUtil.isNotEmpty(uris)) {
          CrlDistributionPointsControl control = certprofile.getFreshestCrlControl();
          Set<String> protocols = control == null ? null : control.getProtocols();
          assertAllUrisHasProtocol(uris, protocols);
          value = CaUtil.createCrlDistributionPoints(caUris.getDeltaCrlUris(),
              x500CaPrincipal, crlSignerSubject);
        }
        addExtension(values, extType, value, extControl);
      }
    }

    // BasicConstraints
    extType = Extension.basicConstraints;
    extControl = controls.remove(extType);
    if (extControl != null) {
      BasicConstraints value = CaUtil.createBasicConstraints(certprofile.getCertLevel(),
          certprofile.getPathLenBasicConstraint());
      addExtension(values, extType, value, extControl);
    }

    // KeyUsage
    extType = Extension.keyUsage;
    extControl = controls.remove(extType);
    if (extControl != null) {
      Set<KeyUsage> usages = new HashSet<>();
      Set<KeyUsageControl> usageOccs = certprofile.getKeyUsage();
      for (KeyUsageControl k : usageOccs) {
        if (k.isRequired()) {
          usages.add(k.getKeyUsage());
        }
      }

      // the optional KeyUsage will only be set if requested explicitly
      addRequestedKeyusage(usages, requestedExtns, usageOccs);

      org.bouncycastle.asn1.x509.KeyUsage value = X509Util.createKeyUsage(usages);
      addExtension(values, extType, value, extControl);
    }

    // ExtendedKeyUsage
    extType = Extension.extendedKeyUsage;
    extControl = controls.remove(extType);
    if (extControl != null) {
      List<ASN1ObjectIdentifier> usages = new LinkedList<>();
      Set<ExtKeyUsageControl> usageOccs = certprofile.getExtendedKeyUsages();
      for (ExtKeyUsageControl k : usageOccs) {
        if (k.isRequired()) {
          usages.add(k.getExtKeyUsage());
        }
      }

      // the optional ExtKeyUsage will only be set if requested explicitly
      addRequestedExtKeyusage(usages, requestedExtns, usageOccs);

      if (extControl.isCritical()
          && usages.contains(ObjectIdentifiers.XKU.id_kp_anyExtendedKeyUsage)) {
        extControl = new ExtensionControl(false, extControl.isRequired(),
            extControl.isRequest());
      }

      if (!extControl.isCritical() && usages.contains(ObjectIdentifiers.XKU.id_kp_timeStamping)) {
        extControl = new ExtensionControl(true, extControl.isRequired(), extControl.isRequest());
      }

      ExtendedKeyUsage value = X509Util.createExtendedUsage(usages);
      addExtension(values, extType, value, extControl);
    }

    // ocsp-nocheck
    extType = ObjectIdentifiers.Extn.id_extension_pkix_ocsp_nocheck;
    extControl = controls.remove(extType);
    if (extControl != null) {
      // the extension ocsp-nocheck will only be set if requested explicitly
      addExtension(values, extType, DERNull.INSTANCE, extControl);
    }

    // SubjectInfoAccess
    extType = Extension.subjectInfoAccess;
    extControl = controls.remove(extType);
    if (extControl != null) {
      ASN1Sequence value = createSubjectInfoAccess(requestedExtns,
            certprofile.getSubjectInfoAccessModes());
      addExtension(values, extType, value, extControl);
    }

    // CertificatePolicies
    extType = Extension.certificatePolicies;
    extControl = controls.remove(extType);
    if (extControl != null) {
      ASN1Encodable value = certprofile.getCertificatePolicies();
      addExtension(values, extType, value, extControl);
    }

    ExtensionValues subvalues = certprofile.getExtensions(Collections.unmodifiableMap(controls),
        requestedSubject, grantedSubject, requestedExtns, notBefore, notAfter, publicCaInfo);

    Set<ASN1ObjectIdentifier> extTypes = new HashSet<>(controls.keySet());
    for (ASN1ObjectIdentifier type : extTypes) {
      extControl = controls.get(type);
      ExtensionValue value = subvalues.getExtensionValue(type);
      if (value == null && extControl.isRequest()) {
        Extension reqExt = requestedExtns.get(type);
        if (reqExt != null) {
          value = new ExtensionValue(extControl.isCritical(), reqExt.getParsedValue());
        }
      }

      if (value != null) {
        addExtension(values, type, value, extControl);
        controls.remove(type);
      }
    }

    Set<ASN1ObjectIdentifier> unprocessedExtTypes = new HashSet<>();
    for (ASN1ObjectIdentifier type : controls.keySet()) {
      if (controls.get(type).isRequired()) {
        unprocessedExtTypes.add(type);
      }
    }

    if (CollectionUtil.isNotEmpty(unprocessedExtTypes)) {
      throw new CertprofileException(
          "could not add required extensions "
          + CertprofileUtil.toString(unprocessedExtTypes));
    }

    // Check the SubjectAltNames
    if (certprofile.getCertDomain() == CertDomain.CABForumBR
        && getCertLevel() == CertLevel.EndEntity) {
      // Make sure that the commonName included in SubjectAltName
      String commonName = X509Util.getCommonName(grantedSubject);
      boolean commonNameInSan = commonName == null;

      // No private IP address is permitted
      GeneralName[] genNames = GeneralNames.getInstance(
              values.getExtensionValue(Extension.subjectAlternativeName).getValue()).getNames();
      for (GeneralName m : genNames) {
        if (GeneralName.dNSName == m.getTagNo()) {
          String domain = DERIA5String.getInstance(m.getName()).getString();
          if (!commonNameInSan && domain.equals(commonName)) {
            commonNameInSan = true;
          }

          if (domain.indexOf('_') != -1) {
            throw new BadCertTemplateException("invalid DNSName " + domain);
          }

          if (!ExtensionSpec.isValidPublicDomain(domain)) {
            throw new BadCertTemplateException("invalid DNSName " + domain);
          }
        } else if (GeneralName.iPAddress == m.getTagNo()) {
          byte[] octets = DEROctetString.getInstance(m.getName()).getOctets();
          if (octets.length == 4) { // IPv4 address
            if (!commonNameInSan) {
              String ipAddressText = (0xFF & octets[0]) + "." + (0xFF & octets[1]) + "."
                  + (0xFF & octets[2]) + "." + (0xFF & octets[3]);
              if (ipAddressText.equals(commonName)) {
                commonNameInSan = true;
              }
            }

            //if (!ExtensionSpec.isValidPublicIPv4Address(octets)) {
            //  throw new BadCertTemplateException(
            //      "invalid IPv4Address " + ipAddressText);
            //}
          } else if (octets.length == 8) { // IPv6 address
            if (!commonNameInSan) {
              // get the number of ":"
              List<Integer> positions = new ArrayList<>(7);
              int n = commonName.length();

              for (int i = 0; i < n; i++) {
                if (commonName.charAt(i) == ':') {
                  positions.add(i);
                }
              }

              if (positions.size() == 7) {
                String[] blocks = new String[8];
                blocks[0] = commonName.substring(0, positions.get(0));
                for (int i = 0; i < 6; i++) {
                  blocks[i + 1] = commonName.substring(positions.get(i) + 1, positions.get(i + 1));
                }
                blocks[7] = commonName.substring(positions.get(6) + 1);

                byte[] commonNameBytes = new byte[16];
                for (int i = 0; i < 8; i++) {
                  String block = blocks[i];
                  int blen = block.length();
                  if (blen == 1 | blen == 2) {
                    commonNameBytes[i * 2 + 1] = (byte) Integer.parseInt(block, 16);
                  } else if (blen == 3 | blen == 4) {
                    commonNameBytes[i * 2] =
                        (byte) Integer.parseInt(block.substring(0, blen - 2), 16);
                    commonNameBytes[i * 2 + 1] =
                        (byte) Integer.parseInt(block.substring(blen - 2), 16);
                  } else if(blen != 0) {
                    throw new BadCertTemplateException(
                        "invalid IP address in commonName " + commonName);
                  }
                }

                if (Arrays.equals(commonNameBytes, octets)) {
                  commonNameInSan = true;
                }
              }
            }
          } else {
            throw new BadCertTemplateException(
                "invalid IP address " + Hex.toHexString(octets));
          }
        }
      }

      if (!commonNameInSan) {
        throw new BadCertTemplateException(
            "content of subject:commonName is not included in extension:SubjectAlternativeNames");
      }
    }

    return values;
  } // method getExtensions

  private static void assertAllUrisHasProtocol(List<String> uris, Set<String> protocols)
          throws CertprofileException {
    if (protocols == null) {
      return;
    }

    for (String uri : uris) {
      boolean validUri = false;
      for (String protocol : protocols) {
        if (uri.startsWith(protocol + ":")) {
          validUri = true;
          break;
        }
      }

      if (!validUri) {
        throw new CertprofileException(
                "URL '" + uri + "' does not have any of protocols " + protocols);
      }
    }
  }

  public CertLevel getCertLevel() {
    return certprofile.getCertLevel();
  }

  public KeypairGenControl getKeypairGenControl() {
    return certprofile.getKeypairGenControl();
  }

  public String getSerialNumberMode() {
    return certprofile.getSerialNumberMode();
  }

  public BigInteger generateSerialNumber(
          X500Name caSubject,
          SubjectPublicKeyInfo caPublicKeyInfo,
          X500Name requestSubject,
          SubjectPublicKeyInfo publicKeyInfo,
          ConfPairs caExtraControl)
          throws CertprofileException {
    return certprofile.generateSerialNumber(caSubject, caPublicKeyInfo,
            requestSubject, publicKeyInfo, caExtraControl);
  }

  public boolean isOnlyForRa() {
    return certprofile.isOnlyForRa();
  }

  public SubjectPublicKeyInfo checkPublicKey(SubjectPublicKeyInfo publicKey)
      throws CertprofileException, BadCertTemplateException {
    return certprofile.checkPublicKey(notNull(publicKey, "publicKey"));
  }

  @Override
  public void close() {
    if (certprofile != null) {
      certprofile.close();
    }
  }

  public boolean isSerialNumberInReqPermitted() {
    return certprofile.isSerialNumberInReqPermitted();
  }

  public Map<ASN1ObjectIdentifier, ExtensionControl> getExtensionControls() {
    return certprofile.getExtensionControls();
  }

  public Integer getPathLenBasicConstraint() {
    return certprofile.getPathLenBasicConstraint();
  }

  public int getMaxCertSize() {
    return certprofile.getMaxCertSize();
  }

}
