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
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.profile.*;
import org.xipki.ca.api.profile.Certprofile.*;
import org.xipki.ca.api.profile.KeyParametersOption.DSAParametersOption;
import org.xipki.ca.api.profile.KeyParametersOption.ECParamatersOption;
import org.xipki.ca.api.profile.KeyParametersOption.RSAParametersOption;
import org.xipki.security.KeyUsage;
import org.xipki.security.*;
import org.xipki.security.ObjectIdentifiers.BaseRequirements;
import org.xipki.security.ObjectIdentifiers.DN;
import org.xipki.security.ObjectIdentifiers.XKU;
import org.xipki.util.CollectionUtil;
import org.xipki.util.Validity;
import org.xipki.util.Validity.Unit;

import java.util.*;

/**
 * CertProfile with identifier.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertprofileUtil {

  private static final Validity maxCabEeValidity = new Validity(397, Unit.DAY);

  public static SubjectInfo getSubject(Certprofile certprofile, X500Name requestedSubject)
      throws CertprofileException, BadCertTemplateException {
    SubjectInfo subjectInfo = certprofile.getSubject(requestedSubject);

    if (certprofile.getCertDomain() == CertDomain.CABForumBR) {
      X500Name subject = subjectInfo.getGrantedSubject();

      if (certprofile.getCertLevel() == CertLevel.EndEntity) {
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

  public static void validate(Certprofile certprofile)
      throws CertprofileException {
    StringBuilder msg = new StringBuilder();

    Map<ASN1ObjectIdentifier, ExtensionControl> controls = certprofile.getExtensionControls();
    Set<ASN1ObjectIdentifier> types = new HashSet<>(controls.keySet());

    CertLevel certLevel = certprofile.getCertLevel();
    CertDomain certDomain = certprofile.getCertDomain();

    ExtensionSpec spec = ExtensionSpec.getExtensionSpec(certDomain, certLevel);

    // make sure that non-request extensions are not permitted in requests
    Set<ASN1ObjectIdentifier> set = new HashSet<>();
    for (ASN1ObjectIdentifier type : types) {
      ExtensionControl control = controls.get(type);
      if (control.isRequest() && spec.isNonRequest(type)) {
        set.add(type);
      }
    }

    if (CollectionUtil.isNotEmpty(set)) {
      msg.append("extensions ").append(toString(set)).append(" must not be contained in request, ");
    }

    // make sure that non-permitted extensions are not configured
    set.clear();
    for (ASN1ObjectIdentifier type : types) {
      if (spec.isNotPermitted(type)) {
        set.add(type);
      }
    }

    if (CollectionUtil.isNotEmpty(set)) {
      msg.append("extensions ").append(toString(set)).append(" must not be contained, ");
    }

    // make sure that critical only extensions are not marked as non-critical.
    set.clear();
    for (ASN1ObjectIdentifier type : types) {
      ExtensionControl control = controls.get(type);
      if (control.isCritical() && spec.isNonCriticalOnly(type)) {
        set.add(type);
      }
    }

    if (CollectionUtil.isNotEmpty(set)) {
      msg.append("critical only extensions are marked as non-critical ")
        .append(toString(set)).append(", ");
    }

    // make sure that non-critical only extensions are not marked as critical.
    set.clear();
    for (ASN1ObjectIdentifier type : types) {
      ExtensionControl control = controls.get(type);
      if (!control.isCritical() && spec.isCriticalOnly(type)) {
        set.add(type);
      }
    }

    if (CollectionUtil.isNotEmpty(set)) {
      msg.append("non-critical only extensions are marked as critical ")
        .append(toString(set)).append(", ");
    }

    // make sure that required extensions are present
    set.clear();
    Set<ASN1ObjectIdentifier> requiredTypes = spec.getRequiredExtensions();

    for (ASN1ObjectIdentifier type : requiredTypes) {
      ExtensionControl extCtrl = controls.get(type);
      if (extCtrl == null || !extCtrl.isRequired()) {
        set.add(type);
      }
    }

    if (!set.isEmpty()) {
      msg.append("required extensions are not configured or not marked as required ")
        .append(toString(set)).append(", ");
    }

    // KeyUsage
    Set<KeyUsageControl> usages = certprofile.getKeyUsage();

    if (certLevel == CertLevel.SubCA || certLevel == CertLevel.RootCA) {
      // make sure the CA certificate contains usage keyCertSign and cRLSign
      org.xipki.security.KeyUsage[] requiredUsages = new org.xipki.security.KeyUsage[] {
          org.xipki.security.KeyUsage.keyCertSign,
          org.xipki.security.KeyUsage.cRLSign};
      for (org.xipki.security.KeyUsage usage : requiredUsages) {
        if (!containsKeyusage(usages, usage)) {
          msg.append("CA profile does not contain keyUsage ").append(usage).append(", ");
        }
      }
    } else {
      // make sure the EE certificate does not contain CA-only usages
      org.xipki.security.KeyUsage[] caOnlyUsages = {org.xipki.security.KeyUsage.keyCertSign};

      Set<org.xipki.security.KeyUsage> setUsages = new HashSet<>();
      for (org.xipki.security.KeyUsage caOnlyUsage : caOnlyUsages) {
        if (containsKeyusage(usages, caOnlyUsage)) {
          setUsages.add(caOnlyUsage);
        }
      }

      if (CollectionUtil.isNotEmpty(set)) {
        msg.append("EndEntity profile must not contain CA-only keyUsage ").append(setUsages)
          .append(", ");
      }
    }

    // BasicConstraints
    if (certLevel == CertLevel.RootCA) {
      Integer pathLen = certprofile.getPathLenBasicConstraint();
      if (pathLen != null) {
        msg.append("Root CA must not set PathLen, ");
      }
    }

    if (certDomain == CertDomain.CABForumBR) {
      validateCABForumBR(certprofile, msg);
    }

    // Edwards or Montgomery Curves (RFC8410)
    Map<ASN1ObjectIdentifier, KeyParametersOption> keyAlgorithms = certprofile.getKeyAlgorithms();
    boolean withEdwardsCurves = keyAlgorithms.containsKey(EdECConstants.id_ED25519)
        || keyAlgorithms.containsKey(EdECConstants.id_ED448);
    boolean withMontgomeryCurves = keyAlgorithms.containsKey(EdECConstants.id_X25519)
        || keyAlgorithms.containsKey(EdECConstants.id_X448);

    if (withEdwardsCurves || withMontgomeryCurves) {
      Set<KeyUsage> requiredUsages = new HashSet<>();
      Set<KeyUsage> optionalUsages = new HashSet<>();
      for (KeyUsageControl m : usages) {
        if (m.isRequired()) {
          requiredUsages.add(m.getKeyUsage());
        } else {
          optionalUsages.add(m.getKeyUsage());
        }
      }

      List<KeyUsage> allowedUsages;
      if (withMontgomeryCurves) {
        if (certLevel != CertLevel.EndEntity) {
          msg.append("montgomery curves are not permitted in CA certificates, ");
        }

        if (!requiredUsages.contains(KeyUsage.keyAgreement)) {
          msg.append("required KeyUsage KeyAgreement is not marked as 'required', ");
        }

        allowedUsages = Arrays.asList(KeyUsage.keyAgreement, KeyUsage.encipherOnly,
                          KeyUsage.decipherOnly);
      } else {
        if (certLevel == CertLevel.EndEntity) {
          if (! (requiredUsages.contains(KeyUsage.digitalSignature)
                || requiredUsages.contains(KeyUsage.contentCommitment))) {
            msg.append("required KeyUsage digitalSignature or contentCommitment is not marked "
                + "as 'required', ");
          }

          allowedUsages = Arrays.asList(KeyUsage.digitalSignature, KeyUsage.contentCommitment);
        } else {
          allowedUsages = Arrays.asList(KeyUsage.digitalSignature, KeyUsage.contentCommitment,
              KeyUsage.keyCertSign, KeyUsage.cRLSign);
        }
      }

      requiredUsages.removeAll(allowedUsages);
      optionalUsages.removeAll(allowedUsages);

      if (!requiredUsages.isEmpty()) {
        msg.append("Required KeyUsage items ").append(requiredUsages)
          .append(" are not permitted, ");
      }

      if (!optionalUsages.isEmpty()) {
        msg.append("Optional KeyUsage items ").append(requiredUsages)
        .append(" are not permitted, ");
      }
    }

    final int len = msg.length();
    if (len > 2) {
      msg.delete(len - 2, len);
      throw new CertprofileException(msg.toString());
    }

  } // method validate

  // CHECKSTYLE:SKIP
  private static void validateCABForumBR(Certprofile certprofile, StringBuilder msg) {
    // Subject only one entries in a RDN is allowed
    SubjectControl subjectCtl = certprofile.getSubjectControl();
    if (CollectionUtil.isNotEmpty(subjectCtl.getGroups())) {
      msg.append("multiple AttributeAndTypes in one RDN is not permitted, ");
    }

    for (ASN1ObjectIdentifier m : subjectCtl.getTypes()) {
      RdnControl ctl = subjectCtl.getControl(m);
      if (ctl.getMaxOccurs() > 1) {
        msg.append("multiple RDNs of the same type are not permitted, ");
      }
    }

    CertLevel certLevel = certprofile.getCertLevel();

    // validity
    if (certLevel == CertLevel.EndEntity) {
      Validity validity = certprofile.getValidity();
      if (validity.compareTo(maxCabEeValidity) > 0) {
        msg.append("validity exceeds the maximal validity of subscriber certificate, ");
      }
    }

    // Signature/hash algorithm
    List<SignAlgo> sigAlgos = certprofile.getSignatureAlgorithms();
    if (sigAlgos == null) {
      msg.append("signature algorithms not defined, ");
    } else {
      List<HashAlgo> allowedHashAlgos =
          Arrays.asList(HashAlgo.SHA256, HashAlgo.SHA384, HashAlgo.SHA512);
      for (SignAlgo signAlgo : sigAlgos) {
        HashAlgo hashAlgo = signAlgo.getHashAlgo();
        if (!allowedHashAlgos.contains(hashAlgo)) {
          msg.append("unpermitted hash algorithm ").append(hashAlgo).append(", ");
        }
      }
    }

    // Public Key
    Map<ASN1ObjectIdentifier, KeyParametersOption> keyAlgorithms = certprofile.getKeyAlgorithms();
    if (CollectionUtil.isEmpty(keyAlgorithms)) {
      msg.append("keyAlgorithms is not configured, ");
    } else {
      for (ASN1ObjectIdentifier m : keyAlgorithms.keySet()) {
        KeyParametersOption opt = keyAlgorithms.get(m);
        if (m.equals(PKCSObjectIdentifiers.rsaEncryption)) {
          if (opt instanceof RSAParametersOption) {
            if (((RSAParametersOption) opt).allowsModulusLength(2048 - 1)) {
              msg.append("minimum RSA modulus size 2048 bit not satisfied, ");
            }
          } else {
            msg.append("unpermitted RSA modulus are configured, ");
          }
        } else if (m.equals(X9ObjectIdentifiers.id_ecPublicKey)) {
          if (opt instanceof ECParamatersOption) {
            Set<ASN1ObjectIdentifier> curveOids =
                new HashSet<>(((ECParamatersOption) opt).getCurveOids());
            curveOids.remove(SECObjectIdentifiers.secp256r1);
            curveOids.remove(SECObjectIdentifiers.secp384r1);
            curveOids.remove(SECObjectIdentifiers.secp521r1);

            if (!curveOids.isEmpty()) {
              msg.append("EC curves ").append(curveOids).append(" are not permitted, ");
            }
          } else {
            msg.append("unpermitted EC curves are configured, ");
          }
        } else if (m.equals(X9ObjectIdentifiers.id_dsa)) {
          if (opt instanceof DSAParametersOption) {
            DSAParametersOption dsaOpt = (DSAParametersOption) opt;
            if (dsaOpt.allowsPlength(2048 - 1)) {
              msg.append("minimum L (2048) not satisfied, ");
            }
            if (dsaOpt.allowsQlength(224 - 1)) {
              msg.append("minimum N (224) not satisfied, ");
            }
          } else {
            msg.append("unpermitted DSA (p,q) are configured, ");
          }
        } else {
          msg.append("keyAlgorithm ").append(m.getId()).append(" is not permitted, ");
        }
      }
    }

    // CRLDistributionPoints
    CrlDistributionPointsControl crlDpControl = certprofile.getCrlDpControl();
    if (crlDpControl == null) {
      msg.append("restriction of CRLDistributionPoints is not configured, ");
    } else {
      Set<String> protocols = crlDpControl.getProtocols();
      if (protocols == null || protocols.size() != 1 || !protocols.contains("http")) {
        msg.append("CRLDistributionPoints allows protocol other than http, ");
      }
    }

    // FreshestCRLDistributionPoints
    CrlDistributionPointsControl freshestCrlControl = certprofile.getFreshestCrlControl();
    if (freshestCrlControl == null) {
      msg.append("restriction of FreshestCRL is not configured, ");
    } else {
      Set<String> protocols = freshestCrlControl.getProtocols();
      if (protocols == null || protocols.size() != 1 || !protocols.contains("http")) {
        msg.append("FreshestCRL allows protocol other than http, ");
      }
    }

    // AuthorityInfoAccess
    AuthorityInfoAccessControl aiaControl = certprofile.getAiaControl();
    if (aiaControl == null) {
      msg.append("restriction of AuthorityInfoAccess is not configured, ");
    } else {
      if (!aiaControl.isIncludesOcsp()) {
        msg.append("access method id-ad-ocsp is not configured, ");
      } else {
        Set<String> protocols = aiaControl.getOcspProtocols();
        if (protocols == null || protocols.size() != 1 || !protocols.contains("http")) {
          msg.append("AIA OCSP allows protocol other than http, ");
        }
      }

      if (!aiaControl.isIncludesCaIssuers()) {
        msg.append("access method id-ad-caIssuers is not configured, ");
      } else {
        Set<String> protocols = aiaControl.getCaIssuersProtocols();
        if (protocols == null || protocols.size() != 1 || !protocols.contains("http")) {
          msg.append("AIA CAIssuers allows protocol other than http, ");
        }
      }
    }

    // Certificate Policies
    if (certLevel == CertLevel.SubCA || certLevel == CertLevel.EndEntity) {
      CertificatePolicies certPolicyValue = certprofile.getCertificatePolicies();
      if (certPolicyValue == null) {
        msg.append("CertificatePolicies is not configured, ");
      }
    }

    // SubjectAltNames
    if (certLevel == CertLevel.EndEntity) {
      Set<GeneralNameMode> sanModes = certprofile.getSubjectAltNameModes();
      if (sanModes == null) {
        msg.append("Restriction of SubjectAltNames is not configured, ");
      } else {
        Set<GeneralNameMode> tmp = new HashSet<>(sanModes);
        for (GeneralNameMode m : sanModes) {
          if (m.getTag() != GeneralNameTag.uniformResourceIdentifier
              && m.getTag() == GeneralNameTag.IPAddress) {
            tmp.add(m);
          }
        }

        if (!tmp.isEmpty()) {
          msg.append("SubjectAltNames ").append(tmp).append(" is not configured, ");
        }
      }
    }

    // KeyUsage
    Set<KeyUsageControl> usages = certprofile.getKeyUsage();
    if (certLevel == CertLevel.RootCA || certLevel == CertLevel.SubCA) {
      if (!containsKeyusage(usages, org.xipki.security.KeyUsage.cRLSign)) {
        msg.append("RootCA profile does contain keyUsage ")
          .append(org.xipki.security.KeyUsage.cRLSign).append(", ");
      }
    } else if (certLevel == CertLevel.EndEntity) {
      if (containsKeyusage(usages, org.xipki.security.KeyUsage.cRLSign)) {
        msg.append("EndEntity profile must not contain keyUsage ")
          .append(org.xipki.security.KeyUsage.cRLSign).append(", ");
      }
    }

    // ExtendedKeyUsage
    Set<ExtKeyUsageControl> ekuControls = certprofile.getExtendedKeyUsages();
    if (certLevel == CertLevel.EndEntity) {
      // ekuControls could not be null here.
      boolean xkuTlsServerRequired = false;
      boolean xkuTlsClientRequired = false;
      for (ExtKeyUsageControl m : ekuControls) {
        ASN1ObjectIdentifier oid = m.getExtKeyUsage();
        if (m.isRequired()) {
          if (XKU.id_kp_serverAuth.equals(oid)) {
            xkuTlsServerRequired = true;
          } else if (XKU.id_kp_clientAuth.equals(oid)) {
            xkuTlsClientRequired = true;
          }
        }

        if (!(XKU.id_kp_serverAuth.equals(oid) || XKU.id_kp_clientAuth.equals(oid)
            || XKU.id_kp_emailProtection.equals(oid))) {
          msg.append("extendedKeyUsage ").append(oid.getId()).append(" is not permitted, ");
        }
      }

      if (!(xkuTlsClientRequired | xkuTlsServerRequired)) {
        msg.append("none of ").append(XKU.id_kp_clientAuth).append(" and ")
          .append(XKU.id_kp_serverAuth).append(" is not configured, ");
      }
    } else {
      if (ekuControls != null) {
        for (ExtKeyUsageControl m : ekuControls) {
          if (m.getExtKeyUsage().equals(XKU.id_kp_anyExtendedKeyUsage)) {
            msg.append(XKU.id_kp_clientAuth).append(" is not allowed, ");
          }
        }
      }
    }

  } // method validateCABForumBR

  static boolean containsRdn(X500Name name, ASN1ObjectIdentifier rdnType) {
    RDN[] rdns = name.getRDNs(rdnType);
    return rdns != null && rdns.length > 0;
  } // method containsRdn

  static boolean containsKeyusage(Set<KeyUsageControl> usageControls, KeyUsage usage) {
    for (KeyUsageControl entry : usageControls) {
      if (usage == entry.getKeyUsage()) {
        return true;
      }
    }
    return false;
  }

  static void addRequestedKeyusage(Set<KeyUsage> usages,
      Map<ASN1ObjectIdentifier, Extension> requestedExtensions,
      Set<KeyUsageControl> usageOccs) {
    Extension extension = requestedExtensions.get(Extension.keyUsage);
    if (extension == null) {
      return;
    }

    org.bouncycastle.asn1.x509.KeyUsage reqKeyUsage =
        org.bouncycastle.asn1.x509.KeyUsage.getInstance(extension.getParsedValue());
    for (KeyUsageControl k : usageOccs) {
      if (k.isRequired()) {
        continue;
      }

      if (reqKeyUsage.hasUsages(k.getKeyUsage().getBcUsage())) {
        usages.add(k.getKeyUsage());
      }
    }
  } // method addRequestedKeyusage

  static void addRequestedExtKeyusage(List<ASN1ObjectIdentifier> usages,
      Map<ASN1ObjectIdentifier, Extension> requestedExtensions, Set<ExtKeyUsageControl> usageOccs) {
    Extension extension = requestedExtensions.get(Extension.extendedKeyUsage);
    if (extension == null) {
      return;
    }

    ExtendedKeyUsage reqKeyUsage = ExtendedKeyUsage.getInstance(extension.getParsedValue());
    for (ExtKeyUsageControl k : usageOccs) {
      if (k.isRequired()) {
        continue;
      }

      if (reqKeyUsage.hasKeyPurposeId(KeyPurposeId.getInstance(k.getExtKeyUsage()))) {
        usages.add(k.getExtKeyUsage());
      }
    }
  } // method addRequestedExtKeyusage

  static ASN1Sequence createSubjectInfoAccess(
      Map<ASN1ObjectIdentifier, Extension> requestedExtensions,
      Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> modes)
          throws BadCertTemplateException {
    if (modes == null) {
      return null;
    }

    Extension extn = requestedExtensions.get(Extension.subjectInfoAccess);
    if (extn == null) {
      return null;
    }

    ASN1Encodable extValue = extn.getParsedValue();
    if (extValue == null) {
      return null;
    }

    ASN1Sequence reqSeq = ASN1Sequence.getInstance(extValue);
    int size = reqSeq.size();

    ASN1EncodableVector vec = new ASN1EncodableVector();
    for (int i = 0; i < size; i++) {
      AccessDescription ad = AccessDescription.getInstance(reqSeq.getObjectAt(i));
      ASN1ObjectIdentifier accessMethod = ad.getAccessMethod();
      Set<GeneralNameMode> generalNameModes = modes.get(accessMethod);

      if (generalNameModes == null) {
        throw new BadCertTemplateException("subjectInfoAccess.accessMethod "
            + accessMethod.getId() + " is not allowed");
      }

      GeneralName accessLocation = BaseCertprofile.createGeneralName(
          ad.getAccessLocation(), generalNameModes);
      vec.add(new AccessDescription(accessMethod, accessLocation));
    } // end for

    return vec.size() > 0 ? new DERSequence(vec) : null;
  } // method createSubjectInfoAccess

  static void addExtension(ExtensionValues values, ASN1ObjectIdentifier extType,
      ExtensionValue extValue, ExtensionControl extControl)
          throws CertprofileException {
    if (extValue != null) {
      values.addExtension(extType, extValue);
    } else if (extControl.isRequired()) {
      String description = ObjectIdentifiers.getName(extType);
      if (description == null) {
        description = extType.getId();
      }
      throw new CertprofileException("could not add required extension " + description);
    }
  } // method addExtension

  static void addExtension(ExtensionValues values, ASN1ObjectIdentifier extType,
      ASN1Encodable extValue, ExtensionControl extControl)
          throws CertprofileException {
    if (extValue != null) {
      values.addExtension(extType, extControl.isCritical(), extValue);
    } else if (extControl.isRequired()) {
      String description = ObjectIdentifiers.getName(extType);
      if (description == null) {
        description = extType.getId();
      }
      throw new CertprofileException("could not add required extension " + description);
    }
  } // method addExtension

  static String toString(Set<ASN1ObjectIdentifier> oids) {
    if (oids == null) {
      return "null";
    }

    StringBuilder sb = new StringBuilder();
    sb.append("[");

    for (ASN1ObjectIdentifier oid : oids) {
      String name = ObjectIdentifiers.getName(oid);
      if (name != null) {
        sb.append(name);
        sb.append(" (").append(oid.getId()).append(")");
      } else {
        sb.append(oid.getId());
      }
      sb.append(", ");
    }

    if (CollectionUtil.isNotEmpty(oids)) {
      int len = sb.length();
      sb.delete(len - 2, len);
    }
    sb.append("]");

    return sb.toString();
  } // method toString
}
