// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.ctrl.CertDomain;
import org.xipki.ca.api.profile.ctrl.CertLevel;
import org.xipki.ca.api.profile.ctrl.ExtKeyUsageControl;
import org.xipki.ca.api.profile.ctrl.ExtensionControl;
import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.ca.api.profile.ctrl.KeySingleUsage;
import org.xipki.ca.api.profile.ctrl.SubjectDnSpec;
import org.xipki.ca.api.profile.ctrl.SubjectInfo;
import org.xipki.ca.api.profile.id.ExtensionID;
import org.xipki.security.KeyUsage;
import org.xipki.security.OIDs;
import org.xipki.security.exception.BadCertTemplateException;
import org.xipki.util.extra.exception.CertprofileException;
import org.xipki.util.extra.misc.CollectionUtil;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * CertProfile with identifier.
 *
 * @author Lijun Liao
 *
 */

public class CertprofileUtil {

  public static SubjectInfo getSubject(
      Certprofile certprofile, X500Name requestedSubject)
      throws CertprofileException, BadCertTemplateException {
    SubjectInfo subjectInfo = certprofile.getSubject(requestedSubject);

    if (certprofile.getCertDomain() == CertDomain.CABForumBR) {
      checkCABForumBR(certprofile, subjectInfo.getGrantedSubject());
    }

    // check the country
    ASN1ObjectIdentifier[] countryOids = new ASN1ObjectIdentifier[] {
        OIDs.DN.country,
        OIDs.DN.countryOfCitizenship,
        OIDs.DN.countryOfResidence,
        OIDs.DN.jurIncorporationCountry};

    ASN1ObjectIdentifier errorOid = null;
    String errorCountry = null;
    for (ASN1ObjectIdentifier oid : countryOids) {
      X500Name gs = subjectInfo.getGrantedSubject();
      RDN[] countryRdns = gs.getRDNs(oid);
      if (countryRdns != null) {
        for (RDN rdn : countryRdns) {
          String textValue = IETFUtils.valueToString(rdn.getFirst().getValue());
          if (!SubjectDnSpec.isValidCountryAreaCode(textValue)) {
            errorOid = oid;
            errorCountry = textValue;
            break;
          }
        }
      }

      if (errorOid != null) {
        break;
      }
    }

    if (errorOid != null) {
      String name = OIDs.getName(errorOid);
      if (name == null) {
        name = errorOid.getId();
      }

      throw new BadCertTemplateException("invalid country/area code '" +
          errorCountry + "' in subject attribute " + name);
    }

    return subjectInfo;
  } // method getSubject

  private static void checkCABForumBR(Certprofile certprofile, X500Name subject)
      throws BadCertTemplateException {
    if (certprofile.getCertLevel() == CertLevel.EndEntity) {
      // extract the policyIdentifier
      CertificatePolicies policies = certprofile.getCertificatePolicies();
      ASN1ObjectIdentifier policyId = null;
      if (policies != null) {
        for (PolicyInformation m : policies.getPolicyInformation()) {
          ASN1ObjectIdentifier pid = m.getPolicyIdentifier();
          if (OIDs.PolicyIdentifier.id_domain_validated.equals(pid)
              || OIDs.PolicyIdentifier.id_organization_validated.equals(pid)
              || OIDs.PolicyIdentifier.id_individual_validated.equals(pid)) {
            policyId = pid;
            break;
          }
        }
      }

      // subject:street
      if (containsRdn(subject, OIDs.DN.street)) {
        if (!containsRdn(subject, OIDs.DN.organization)
            && !containsRdn(subject, OIDs.DN.givenName)
            && !containsRdn(subject, OIDs.DN.surname)) {
          throw new BadCertTemplateException(
              "subject:street is prohibited if the " +
              "subject:organizationName field, subject:givenName, and " +
              "subject:surname field are absent.");
        }
      }

      // subject:localityName
      if (containsRdn(subject, OIDs.DN.locality)) {
        if (!containsRdn(subject, OIDs.DN.organization)
            && !containsRdn(subject, OIDs.DN.givenName)
            && !containsRdn(subject, OIDs.DN.surname)) {
          throw new BadCertTemplateException(
              "subject:localityName is prohibited if " +
              "the subject:organizationName field, subject:givenName, and " +
              "subject:surname field are absent.");
        }
      } else {
        if (!containsRdn(subject, OIDs.DN.state) &&
            (containsRdn(subject, OIDs.DN.organization)
                || containsRdn(subject, OIDs.DN.givenName)
                || containsRdn(subject, OIDs.DN.surname))) {
          throw new BadCertTemplateException(
              "subject:localityName is required if the " +
              "subject:organizationName field, subject:givenName field, " +
              "or subject:surname field are present and the " +
              "subject:stateOrProvinceName field is absent.");
        }
      }

      // subject:stateOrProvinceName
      if (containsRdn(subject, OIDs.DN.state)) {
        if (!containsRdn(subject, OIDs.DN.organization)
            && !containsRdn(subject, OIDs.DN.givenName)
            && !containsRdn(subject, OIDs.DN.surname)) {
          throw new BadCertTemplateException(
              "subject:stateOrProvinceName is prohibited if the " +
              "subject:organizationName field, subject:givenName, and " +
              "subject:surname field are absent.");
        }
      } else {
        if (!containsRdn(subject, OIDs.DN.locality) &&
            (containsRdn(subject, OIDs.DN.organization)
                || containsRdn(subject, OIDs.DN.givenName)
                || containsRdn(subject, OIDs.DN.surname))) {
          throw new BadCertTemplateException(
              "subject:stateOrProvinceName is required if the " +
              "subject:organizationName field, subject:givenName field, " +
              "or subject:surname field are present and the " +
              "subject:localityName field is absent.");
        }
      }

      // subject:postalCode
      if (containsRdn(subject, OIDs.DN.postalCode)) {
        if (!containsRdn(subject, OIDs.DN.organization)
            && !containsRdn(subject, OIDs.DN.givenName)
            && !containsRdn(subject, OIDs.DN.surname)) {
          throw new BadCertTemplateException(
              "subject:postalCode is prohibited if the " +
              "subject:organizationName field, subject:givenName, and " +
              "subject:surname field are absent.");
        }
      }

      // subject:countryCode
      if (!containsRdn(subject, OIDs.DN.country)) {
        if (containsRdn(subject, OIDs.DN.organization)
            || containsRdn(subject, OIDs.DN.givenName)
            || containsRdn(subject, OIDs.DN.surname)) {
          throw new BadCertTemplateException(
              "subject:countryCode is required if the " +
              "subject:organizationName field, subject:givenName, and " +
              "subject:surname field are present");
        }
      }

      if (OIDs.PolicyIdentifier.id_domain_validated.equals(policyId)) {
        ASN1ObjectIdentifier[] excludeSubjectFields =
            new ASN1ObjectIdentifier[] {
                OIDs.DN.organization, OIDs.DN.givenName, OIDs.DN.surname,
                OIDs.DN.street,       OIDs.DN.locality,  OIDs.DN.state,
                OIDs.DN.postalCode};
        for (ASN1ObjectIdentifier m : excludeSubjectFields) {
          if (containsRdn(subject, m)) {
            throw new BadCertTemplateException("subject " + OIDs.getName(m)
                + " is prohibited in domain validated certificate");
          }
        }
      } else if (OIDs.PolicyIdentifier.id_organization_validated
          .equals(policyId)) {
        ASN1ObjectIdentifier[] includeSubjectFields =
            new ASN1ObjectIdentifier[] {OIDs.DN.organization, OIDs.DN.country};

        for (ASN1ObjectIdentifier m : includeSubjectFields) {
          if (!containsRdn(subject, m)) {
            throw new BadCertTemplateException("subject " + OIDs.getName(m)
                + " is required in organization validated certificate");
          }
        }

        if (!(containsRdn(subject, OIDs.DN.locality)
            || containsRdn(subject, OIDs.DN.state))) {
          throw new BadCertTemplateException("at least one of " +
              "subject:localityName and subject:stateOrProvinceName is " +
              "required in organization validated certificate");
        }
      } else if (OIDs.PolicyIdentifier.id_individual_validated.equals(
          policyId)) {
        ASN1ObjectIdentifier[] includeSubjectFields =
            new ASN1ObjectIdentifier[] {OIDs.DN.country};
        for (ASN1ObjectIdentifier m : includeSubjectFields) {
          if (!containsRdn(subject, m)) {
            throw new BadCertTemplateException("subject " + OIDs.getName(m)
                + " is required in individual validated certificate");
          }
        }

        if (!(containsRdn(subject, OIDs.DN.organization)
            || (containsRdn(subject, OIDs.DN.givenName)
                  && containsRdn(subject, OIDs.DN.surname)))) {
          throw new BadCertTemplateException(
              "at least one of subject:organizationName and " +
              "(subject:givenName, subject:surName) is required in " +
              "individual validated certificate");
        }

        if (!(containsRdn(subject, OIDs.DN.locality)
            || containsRdn(subject, OIDs.DN.state))) {
          throw new BadCertTemplateException(
              "at least one of subject:localityName and " +
              "subject:stateOrProvinceName is required in individual " +
              "validated certificate");
        }
      }
    } else {
      ASN1ObjectIdentifier[] requiredTypes = new ASN1ObjectIdentifier[] {
          OIDs.DN.commonName, OIDs.DN.organization, OIDs.DN.country};
      for (ASN1ObjectIdentifier m : requiredTypes) {
        if (!containsRdn(subject, OIDs.DN.commonName)) {
          throw new BadCertTemplateException(
              "missing " + OIDs.getName(m) + " in subject");
        }
      }
    }
  }

  static boolean containsRdn(X500Name name, ASN1ObjectIdentifier rdnType) {
    RDN[] rdns = name.getRDNs(rdnType);
    return rdns != null && rdns.length > 0;
  }

  static void addRequestedKeyusage(
      Set<KeyUsage> usages,
      Map<ASN1ObjectIdentifier, Extension> requestedExtensions,
      Set<KeySingleUsage> usageOccs) {
    Extension extension = requestedExtensions.get(OIDs.Extn.keyUsage);
    if (extension == null) {
      return;
    }

    org.bouncycastle.asn1.x509.KeyUsage reqX509 =
        org.bouncycastle.asn1.x509.KeyUsage.getInstance(
            extension.getParsedValue());

    for (KeySingleUsage k : usageOccs) {
      if (k.isRequired()) {
        continue;
      }

      if (reqX509.hasUsages(k.getKeyUsage().getBcUsage())) {
        usages.add(k.getKeyUsage());
      }
    }
  } // method addRequestedKeyusage

  static void addRequestedExtKeyusage(
      List<ASN1ObjectIdentifier> usages,
      Map<ASN1ObjectIdentifier, Extension> requestedExtensions,
      Set<ExtKeyUsageControl> usageOccs) {
    Extension extension = requestedExtensions.get(OIDs.Extn.extendedKeyUsage);
    if (extension == null) {
      return;
    }

    ExtendedKeyUsage reqKeyUsage =
        ExtendedKeyUsage.getInstance(extension.getParsedValue());

    for (ExtKeyUsageControl k : usageOccs) {
      if (k.isRequired()) {
        continue;
      }

      if (reqKeyUsage.hasKeyPurposeId(
          KeyPurposeId.getInstance(k.getExtKeyUsage()))) {
        usages.add(k.getExtKeyUsage());
      }
    }
  } // method addRequestedExtKeyusage

  static ASN1Sequence createSubjectInfoAccess(
      Map<ASN1ObjectIdentifier, Extension> requestedExtensions,
      Map<ASN1ObjectIdentifier, Set<GeneralNameTag>> modes)
      throws BadCertTemplateException {
    if (modes == null) {
      return null;
    }

    Extension extn = requestedExtensions.get(OIDs.Extn.subjectInfoAccess);
    if (extn == null) {
      return null;
    }

    ASN1Sequence reqSeq = ASN1Sequence.getInstance(extn.getParsedValue());
    int size = reqSeq.size();

    for (int i = 0; i < size; i++) {
      AccessDescription ad =
          AccessDescription.getInstance(reqSeq.getObjectAt(i));

      ASN1ObjectIdentifier accessMethod = ad.getAccessMethod();
      Optional.ofNullable(modes.get(accessMethod)).orElseThrow(() ->
          new BadCertTemplateException("subjectInfoAccess.accessMethod "
              + accessMethod.getId() + " is not allowed"));
    }

    return reqSeq;
  }

  static void addExtension(
      ExtensionValues values, ASN1ObjectIdentifier extType,
      ExtensionControl extControl, ASN1Encodable extValue)
      throws CertprofileException {
    if (extValue != null) {
      values.addExtension(extType,
          new ExtensionValue(extControl.isCritical(), extValue));
    } else if (extControl.isRequired()) {
      String description = getExtensionIDDesc(extType);
      if (description == null) {
        description = extType.getId();
      }
      throw new CertprofileException(
          "could not add required extension " + description);
    }
  } // method addExtension

  static String toString(Set<ASN1ObjectIdentifier> oids) {
    if (oids == null) {
      return "null";
    }

    StringBuilder sb = new StringBuilder();
    sb.append("[");

    for (ASN1ObjectIdentifier oid : oids) {
      sb.append(getExtensionIDDesc(oid)).append(", ");
    }

    if (CollectionUtil.isNotEmpty(oids)) {
      int len = sb.length();
      sb.delete(len - 2, len);
    }
    sb.append("]");

    return sb.toString();
  } // method toString

  private static String getExtensionIDDesc(ASN1ObjectIdentifier oid) {
    return ExtensionID.ofOid(oid).getMainAlias();
  }

}
