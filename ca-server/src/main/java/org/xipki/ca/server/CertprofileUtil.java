// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.AttributeOIDs;
import org.xipki.codec.asn1.oid.CertPolicyOIDs;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.asn1.oid.OIDs;
import org.xipki.pkix.asn1.util.IETFUtils;
import org.xipki.pkix.asn1.x500.RDN;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.AccessDescription;
import org.xipki.pkix.asn1.x509.CertificatePolicies;
import org.xipki.pkix.asn1.x509.ExtendedKeyUsage;
import org.xipki.pkix.asn1.x509.Extension;
import org.xipki.pkix.asn1.x509.PolicyInformation;
import org.xipki.pkix.asn1.x509.SubjectInfoAccessSyntax;
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
import org.xipki.pkix.exception.BadCertTemplateException;
import org.xipki.pkix.cert.KeyUsage;
import org.xipki.ca.api.CertprofileException;
import org.xipki.pkix.util.misc.CollectionUtil;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Certprofile Util.
 *
 * @author Lijun Liao (xipki)
 */
public class CertprofileUtil {

  public static SubjectInfo getSubject(Certprofile certprofile, X500Name requestedSubject)
      throws BadCertTemplateException {
    SubjectInfo subjectInfo = certprofile.subject(requestedSubject);

    if (certprofile.certDomain() == CertDomain.CABForumBR) {
      checkCABForumBR(certprofile, subjectInfo.grantedSubject());
    }

    // check the country
    Asn1Oid[] countryOids = new Asn1Oid[] {
        AttributeOIDs.country, AttributeOIDs.countryOfCitizenship,
        AttributeOIDs.countryOfResidence, AttributeOIDs.jurIncorporationCountry};

    Asn1Oid errorOid = null;
    String errorCountry = null;
    for (Asn1Oid oid : countryOids) {
      X500Name gs = subjectInfo.grantedSubject();
      List<RDN> countryRdns = gs.getRDNs(oid);
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
      throw new BadCertTemplateException("invalid country/area code '" +
          errorCountry + "' in subject attribute " + name);
    }

    return subjectInfo;
  } // method getSubject

  private static void checkCABForumBR(Certprofile certprofile, X500Name subject)
      throws BadCertTemplateException {
    if (certprofile.certLevel() == CertLevel.EndEntity) {
      // extract the policyIdentifier
      CertificatePolicies policies = certprofile.certificatePolicies();
      Asn1Oid policyId = null;
      if (policies != null) {
        for (PolicyInformation m : policies) {
          Asn1Oid pid = m.getPolicyIdentifier();
          if (CertPolicyOIDs.id_domain_validated.equals(pid)
              || CertPolicyOIDs.id_organization_validated.equals(pid)
              || CertPolicyOIDs.id_individual_validated.equals(pid)) {
            policyId = pid;
            break;
          }
        }
      }

      // subject:street
      if (containsRdn(subject, AttributeOIDs.street)) {
        if (!containsRdn(subject, AttributeOIDs.organization)
            && !containsRdn(subject, AttributeOIDs.givenName)
            && !containsRdn(subject, AttributeOIDs.surname)) {
          throw new BadCertTemplateException(
              "subject:street is prohibited if the subject:organizationName field, " +
              "subject:givenName, and subject:surname field are absent.");
        }
      }

      // subject:localityName
      if (containsRdn(subject, AttributeOIDs.locality)) {
        if (!containsRdn(subject, AttributeOIDs.organization)
            && !containsRdn(subject, AttributeOIDs.givenName)
            && !containsRdn(subject, AttributeOIDs.surname)) {
          throw new BadCertTemplateException(
              "subject:localityName is prohibited if the subject:organizationName field, " +
                  "subject:givenName, and subject:surname field are absent.");
        }
      } else {
        if (!containsRdn(subject, AttributeOIDs.state) &&
            (containsRdn(subject, AttributeOIDs.organization)
                || containsRdn(subject, AttributeOIDs.givenName)
                || containsRdn(subject, AttributeOIDs.surname))) {
          throw new BadCertTemplateException(
              "subject:localityName is required if the subject:organizationName field, " +
                  "subject:givenName field, or subject:surname field are present and the " +
                  "subject:stateOrProvinceName field is absent.");
        }
      }

      // subject:stateOrProvinceName
      if (containsRdn(subject, AttributeOIDs.state)) {
        if (!containsRdn(subject, AttributeOIDs.organization)
            && !containsRdn(subject, AttributeOIDs.givenName)
            && !containsRdn(subject, AttributeOIDs.surname)) {
          throw new BadCertTemplateException(
              "subject:stateOrProvinceName is prohibited if the subject:organizationName field, " +
                  "subject:givenName, and subject:surname field are absent.");
        }
      } else {
        if (!containsRdn(subject, AttributeOIDs.locality) &&
            (containsRdn(subject, AttributeOIDs.organization)
                || containsRdn(subject, AttributeOIDs.givenName)
                || containsRdn(subject, AttributeOIDs.surname))) {
          throw new BadCertTemplateException(
              "subject:stateOrProvinceName is required if the subject:organizationName field, " +
                  "subject:givenName field, or subject:surname field are present and the " +
                  "subject:localityName field is absent.");
        }
      }

      // subject:postalCode
      if (containsRdn(subject, AttributeOIDs.postalCode)) {
        if (!containsRdn(subject, AttributeOIDs.organization)
            && !containsRdn(subject, AttributeOIDs.givenName)
            && !containsRdn(subject, AttributeOIDs.surname)) {
          throw new BadCertTemplateException(
              "subject:postalCode is prohibited if the subject:organizationName field, " +
                  "subject:givenName, and subject:surname field are absent.");
        }
      }

      // subject:countryCode
      if (!containsRdn(subject, AttributeOIDs.country)) {
        if (containsRdn(subject, AttributeOIDs.organization)
            || containsRdn(subject, AttributeOIDs.givenName)
            || containsRdn(subject, AttributeOIDs.surname)) {
          throw new BadCertTemplateException(
              "subject:countryCode is required if the subject:organizationName field, " +
                  "subject:givenName, and subject:surname field are present");
        }
      }

      if (CertPolicyOIDs.id_domain_validated.equals(policyId)) {
        Asn1Oid[] excludeSubjectFields =
            new Asn1Oid[] {
                AttributeOIDs.organization, AttributeOIDs.givenName, AttributeOIDs.surname,
                AttributeOIDs.street,       AttributeOIDs.locality,  AttributeOIDs.state,
                AttributeOIDs.postalCode};
        for (Asn1Oid m : excludeSubjectFields) {
          if (containsRdn(subject, m)) {
            throw new BadCertTemplateException("subject " + OIDs.getName(m)
                + " is prohibited in domain validated certificate");
          }
        }
      } else if (CertPolicyOIDs.id_organization_validated.equals(policyId)) {
        Asn1Oid[] includeSubjectFields =
            new Asn1Oid[] {AttributeOIDs.organization, AttributeOIDs.country};

        for (Asn1Oid m : includeSubjectFields) {
          if (!containsRdn(subject, m)) {
            throw new BadCertTemplateException("subject " + OIDs.getName(m)
                + " is required in organization validated certificate");
          }
        }

        if (!(containsRdn(subject, AttributeOIDs.locality)
            || containsRdn(subject, AttributeOIDs.state))) {
          throw new BadCertTemplateException("at least one of subject:localityName and " +
              "subject:stateOrProvinceName is required in organization validated certificate");
        }
      } else if (CertPolicyOIDs.id_individual_validated.equals(policyId)) {
        Asn1Oid[] includeSubjectFields = new Asn1Oid[] {AttributeOIDs.country};
        for (Asn1Oid m : includeSubjectFields) {
          if (!containsRdn(subject, m)) {
            throw new BadCertTemplateException("subject " + OIDs.getName(m)
                + " is required in individual validated certificate");
          }
        }

        if (!(containsRdn(subject, AttributeOIDs.organization)
            || (containsRdn(subject, AttributeOIDs.givenName)
                  && containsRdn(subject, AttributeOIDs.surname)))) {
          throw new BadCertTemplateException("at least one of subject:organizationName and " +
            "(subject:givenName, subject:surName) is required in individual validated certificate");
        }

        if (!(containsRdn(subject, AttributeOIDs.locality)
            || containsRdn(subject, AttributeOIDs.state))) {
          throw new BadCertTemplateException("at least one of subject:localityName and " +
              "subject:stateOrProvinceName is required in individual validated certificate");
        }
      }
    } else {
      Asn1Oid[] requiredTypes = new Asn1Oid[] {
          AttributeOIDs.commonName, AttributeOIDs.organization, AttributeOIDs.country};
      for (Asn1Oid m : requiredTypes) {
        if (!containsRdn(subject, AttributeOIDs.commonName)) {
          throw new BadCertTemplateException("missing " + OIDs.getName(m) + " in subject");
        }
      }
    }
  }

  static boolean containsRdn(X500Name name, Asn1Oid rdnType) {
    List<RDN> rdns = name.getRDNs(rdnType);
    return rdns != null && !rdns.isEmpty();
  }

  static void addRequestedKeyusage(
      Set<KeyUsage> usages, Map<Asn1Oid, Extension> requestedExtensions,
      Set<KeySingleUsage> usageOccs) {
    Extension extension = requestedExtensions.get(ExtensionOIDs.keyUsage);
    if (extension == null) {
      return;
    }

    org.xipki.pkix.asn1.x509.KeyUsage reqX509 = extension.getKeyUsage();
    for (KeySingleUsage k : usageOccs) {
      if (k.isRequired()) {
        continue;
      }

      if (reqX509.hasFlag(k.keyUsage().asn1())) {
        usages.add(k.keyUsage());
      }
    }
  } // method addRequestedKeyusage

  static void addRequestedExtKeyusage(
      List<Asn1Oid> usages, Map<Asn1Oid, Extension> requestedExtensions,
      Set<ExtKeyUsageControl> usageOccs) {
    Extension extension = requestedExtensions.get(ExtensionOIDs.extendedKeyUsage);
    if (extension == null) {
      return;
    }

    ExtendedKeyUsage reqKeyUsage = extension.getExtendedKeyUsage();
    for (ExtKeyUsageControl k : usageOccs) {
      if (k.isRequired()) {
        continue;
      }

      if (reqKeyUsage.hasKeyPurposeId(k.extKeyUsage())) {
        usages.add(k.extKeyUsage());
      }
    }
  } // method addRequestedExtKeyusage

  static SubjectInfoAccessSyntax createSubjectInfoAccess(
      Map<Asn1Oid, Extension> requestedExtensions,
      Map<Asn1Oid, Set<GeneralNameTag>> modes)
      throws BadCertTemplateException {
    if (modes == null) {
      return null;
    }

    Extension extn = requestedExtensions.get(ExtensionOIDs.subjectInfoAccess);
    if (extn == null) {
      return null;
    }

    SubjectInfoAccessSyntax sia = extn.getSubjectInfoAccess();
    for (AccessDescription ad : sia) {
      Asn1Oid accessMethod = ad.getAccessMethod();
      Optional.ofNullable(modes.get(accessMethod)).orElseThrow(() ->
          new BadCertTemplateException("subjectInfoAccess.accessMethod "
              + accessMethod.getId() + " is not allowed"));
    }

    return sia;
  }

  static void addExtension(
      ExtensionValues values, Asn1Oid extType,
      ExtensionControl extControl, Asn1Encodable extValue) throws CertprofileException {
    if (extValue != null) {
      values.addExtension(extType, ExtensionValue.build(extControl.isCritical(), extValue));
    } else if (extControl.isRequired()) {
      String description = getExtensionIDDesc(extType);
      if (description == null) {
        description = extType.getId();
      }
      throw new CertprofileException("could not add required extension " + description);
    }
  } // method addExtension

  static String toString(Set<Asn1Oid> oids) {
    if (oids == null) {
      return "null";
    }

    StringBuilder sb = new StringBuilder();
    sb.append("[");

    for (Asn1Oid oid : oids) {
      sb.append(getExtensionIDDesc(oid)).append(", ");
    }

    if (CollectionUtil.isNotEmpty(oids)) {
      int len = sb.length();
      sb.delete(len - 2, len);
    }
    sb.append("]");

    return sb.toString();
  } // method toString

  private static String getExtensionIDDesc(Asn1Oid oid) {
    return ExtensionID.ofOid(oid).mainAlias();
  }

}
