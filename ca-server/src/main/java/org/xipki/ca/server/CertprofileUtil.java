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
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.profile.*;
import org.xipki.ca.api.profile.Certprofile.*;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.BaseRequirements;
import org.xipki.security.ObjectIdentifiers.DN;
import org.xipki.util.CollectionUtil;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * CertProfile with identifier.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertprofileUtil {

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

  static boolean containsRdn(X500Name name, ASN1ObjectIdentifier rdnType) {
    RDN[] rdns = name.getRDNs(rdnType);
    return rdns != null && rdns.length > 0;
  } // method containsRdn

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
