// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.api.profile.ctrl.RdnControl;
import org.xipki.ca.api.profile.ctrl.StringType;
import org.xipki.ca.api.profile.ctrl.SubjectControl;
import org.xipki.ca.api.profile.ctrl.TextVadidator;
import org.xipki.qa.ValidationIssue;
import org.xipki.security.OIDs;
import org.xipki.security.exception.BadCertTemplateException;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.CollectionUtil;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Subject checker.
 *
 * @author Lijun Liao
 *
 */

public class X509SubjectChecker {

  private final SubjectControl subjectControl;

  public X509SubjectChecker(SubjectControl subjectControl) {
    this.subjectControl = Args.notNull(subjectControl, "subjectControl");
  }

  public List<ValidationIssue> checkSubject(
      X500Name subject, X500Name requestedSubject) {
    Args.notNull(subject, "subject");
    Args.notNull(requestedSubject, "requestedSubject");

    // collect subject attribute types to check
    Set<ASN1ObjectIdentifier> oids = new HashSet<>(subjectControl.getTypes());

    Collections.addAll(oids, subject.getAttributeTypes());

    List<ValidationIssue> result = new LinkedList<>();

    for (ASN1ObjectIdentifier type : oids) {
      ValidationIssue valIssue = createSubjectIssue(type);

      try {
        checkSubjectAttribute(valIssue, type, subject, requestedSubject);
      } catch (BadCertTemplateException ex) {
        valIssue.setFailureMessage(ex.getMessage());
      }
      result.add(valIssue);
    }

    return result;
  } // method checkSubject

  private void checkSubjectAttribute(
      ValidationIssue issue, ASN1ObjectIdentifier type, X500Name subject,
      X500Name requestedSubject) throws BadCertTemplateException {
    // control
    RdnControl rdnControl = subjectControl.getControl(type);
    int minOccurs = (rdnControl == null) ? 0 : rdnControl.getMinOccurs();
    int maxOccurs = (rdnControl == null) ? 0 : rdnControl.getMaxOccurs();

    RDN[] rdns = subject.getRDNs(type);
    int rdnsSize = (rdns == null) ? 0 : rdns.length;

    if (rdnsSize < minOccurs || rdnsSize > maxOccurs) {
      issue.setFailureMessage("number of RDNs '" + rdnsSize
          + "' is not within [" + minOccurs + ", " + maxOccurs + "]");
      return;
    }

    List<String> requestedCoreAtvTextValues = new LinkedList<>();

    RDN[] requestedRdns = requestedSubject.getRDNs(type);
    if (rdnControl == null || rdnControl.getValue() == null) {
      if (requestedRdns != null && requestedRdns.length > 0) {
        for (RDN requestedRdn : requestedRdns) {
          AttributeTypeAndValue firstAtv = requestedRdn.getFirst();
          String textValue =
              getRdnTextValue(firstAtv.getType(), firstAtv.getValue());
          requestedCoreAtvTextValues.add(textValue);
        }
      } else if (rdnControl != null && rdnControl.getValue() != null) {
        requestedCoreAtvTextValues.add(rdnControl.getValue());
      }
    } else {
      requestedCoreAtvTextValues.add(rdnControl.getValue());
    }

    if (rdnsSize == 0) {
      // check optional attribute but is present in requestedSubject
      if (maxOccurs > 0 && !requestedCoreAtvTextValues.isEmpty()) {
        issue.setFailureMessage("is absent but expected present");
      }
      return;
    }

    StringBuilder failureMsg = new StringBuilder();

    // check the encoding
    StringType stringType = rdnControl.getStringType();

    for (int i = 0; i < rdns.length; i++) {
      RDN rdn = rdns[i];
      AttributeTypeAndValue[] atvs = rdn.getTypesAndValues();
      if (atvs.length > 1) {
        failureMsg.append("size of RDN[").append(i).append("] is '")
            .append(atvs.length).append("' but expected '1'");
        failureMsg.append("; ");
        continue;
      }

      String atvTextValue = getAtvValueString("RDN[" + i + "]",
          atvs[0], stringType, failureMsg);
      if (atvTextValue == null) {
        continue;
      }

      checkAttributeTypeAndValue("RDN[" + i + "]", type, atvTextValue,
          rdnControl, requestedCoreAtvTextValues, i, failureMsg);
    }

    int len = failureMsg.length();
    if (len > 2) {
      failureMsg.delete(len - 2, len);
      issue.setFailureMessage(failureMsg.toString());
    }
  } // method checkSubjectAttributeNotMultiValued

  private void checkAttributeTypeAndValue(
      String name, ASN1ObjectIdentifier type, String atvTextValue,
      RdnControl rdnControl, List<String> requestedCoreAtvTextValues,
      int index, StringBuilder failureMsg) {
    Args.notNull(atvTextValue, "atvTextValue");
    if (OIDs.DN.emailAddress.equals(type)) {
      atvTextValue = atvTextValue.toLowerCase();
    }

    if (rdnControl != null) {
      TextVadidator pattern = rdnControl.getPattern();
      if (pattern != null) {
        boolean matches = pattern.isValid(atvTextValue);
        if (!matches) {
          failureMsg.append(name).append(" '").append(atvTextValue)
            .append("' is not valid against regex '")
            .append(pattern.pattern()).append("'; ");
          return;
        }
      }
    }

    if (CollectionUtil.isEmpty(requestedCoreAtvTextValues)) {
      if (!type.equals(OIDs.DN.serialNumber)) {
        failureMsg.append("is present but not contained in the request; ");
      }
    } else {
      String requestedCoreAtvTextValue = requestedCoreAtvTextValues.get(index);
      if (!type.equals(OIDs.DN.serialNumber)) {
        if (requestedCoreAtvTextValue != null
            && type.equals(OIDs.DN.emailAddress)) {
          requestedCoreAtvTextValue = requestedCoreAtvTextValue.toLowerCase();
        }

        if (!atvTextValue.equals(requestedCoreAtvTextValue)) {
          failureMsg.append("content '").append(atvTextValue)
            .append("' but expected '").append(requestedCoreAtvTextValue)
            .append("'; ");
        }
      }
    }
  } // method checkAttributeTypeAndValue

  private static boolean matchStringType(
      ASN1Encodable atvValue, StringType stringType) {
    if (stringType == null) {
      // both PrintableString and UTF8String are allowed.
      return (atvValue instanceof DERPrintableString
          || atvValue instanceof DERUTF8String);
    }

    boolean correctStringType;
    switch (stringType) {
      case printableString:
        correctStringType = (atvValue instanceof DERPrintableString);
        break;
      case utf8String:
        correctStringType = (atvValue instanceof DERUTF8String);
        break;
      case ia5String:
        correctStringType = (atvValue instanceof DERIA5String);
        break;
      default:
        throw new IllegalStateException(
            "should not reach here, unknown StringType " + stringType);
    } // end switch
    return correctStringType;
  } // method matchStringType

  private static String getRdnTextValue(
      ASN1ObjectIdentifier rdnType, ASN1Encodable rdnValue)
      throws BadCertTemplateException {
    if (OIDs.DN.dateOfBirth.equals(rdnType)) {
      if (!(rdnValue instanceof ASN1GeneralizedTime)) {
        throw new BadCertTemplateException(
            "requested RDN is not of GeneralizedTime");
      }
      return ((ASN1GeneralizedTime) rdnValue).getTimeString();
    } else if (OIDs.DN.postalAddress.equals(rdnType)) {
      if (!(rdnValue instanceof ASN1Sequence)) {
        throw new BadCertTemplateException("requested RDN is not of Sequence");
      }

      ASN1Sequence seq = (ASN1Sequence) rdnValue;
      final int n = seq.size();

      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < n; i++) {
        ASN1Encodable obj = seq.getObjectAt(i);
        sb.append("[").append(i).append("]=")
            .append(X509Util.rdnValueToString(obj)).append(",");
      }

      return sb.toString();
    } else {
      return X509Util.rdnValueToString(rdnValue);
    }
  } // method getRdnTextValue

  private static ValidationIssue createSubjectIssue(
      ASN1ObjectIdentifier subjectAttrType) {
    ValidationIssue issue;
    String attrName = OIDs.getName(subjectAttrType);
    if (attrName == null) {
      attrName = subjectAttrType.getId().replace('.', '_');
      issue = new ValidationIssue("X509.SUBJECT." + attrName,
          "attribute " + subjectAttrType.getId());
    } else {
      issue = new ValidationIssue("X509.SUBJECT." + attrName,
          "attribute " + attrName + " (" + subjectAttrType.getId() + ")");
    }
    return issue;
  } // method createSubjectIssue

  private static String getAtvValueString(
      String name, AttributeTypeAndValue atv, StringType stringType,
      StringBuilder failureMsg) throws BadCertTemplateException {
    ASN1Encodable atvValue = atv.getValue();

    if (stringType != null) {
      if (!matchStringType(atvValue, stringType)) {
        failureMsg.append(name).append(" is not of type ")
            .append(stringType.name()).append("; ");
        return null;
      }
    }

    return getRdnTextValue(atv.getType(), atvValue);
  } // method getAtvValueString

}
