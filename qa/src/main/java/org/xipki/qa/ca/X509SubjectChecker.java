// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.xipki.codec.asn1.Asn1GeneralizedTime;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1PrintableString;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.asn1.oid.AttributeOIDs;
import org.xipki.codec.asn1.oid.OIDs;
import org.xipki.pkix.asn1.x500.AttributeTypeAndValue;
import org.xipki.pkix.asn1.x500.RDN;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.ca.api.profile.ctrl.RdnControl;
import org.xipki.ca.api.profile.ctrl.StringType;
import org.xipki.ca.api.profile.ctrl.SubjectControl;
import org.xipki.ca.api.profile.ctrl.TextValidator;
import org.xipki.codec.util.Args;
import org.xipki.qa.ValidationIssue;
import org.xipki.pkix.exception.BadCertTemplateException;
import org.xipki.pkix.util.X509Util;
import org.xipki.pkix.util.misc.CollectionUtil;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * X509 Subject Checker.
 *
 * @author Lijun Liao (xipki)
 */
public class X509SubjectChecker {

  private final SubjectControl subjectControl;

  public X509SubjectChecker(SubjectControl subjectControl) {
    this.subjectControl = Args.notNull(subjectControl, "subjectControl");
  }

  public List<ValidationIssue> checkSubject(X500Name subject, X500Name requestedSubject) {
    Args.notNull(subject, "subject");
    Args.notNull(requestedSubject, "requestedSubject");

    // collect subject attribute types to check
    Set<Asn1Oid> oids = new HashSet<>(subjectControl.types());
    oids.addAll(subject.getAttributeTypes());

    List<ValidationIssue> result = new LinkedList<>();

    for (Asn1Oid type : oids) {
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
      ValidationIssue issue, Asn1Oid type, X500Name subject,
      X500Name requestedSubject) throws BadCertTemplateException {
    // control
    RdnControl rdnControl = subjectControl.getControl(type);
    int minOccurs = (rdnControl == null) ? 0 : rdnControl.minOccurs();
    int maxOccurs = (rdnControl == null) ? 0 : rdnControl.maxOccurs();

    List<RDN> rdns = subject.getRDNs(type);
    int rdnsSize = (rdns == null) ? 0 : rdns.size();

    if (rdnsSize < minOccurs || rdnsSize > maxOccurs) {
      issue.setFailureMessage("number of RDNs '" + rdnsSize
          + "' is not within [" + minOccurs + ", " + maxOccurs + "]");
      return;
    }

    List<String> requestedCoreAtvTextValues = new LinkedList<>();

    List<RDN> requestedRdns = requestedSubject.getRDNs(type);
    if (rdnControl == null || rdnControl.value() == null) {
      if (requestedRdns != null && !requestedRdns.isEmpty()) {
        for (RDN requestedRdn : requestedRdns) {
          AttributeTypeAndValue firstAtv = requestedRdn.getFirst();
          String textValue = getRdnTextValue(firstAtv.getType(), firstAtv.getValue());
          requestedCoreAtvTextValues.add(textValue);
        }
      } else if (rdnControl != null && rdnControl.value() != null) {
        requestedCoreAtvTextValues.add(rdnControl.value());
      }
    } else {
      requestedCoreAtvTextValues.add(rdnControl.value());
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
    StringType stringType = rdnControl.stringType();

    for (int i = 0; i < rdns.size(); i++) {
      RDN rdn = rdns.get(i);
      if (rdn.size() > 1) {
        failureMsg.append("size of RDN[").append(i).append("] is '")
            .append(rdn.size()).append("' but expected '1'");
        failureMsg.append("; ");
        continue;
      }

      String atvTextValue = getAtvValueString("RDN[" + i + "]", rdn.get(0), stringType, failureMsg);
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
      String name, Asn1Oid type, String atvTextValue,
      RdnControl rdnControl, List<String> requestedCoreAtvTextValues,
      int index, StringBuilder failureMsg) {
    Args.notNull(atvTextValue, "atvTextValue");
    if (AttributeOIDs.emailAddress.equals(type)) {
      atvTextValue = atvTextValue.toLowerCase();
    }

    if (rdnControl != null) {
      TextValidator pattern = rdnControl.pattern();
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
      if (!type.equals(AttributeOIDs.serialNumber)) {
        failureMsg.append("is present but not contained in the request; ");
      }
    } else {
      String requestedCoreAtvTextValue = requestedCoreAtvTextValues.get(index);
      if (!type.equals(AttributeOIDs.serialNumber)) {
        if (requestedCoreAtvTextValue != null
            && type.equals(AttributeOIDs.emailAddress)) {
          requestedCoreAtvTextValue = requestedCoreAtvTextValue.toLowerCase();
        }

        if (!atvTextValue.equals(requestedCoreAtvTextValue)) {
          failureMsg.append("content '").append(atvTextValue)
            .append("' but expected '").append(requestedCoreAtvTextValue).append("'; ");
        }
      }
    }
  } // method checkAttributeTypeAndValue

  private static boolean matchStringType(Asn1Primitive atvValue, StringType stringType) {
    if (stringType == null) {
      // both PrintableString and UTF8String are allowed.
      return (atvValue instanceof Asn1PrintableString || atvValue instanceof Asn1Utf8String);
    }

    boolean correctStringType;
    switch (stringType) {
      case printableString:
        correctStringType = (atvValue instanceof Asn1PrintableString);
        break;
      case utf8String:
        correctStringType = (atvValue instanceof Asn1Utf8String);
        break;
      case ia5String:
        correctStringType = (atvValue instanceof Asn1IA5String);
        break;
      default:
        throw new IllegalStateException("should not reach here, unknown StringType " + stringType);
    } // end switch
    return correctStringType;
  } // method matchStringType

  private static String getRdnTextValue(Asn1Oid rdnType, Asn1Primitive rdnValue)
      throws BadCertTemplateException {
    if (AttributeOIDs.dateOfBirth.equals(rdnType)) {
      if (!(rdnValue instanceof Asn1GeneralizedTime)) {
        throw new BadCertTemplateException("requested RDN is not of GeneralizedTime");
      }
      return ((Asn1GeneralizedTime) rdnValue).getText();
    } else if (AttributeOIDs.postalAddress.equals(rdnType)) {
      if (!(rdnValue instanceof Asn1Sequence)) {
        throw new BadCertTemplateException("requested RDN is not of Sequence");
      }

      Asn1Sequence seq = (Asn1Sequence) rdnValue;
      final int n = seq.size();

      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < n; i++) {
        Asn1Primitive obj = seq.getObjectAt(i);
        sb.append("[").append(i).append("]=").append(X509Util.rdnValueToString(obj)).append(",");
      }

      return sb.toString();
    } else {
      return X509Util.rdnValueToString(rdnValue);
    }
  } // method getRdnTextValue

  private static ValidationIssue createSubjectIssue(Asn1Oid subjectAttrType) {
    String attrName = OIDs.getName(subjectAttrType);
    return new ValidationIssue("X509.SUBJECT." + attrName,
          "attribute " + attrName + " (" + subjectAttrType.getId() + ")");
  } // method createSubjectIssue

  private static String getAtvValueString(
      String name, AttributeTypeAndValue atv, StringType stringType, StringBuilder failureMsg)
      throws BadCertTemplateException {
    Asn1Primitive atvValue = atv.getValue();

    if (stringType != null) {
      if (!matchStringType(atvValue, stringType)) {
        failureMsg.append(name).append(" is not of type ").append(stringType.name()).append("; ");
        return null;
      }
    }

    return getRdnTextValue(atv.getType(), atvValue);
  } // method getAtvValueString

}
