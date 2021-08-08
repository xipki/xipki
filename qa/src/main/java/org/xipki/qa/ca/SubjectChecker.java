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

package org.xipki.qa.ca;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.profile.Certprofile.RdnControl;
import org.xipki.ca.api.profile.Certprofile.StringType;
import org.xipki.ca.api.profile.Certprofile.SubjectControl;
import org.xipki.ca.api.profile.TextVadidator;
import org.xipki.qa.ValidationIssue;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.util.X509Util;

import java.util.*;

import static org.xipki.util.Args.notNull;
import static org.xipki.util.CollectionUtil.isEmpty;
import static org.xipki.util.CollectionUtil.isNotEmpty;

/**
 * Subject checker.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SubjectChecker {

  private final SubjectControl subjectControl;

  public SubjectChecker(SubjectControl subjectControl) {
    this.subjectControl = notNull(subjectControl, "subjectControl");
  }

  public List<ValidationIssue> checkSubject(X500Name subject, X500Name requestedSubject) {
    notNull(subject, "subject");
    notNull(requestedSubject, "requestedSubject");

    // collect subject attribute types to check
    Set<ASN1ObjectIdentifier> oids = new HashSet<>();

    for (ASN1ObjectIdentifier oid : subjectControl.getTypes()) {
      if (!subjectControl.getControl(oid).isNotInSubject()) {
        oids.add(oid);
      }
    }

    Collections.addAll(oids, subject.getAttributeTypes());

    List<ValidationIssue> result = new LinkedList<>();

    ValidationIssue issue = new ValidationIssue("X509.SUBJECT.group", "X509 subject RDN group");
    result.add(issue);
    if (isNotEmpty(subjectControl.getGroups())) {
      Set<String> groups = new HashSet<>(subjectControl.getGroups());
      for (String g : groups) {
        boolean toBreak = false;
        RDN rdn = null;
        for (ASN1ObjectIdentifier type : subjectControl.getTypesForGroup(g)) {
          RDN[] rdns = subject.getRDNs(type);
          if (rdns == null || rdns.length == 0) {
            continue;
          }

          if (rdns.length > 1) {
            issue.setFailureMessage("AttributeTypeAndValues of group " + g + " is not in one RDN");
            toBreak = true;
            break;
          }

          if (rdn == null) {
            rdn = rdns[0];
          } else if (rdn != rdns[0]) {
            issue.setFailureMessage("AttributeTypeAndValues of group " + g + " is not in one RDN");
            toBreak = true;
            break;
          }
        }

        if (toBreak) {
          break;
        }
      }
    }

    for (ASN1ObjectIdentifier type : oids) {
      ValidationIssue valIssue;
      try {
        valIssue = checkSubjectAttribute(type, subject, requestedSubject);
      } catch (BadCertTemplateException ex) {
        valIssue = new ValidationIssue("X509.SUBJECT.REQUEST", "Subject in request");
        valIssue.setFailureMessage(ex.getMessage());
      }
      result.add(valIssue);
    }

    return result;
  } // method checkSubject

  private ValidationIssue checkSubjectAttribute(ASN1ObjectIdentifier type, X500Name subject,
      X500Name requestedSubject)
          throws BadCertTemplateException {
    boolean multiValuedRdn = subjectControl.getGroup(type) != null;
    if (multiValuedRdn) {
      return checkSubjectAttributeMultiValued(type, subject, requestedSubject);
    } else {
      return checkSubjectAttributeNotMultiValued(type, subject, requestedSubject);
    }
  } // method checkSubjectAttribute

  private ValidationIssue checkSubjectAttributeNotMultiValued(ASN1ObjectIdentifier type,
      X500Name subject, X500Name requestedSubject)
          throws BadCertTemplateException {
    ValidationIssue issue = createSubjectIssue(type);

    // control
    RdnControl rdnControl = subjectControl.getControl(type);
    int minOccurs = (rdnControl == null) ? 0 : rdnControl.getMinOccurs();
    int maxOccurs = (rdnControl == null) ? 0 : rdnControl.getMaxOccurs();

    RDN[] rdns = subject.getRDNs(type);
    int rdnsSize = (rdns == null) ? 0 : rdns.length;

    if (rdnsSize < minOccurs || rdnsSize > maxOccurs) {
      issue.setFailureMessage("number of RDNs '" + rdnsSize
          + "' is not within [" + minOccurs + ", " + maxOccurs + "]");
      return issue;
    }

    List<String> requestedCoreAtvTextValues = new LinkedList<>();

    RDN[] requestedRdns = requestedSubject.getRDNs(type);
    if (rdnControl == null || rdnControl.isValueOverridable()) {
      if (requestedRdns != null && requestedRdns.length > 0) {
        for (RDN requestedRdn : requestedRdns) {
          String textValue = getRdnTextValueOfRequest(requestedRdn);
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
      return issue;
    }

    StringBuilder failureMsg = new StringBuilder();

    // check the encoding
    StringType stringType = null;
    if (rdnControl != null) {
      stringType = rdnControl.getStringType();
    }

    for (int i = 0; i < rdns.length; i++) {
      RDN rdn = rdns[i];
      AttributeTypeAndValue[] atvs = rdn.getTypesAndValues();
      if (atvs.length > 1) {
        failureMsg.append("size of RDN[").append(i).append("] is '")
                .append(atvs.length).append("' but expected '1'");
        failureMsg.append("; ");
        continue;
      }

      String atvTextValue = getAtvValueString("RDN[" + i + "]", atvs[0], stringType, failureMsg);
      if (atvTextValue == null) {
        continue;
      }

      checkAttributeTypeAndValue("RDN[" + i + "]", type, atvTextValue, rdnControl,
          requestedCoreAtvTextValues, i, failureMsg);
    }

    int len = failureMsg.length();
    if (len > 2) {
      failureMsg.delete(len - 2, len);
      issue.setFailureMessage(failureMsg.toString());
    }

    return issue;
  } // method checkSubjectAttributeNotMultiValued

  private ValidationIssue checkSubjectAttributeMultiValued(ASN1ObjectIdentifier type,
      X500Name subject, X500Name requestedSubject)
          throws BadCertTemplateException {
    ValidationIssue issue = createSubjectIssue(type);

    RDN[] rdns = subject.getRDNs(type);
    int rdnsSize = (rdns == null) ? 0 : rdns.length;

    RDN[] requestedRdns = requestedSubject.getRDNs(type);

    if (rdnsSize != 1) {
      if (rdnsSize == 0) {
        // check optional attribute but is present in requestedSubject
        if (requestedRdns != null && requestedRdns.length > 0) {
          issue.setFailureMessage("is absent but expected present");
        }
      } else {
        issue.setFailureMessage("number of RDNs '" + rdnsSize + "' is not 1");
      }
      return issue;
    }

    // control
    final RdnControl rdnControl = subjectControl.getControl(type);

    // check the encoding
    StringType stringType = null;
    if (rdnControl != null) {
      stringType = rdnControl.getStringType();
    }
    List<String> requestedCoreAtvTextValues = new LinkedList<>();
    if (requestedRdns != null) {
      for (RDN requestedRdn : requestedRdns) {
        String textValue = getRdnTextValueOfRequest(requestedRdn);
        requestedCoreAtvTextValues.add(textValue);
      }
    }

    StringBuilder failureMsg = new StringBuilder();

    AttributeTypeAndValue[] li = rdns[0].getTypesAndValues();
    List<AttributeTypeAndValue> atvs = new LinkedList<>();
    for (AttributeTypeAndValue m : li) {
      if (type.equals(m.getType())) {
        atvs.add(m);
      }
    }

    final int atvsSize = atvs.size();

    int minOccurs = (rdnControl == null) ? 0 : rdnControl.getMinOccurs();
    int maxOccurs = (rdnControl == null) ? 0 : rdnControl.getMaxOccurs();

    if (atvsSize < minOccurs || atvsSize > maxOccurs) {
      issue.setFailureMessage("number of AttributeTypeAndValuess '" + atvsSize
          + "' is not within [" + minOccurs + ", " + maxOccurs + "]");
      return issue;
    }

    for (int i = 0; i < atvsSize; i++) {
      AttributeTypeAndValue atv = atvs.get(i);
      String atvTextValue = getAtvValueString("AttributeTypeAndValue[" + i + "]", atv,
          stringType, failureMsg);
      if (atvTextValue == null) {
        continue;
      }

      checkAttributeTypeAndValue("AttributeTypeAndValue[" + i + "]", type, atvTextValue,
          rdnControl, requestedCoreAtvTextValues, i, failureMsg);
    }

    int len = failureMsg.length();
    if (len > 2) {
      failureMsg.delete(len - 2, len);
      issue.setFailureMessage(failureMsg.toString());
    }

    return issue;
  } // method checkSubjectAttributeMultiValued

  private void checkAttributeTypeAndValue(String name, ASN1ObjectIdentifier type,
      String atvTextValue, RdnControl rdnControl, List<String> requestedCoreAtvTextValues,
      int index, StringBuilder failureMsg)
          throws BadCertTemplateException {
    if (atvTextValue != null && ObjectIdentifiers.DN.emailAddress.equals(type)) {
      atvTextValue = atvTextValue.toLowerCase();
    }

    if (ObjectIdentifiers.DN.dateOfBirth.equals(type)) {
      if (!TextVadidator.DATE_OF_BIRTH.isValid(atvTextValue)) {
        throw new BadCertTemplateException(
            "Value of RDN dateOfBirth does not have format YYYMMDD000000Z");
      }
    } else if (rdnControl != null) {
      String prefix = rdnControl.getPrefix();
      if (prefix != null) {
        if (!atvTextValue.startsWith(prefix)) {
          failureMsg.append(name).append(" '").append(atvTextValue)
            .append("' does not start with prefix '").append(prefix).append("'; ");
          return;
        } else {
          atvTextValue = atvTextValue.substring(prefix.length());
        }
      }

      String suffix = rdnControl.getSuffix();
      if (suffix != null) {
        if (!atvTextValue.endsWith(suffix)) {
          failureMsg.append(name).append(" '").append(atvTextValue)
            .append("' does not end with suffix '").append(suffix).append("'; ");
          return;
        } else {
          atvTextValue = atvTextValue.substring(0,
              atvTextValue.length() - suffix.length());
        }
      }

      TextVadidator pattern = rdnControl.getPattern();
      if (pattern != null) {
        boolean matches = pattern.isValid(atvTextValue);
        if (!matches) {
          failureMsg.append(name).append(" '").append(atvTextValue)
            .append("' is not valid against regex '").append(pattern.pattern()).append("'; ");
          return;
        }
      }
    }

    if (isEmpty(requestedCoreAtvTextValues)) {
      if (!type.equals(ObjectIdentifiers.DN.serialNumber)) {
        failureMsg.append("is present but not contained in the request; ");
      }
    } else {
      String requestedCoreAtvTextValue = requestedCoreAtvTextValues.get(index);
      if (!type.equals(ObjectIdentifiers.DN.serialNumber)) {
        if (requestedCoreAtvTextValue != null && type.equals(ObjectIdentifiers.DN.emailAddress)) {
          requestedCoreAtvTextValue = requestedCoreAtvTextValue.toLowerCase();
        }

        if (!atvTextValue.equals(requestedCoreAtvTextValue)) {
          failureMsg.append("content '").append(atvTextValue)
            .append("' but expected '").append(requestedCoreAtvTextValue).append("'; ");
        }
      }
    }
  } // method checkAttributeTypeAndValue

  private static boolean matchStringType(ASN1Encodable atvValue, StringType stringType) {
    if (stringType == null) {
      // both PrintableString and UTF8String are allowed.
      return (atvValue instanceof DERPrintableString || atvValue instanceof DERUTF8String);
    }

    boolean correctStringType = true;
    switch (stringType) {
      case bmpString:
        correctStringType = (atvValue instanceof DERBMPString);
        break;
      case printableString:
        correctStringType = (atvValue instanceof DERPrintableString);
        break;
      case teletexString:
        correctStringType = (atvValue instanceof DERT61String);
        break;
      case utf8String:
        correctStringType = (atvValue instanceof DERUTF8String);
        break;
      case ia5String:
        correctStringType = (atvValue instanceof DERIA5String);
        break;
      default:
        throw new IllegalStateException("should not reach here, unknown StringType " + stringType);
    } // end switch
    return correctStringType;
  } // method matchStringType

  private static String getRdnTextValueOfRequest(RDN requestedRdn)
      throws BadCertTemplateException {
    ASN1ObjectIdentifier type = requestedRdn.getFirst().getType();
    ASN1Encodable vec = requestedRdn.getFirst().getValue();
    if (ObjectIdentifiers.DN.dateOfBirth.equals(type)) {
      if (!(vec instanceof ASN1GeneralizedTime)) {
        throw new BadCertTemplateException("requested RDN is not of GeneralizedTime");
      }
      return ((ASN1GeneralizedTime) vec).getTimeString();
    } else if (ObjectIdentifiers.DN.postalAddress.equals(type)) {
      if (!(vec instanceof ASN1Sequence)) {
        throw new BadCertTemplateException("requested RDN is not of Sequence");
      }

      ASN1Sequence seq = (ASN1Sequence) vec;
      final int n = seq.size();

      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < n; i++) {
        ASN1Encodable obj = seq.getObjectAt(i);
        String textValue = X509Util.rdnValueToString(obj);
        sb.append("[").append(i).append("]=").append(textValue).append(",");
      }

      return sb.toString();
    } else {
      return X509Util.rdnValueToString(vec);
    }
  } // method getRdnTextValueOfRequest

  private static ValidationIssue createSubjectIssue(ASN1ObjectIdentifier subjectAttrType) {
    ValidationIssue issue;
    String attrName = ObjectIdentifiers.getName(subjectAttrType);
    if (attrName == null) {
      attrName = subjectAttrType.getId().replace('.', '_');
      issue = new ValidationIssue("X509.SUBJECT." + attrName, "attribute "
          + subjectAttrType.getId());
    } else {
      issue = new ValidationIssue("X509.SUBJECT." + attrName, "attribute " + attrName
          + " (" + subjectAttrType.getId() + ")");
    }
    return issue;
  } // method createSubjectIssue

  private static String getAtvValueString(String name, AttributeTypeAndValue atv,
      StringType stringType, StringBuilder failureMsg) {
    ASN1ObjectIdentifier type = atv.getType();
    ASN1Encodable atvValue = atv.getValue();

    if (ObjectIdentifiers.DN.dateOfBirth.equals(type)) {
      if (!(atvValue instanceof ASN1GeneralizedTime)) {
        failureMsg.append(name).append(" is not of type GeneralizedTime; ");
        return null;
      }
      return ((ASN1GeneralizedTime) atvValue).getTimeString();
    } else if (ObjectIdentifiers.DN.postalAddress.equals(type)) {
      if (!(atvValue instanceof ASN1Sequence)) {
        failureMsg.append(name).append(" is not of type Sequence; ");
        return null;
      }

      ASN1Sequence seq = (ASN1Sequence) atvValue;
      final int n = seq.size();

      StringBuilder sb = new StringBuilder();
      boolean validEncoding = true;
      for (int i = 0; i < n; i++) {
        ASN1Encodable obj = seq.getObjectAt(i);
        if (!matchStringType(obj, stringType)) {
          failureMsg.append(name).append(".[").append(i).append("] is not of type ")
            .append(stringType.name()).append("; ");
          validEncoding = false;
          break;
        }

        String textValue = X509Util.rdnValueToString(obj);
        sb.append("[").append(i).append("]=").append(textValue).append(",");
      }

      if (!validEncoding) {
        return null;
      }

      return sb.toString();
    } else {
      if (!matchStringType(atvValue, stringType)) {
        failureMsg.append(name).append(" is not of type " + stringType.name()).append("; ");
        return null;
      }

      return X509Util.rdnValueToString(atvValue);
    }
  } // method getAtvValueString

}
