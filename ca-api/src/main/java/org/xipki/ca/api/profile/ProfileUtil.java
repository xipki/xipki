// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.ca.api.profile.ctrl.RdnControl;
import org.xipki.ca.api.profile.ctrl.StringType;
import org.xipki.ca.api.profile.ctrl.SubjectControl;
import org.xipki.ca.api.profile.ctrl.SubjectInfo;
import org.xipki.ca.api.profile.ctrl.TextVadidator;
import org.xipki.ca.api.profile.id.AttributeType;
import org.xipki.security.OIDs;
import org.xipki.security.exception.BadCertTemplateException;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.type.Range;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Base Certprofile.
 *
 * @author Lijun Liao (xipki)
 */

public class ProfileUtil {

  public static SubjectInfo getSubject(
      X500Name requestedSubject, SubjectControl scontrol)
      throws BadCertTemplateException {
    Args.notNull(requestedSubject, "requestedSubject");

    RDN[] requestedRdns = requestedSubject.getRDNs();

    List<RDN> rdns = new LinkedList<>();

    for (ASN1ObjectIdentifier type : scontrol.types()) {
      RdnControl control = scontrol.getControl(type);
      if (control == null || control.maxOccurs() < 1) {
        continue;
      }

      String cvalue = control.value();
      RDN[] thisRdns = getRdns(requestedRdns, type);
      int requestedRdnNum = thisRdns == null ? 0 : thisRdns.length;

      if (cvalue == null) {
        if (requestedRdnNum == 0) {
          // not requested and no set in the control
          continue;
        }
      } else {
        if (requestedRdnNum > 0) {
          throw new BadCertTemplateException(requestedRdnNum + " RDNs of type "
              + OIDs.getName(type) + " are requested, but none is allowed.");
        }
      }

      if (cvalue != null) {
        rdns.add(new RDN(type, createRdnValue(type, cvalue, control)));
      } else {
        // cvalue must be null here.
        for (int i = 0; i < requestedRdnNum; i++) {
          ASN1Encodable value = thisRdns[i].getFirst().getValue();
          RDN rdn = createSubjectRdn(type, value, control);
          rdns.add(rdn);
        }
      }
    } // for

    X500Name grantedSubject = new X500Name(rdns.toArray(new RDN[0]));
    return new SubjectInfo(grantedSubject, null);
  } // method getSubject

  private static RDN createSubjectRdn(
      ASN1ObjectIdentifier type, ASN1Encodable value, RdnControl option)
      throws BadCertTemplateException {
    if (AttributeType.postalAddress.oid().equals(type)) {
      return createPostalAddressRdn(type, value, option);
    } else if (AttributeType.dateOfBirth.oid().equals(type)) {
      return createDateOfBirthRdn(type, value);
    } else {
      String text = X509Util.rdnValueToString(value);
      return new RDN(type, createRdnValue(type, text, option));
    }
  } // method createSubjectRdn

  private static RDN createDateOfBirthRdn(
      ASN1ObjectIdentifier type, ASN1Encodable rdnValue)
      throws BadCertTemplateException {
    Args.notNull(type, "type");

    String text;
    ASN1Encodable newRdnValue = null;
    if (rdnValue instanceof ASN1GeneralizedTime) {
      text = ((ASN1GeneralizedTime) rdnValue).getTimeString();
      newRdnValue = rdnValue;
    } else if (rdnValue instanceof ASN1String
        && !(rdnValue instanceof DERUniversalString)) {
      text = ((ASN1String) rdnValue).getString();
    } else {
      throw new BadCertTemplateException(
          "Value of RDN dateOfBirth has incorrect syntax");
    }

    if (!TextVadidator.DATE_OF_BIRTH.isValid(text)) {
      throw new BadCertTemplateException(
          "Value of RDN dateOfBirth does not have format YYYMMDD000000Z");
    }

    if (newRdnValue == null) {
      newRdnValue = new DERGeneralizedTime(text);
    }

    return new RDN(type, newRdnValue);
  } // method createDateOfBirthRdn

  private static RDN createPostalAddressRdn(
      ASN1ObjectIdentifier type, ASN1Encodable rdnValue, RdnControl control)
      throws BadCertTemplateException {
    Args.notNull(type, "type");

    if (!(rdnValue instanceof ASN1Sequence)) {
      throw new BadCertTemplateException(
          "rdnValue of RDN postalAddress has incorrect syntax");
    }

    ASN1Sequence seq = (ASN1Sequence) rdnValue;
    final int size = seq.size();
    if (size < 1 || size > 6) {
      throw new BadCertTemplateException(
          "Sequence size of RDN postalAddress is not within [1, 6]: " + size);
    }

    ASN1EncodableVector vec = new ASN1EncodableVector();
    for (int i = 0; i < size; i++) {
      ASN1Encodable line = seq.getObjectAt(i);
      String text;
      if (line instanceof ASN1String && !(line instanceof DERUniversalString)) {
        text = ((ASN1String) line).getString();
      } else {
        throw new BadCertTemplateException(String.format(
            "postalAddress[%d] has incorrect syntax", i));
      }

      vec.add(createRdnValue(type, text, control));
    }

    return new RDN(type, new DERSequence(vec));
  } // method createPostalAddressRdn

  /**
   * Creates GeneralName.
   *
   * @param requestedName
   *        Requested name. Must not be {@code null}.
   * @param modes
   *        Modes to be considered. Must not be {@code null}.
   * @return the created GeneralName
   * @throws BadCertTemplateException
   *         If requestedName is invalid or contains entries which are
   *         not allowed in the modes.
   */
  public static GeneralName createGeneralName(
      GeneralName requestedName, Set<GeneralNameTag> modes)
      throws BadCertTemplateException {
    Args.notNull(requestedName, "requestedName");

    int tag = requestedName.getTagNo();
    if (tag != GeneralName.otherName) {
      GeneralNameTag mode = null;

      if (modes != null) {
        for (GeneralNameTag m : modes) {
          if (m.tag() == tag) {
            mode = m;
            break;
          }
        }

        if (mode == null) {
          throw new BadCertTemplateException(
              "generalName tag " + tag + " is not allowed");
        }
      }

      switch (tag) {
        case GeneralName.rfc822Name:
        case GeneralName.dNSName:
        case GeneralName.uniformResourceIdentifier:
        case GeneralName.iPAddress:
        case GeneralName.registeredID:
        case GeneralName.directoryName:
          return new GeneralName(tag, requestedName.getName());
        case GeneralName.ediPartyName: {
          ASN1Sequence reqSeq =
              ASN1Sequence.getInstance(requestedName.getName());

          int size = reqSeq.size();
          String nameAssigner = null;
          int idx = 0;
          if (size > 1) {
            nameAssigner = DirectoryString.getInstance(
                ASN1TaggedObject.getInstance(reqSeq.getObjectAt(idx++))
                    .getBaseObject())
                .getString();
          }

          String partyName = DirectoryString.getInstance(
              ASN1TaggedObject.getInstance(reqSeq.getObjectAt(idx))
                  .getBaseObject())
              .getString();

          ASN1EncodableVector vector = new ASN1EncodableVector();
          if (nameAssigner != null) {
            vector.add(new DERTaggedObject(false, 0,
                new DirectoryString(nameAssigner)));
          }
          vector.add(new DERTaggedObject(false, 1,
              new DirectoryString(partyName)));
          return new GeneralName(GeneralName.ediPartyName,
              new DERSequence(vector));
        }
        default:
          throw new IllegalStateException(
              "should not reach here, unknown GeneralName tag " + tag);
      }
    } else {
      ASN1Sequence reqSeq = ASN1Sequence.getInstance(requestedName.getName());
      int size = reqSeq.size();
      if (size != 2) {
        throw new BadCertTemplateException(
            "invalid otherName sequence: size is not 2: " + size);
      }

      ASN1ObjectIdentifier type =
          ASN1ObjectIdentifier.getInstance(reqSeq.getObjectAt(0));
      String typeText = type.getId();

      boolean permitted = isPermitted(modes, typeText);

      if (!permitted) {
        throw new BadCertTemplateException(
            "otherName with type " + typeText + " is not allowed");
      }

      ASN1Encodable asn1 = reqSeq.getObjectAt(1);
      if (!(asn1 instanceof ASN1TaggedObject)) {
        throw new BadCertTemplateException(
            "otherName.value is not tagged Object");
      }

      int tagNo = ASN1TaggedObject.getInstance(asn1).getTagNo();
      if (tagNo != 0) {
        throw new BadCertTemplateException(
            "otherName.value does not have tag 0: " + tagNo);
      }

      ASN1EncodableVector vector = new ASN1EncodableVector();
      vector.add(type);
      vector.add(new DERTaggedObject(true, 0,
          ASN1TaggedObject.getInstance(asn1).getBaseObject()));
      return new GeneralName(GeneralName.otherName, new DERSequence(vector));
    }
  } // method createGeneralName

  private static boolean isPermitted(
      Set<GeneralNameTag> modes, String typeText) {
    return modes.contains(GeneralNameTag.otherName);
  }

  private static RDN[] getRdns(RDN[] rdns, ASN1ObjectIdentifier type) {
    Args.notNull(rdns, "rdns");
    Args.notNull(type, "type");

    List<RDN> ret = new ArrayList<>(1);
    for (RDN rdn : rdns) {
      if (rdn.getFirst().getType().equals(type)) {
        ret.add(rdn);
      }
    }

    return CollectionUtil.isEmpty(ret) ? null : ret.toArray(new RDN[0]);
  } // method getRdns

  private static ASN1Encodable createRdnValue(
      ASN1ObjectIdentifier type, String text, RdnControl option)
          throws BadCertTemplateException {
    if (OIDs.DN.emailAddress.equals(type)) {
      text = text.toLowerCase();
    }

    String tmpText = checkText(text, OIDs.oidToDisplayName(type), option);

    StringType stringType = option == null ? null : option.stringType();

    if (stringType == null) {
      stringType = isPrintableString(tmpText)
          ? StringType.printableString : StringType.utf8String;
    } else if (stringType == StringType.printableString) {
      if (!isPrintableString(tmpText)) {
        throw new BadCertTemplateException("'" + tmpText +
            "' contains non-printableString chars.");
      }
    }

    return stringType.createString(tmpText);
  }

  private static String checkText(
      String text, String typeDesc, RdnControl option)
      throws BadCertTemplateException {
    String tmpText = text.trim();

    if (option != null) {
      TextVadidator pattern = option.pattern();
      if (pattern != null && !pattern.isValid(tmpText)) {
        throw new BadCertTemplateException(
            String.format("invalid subject %s '%s' against regex '%s'",
                typeDesc, tmpText, pattern.pattern()));
      }

      int len = tmpText.length();
      Range range = option.stringLengthRange();
      Integer minLen = (range == null) ? null : range.min();

      if (minLen != null && len < minLen) {
        throw new BadCertTemplateException(String.format(
            "subject %s '%s' is too short (length (%d) < minLen (%d))",
            typeDesc, tmpText, len, minLen));
      }

      Integer maxLen = (range == null) ? null : range.max();

      if (maxLen != null && len > maxLen) {
        throw new BadCertTemplateException(String.format(
            "subject %s '%s' is too long (length (%d) > maxLen (%d))",
            tmpText, tmpText, len, maxLen));
      }
    }

    return tmpText.trim();
  } // method createRdnValue

  private static boolean isPrintableString(String text) {
    // PrintableString does not include the at sign (@), ampersand (&),
    // or asterisk (*).
    for (int i = text.length() - 1; i >= 0; i--) {
      char c = text.charAt(i);
      if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9') || c == ' ' || c == '\''
              || c == '(' || c == ')' || c == '+' || c == ','
              || c == '-' || c == '.' || c == '/' || c == ':'
              || c == '=' || c == '?')) {
        return false;
      }
    }
    return true;
  }

}
