// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.OtherName;
import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.ca.api.profile.ctrl.RdnControl;
import org.xipki.ca.api.profile.ctrl.StringType;
import org.xipki.ca.api.profile.ctrl.SubjectControl;
import org.xipki.ca.api.profile.ctrl.SubjectDnSpec;
import org.xipki.ca.api.profile.ctrl.SubjectInfo;
import org.xipki.ca.api.profile.ctrl.TextValidator;
import org.xipki.ca.api.profile.id.OtherNameID;
import org.xipki.ca.api.profile.id.SubjectDirectoryAttributeType;
import org.xipki.security.OIDs;
import org.xipki.security.asn1.rfc4108.HardwareModuleName;
import org.xipki.security.asn1.spdm.SpdmParser;
import org.xipki.security.asn1.tcg.TcgParser;
import org.xipki.security.exception.BadCertTemplateException;
import org.xipki.security.util.Asn1Util;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.type.Range;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Profile Util.
 *
 * @author Lijun Liao (xipki)
 */
public class ProfileUtil {

  public static SubjectInfo getSubject(X500Name requestedSubject, SubjectControl scontrol)
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
          rdns.add(createSubjectRdn(type, value, control));
        }
      }
    } // for

    X500Name grantedSubject = new X500Name(rdns.toArray(new RDN[0]));
    return new SubjectInfo(grantedSubject, null);
  } // method getSubject

  private static RDN createSubjectRdn(
      ASN1ObjectIdentifier type, ASN1Encodable value, RdnControl option)
      throws BadCertTemplateException {
    String text = X509Util.rdnValueToString(value);
    return new RDN(type, createRdnValue(type, text, option));
  } // method createSubjectRdn

  /**
   * Creates GeneralName.
   *
   * @param requestedName
   *        Requested name. Must not be {@code null}.
   * @param modes
   *        Modes to be considered. Must not be {@code null}.
   * @param otherNameTypes
   *        allowed types of otherName. May be {@code null}.
   * @return the created GeneralName
   * @throws BadCertTemplateException
   *         If requestedName is invalid or contains entries which are
   *         not allowed in the modes.
   */
  public static GeneralName createGeneralName(
      GeneralName requestedName, Set<GeneralNameTag> modes,
      Set<ASN1ObjectIdentifier> otherNameTypes)
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
          throw new BadCertTemplateException("generalName tag " + tag + " is not allowed");
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
          ASN1Sequence reqSeq = ASN1Sequence.getInstance(requestedName.getName());

          int size = reqSeq.size();
          String nameAssigner = null;
          int idx = 0;
          if (size > 1) {
            ASN1TaggedObject taggedObj = ASN1TaggedObject.getInstance(reqSeq.getObjectAt(idx++));
            nameAssigner = DirectoryString.getInstance(taggedObj.getBaseObject()).getString();
          }

          ASN1TaggedObject taggedObj = ASN1TaggedObject.getInstance(reqSeq.getObjectAt(idx));
          String partyName = DirectoryString.getInstance(taggedObj.getBaseObject()).getString();

          ASN1EncodableVector vector = new ASN1EncodableVector();
          if (nameAssigner != null) {
            vector.add(new DERTaggedObject(false, 0, new DirectoryString(nameAssigner)));
          }
          vector.add(new DERTaggedObject(false, 1, new DirectoryString(partyName)));
          return new GeneralName(GeneralName.ediPartyName, new DERSequence(vector));
        }
        default:
          throw new IllegalStateException("should not reach here, unknown GeneralName tag " + tag);
      }
    } else {
      OtherName reqOtherName = OtherName.getInstance(requestedName.getName());
      ASN1ObjectIdentifier type = reqOtherName.getTypeID();
      String typeText = type.getId();

      if (!modes.contains(GeneralNameTag.otherName)) {
        throw new BadCertTemplateException("otherName is not allowed");
      }

      if (otherNameTypes != null && !otherNameTypes.contains(type)) {
        throw new BadCertTemplateException("otherName with type " + typeText + " is not allowed");
      }

      // customized checker and process
      OtherName resOtherName;
      try {
        if (type.on(OIDs.TCG.tcg)) {
          resOtherName = new OtherName(type, TcgParser.parseTcgOtherName(reqOtherName));
        } else if (type.on(OIDs.Spdm.id_spdm)) {
          resOtherName = new OtherName(type, SpdmParser.parseSpdmOtherName(reqOtherName));
        } else if (type.equals(OtherNameID.hardwareModuleName.oid())) {
          HardwareModuleName hmName = HardwareModuleName.getInstance(reqOtherName.getValue());
          resOtherName = new OtherName(type, hmName);
        } else if (type.equals(OtherNameID.macAddress.oid())) {
          ASN1OctetString os = ASN1OctetString.getInstance(reqOtherName.getValue());
          int len = os.getOctets().length;
          if (!(len == 6 || len == 8 || len == 12 || len == 16)) {
            throw new BadCertTemplateException("invalid length of MAC address: " + len);
          }
          resOtherName = reqOtherName;
        } else if (type.equals(OtherNameID.smtpUTF8Mailbox.oid())) {
          String text = Asn1Util.getUTF8String(reqOtherName.getValue());
          boolean withNonAscii = false;
          for (int i = 0; i < text.length(); i++) {
            int c = text.charAt(i);
            if (c > 127) {
              withNonAscii = true;
              break;
            }
          }

          if (!withNonAscii) {
            throw new BadCertTemplateException(
                "smtpUTF8Mailbox shall not contain ASCII-only mailbox");
          }
          resOtherName = reqOtherName;
        } else {
          resOtherName = reqOtherName;
        }
      } catch (RuntimeException e) {
        throw new BadCertTemplateException("invalid value of otherName type " + type);
      }

      return new GeneralName(GeneralName.otherName, resOtherName);
    }
  } // method createGeneralName

  public static Attribute canonicalizeSubjectDirectoryAttribute(Attribute reqAttr)
      throws BadCertTemplateException {
    ASN1ObjectIdentifier attrType = reqAttr.getAttrType();
    ASN1Set reqAttrValues = reqAttr.getAttrValues();

    if (SubjectDirectoryAttributeType.title.oid().equals(attrType) ||
        SubjectDirectoryAttributeType.gender.oid().equals(attrType) ||
        SubjectDirectoryAttributeType.placeOfBirth.oid().equals(attrType) ||
        SubjectDirectoryAttributeType.dateOfBirth.oid().equals(attrType) ||
        SubjectDirectoryAttributeType.countryOfCitizenship.oid().equals(attrType) ||
        SubjectDirectoryAttributeType.countryOfResidence.oid().equals(attrType)) {
      int setSize = reqAttrValues.size();
      if (setSize != 1) {
        throw new IllegalArgumentException("invalid attrValue.size() " + setSize);
      }

      ASN1Primitive sAttrValue = reqAttrValues.getObjectAt(0).toASN1Primitive();

      if (SubjectDirectoryAttributeType.title.oid().equals(attrType)) {
        if (sAttrValue instanceof ASN1T61String ||
            sAttrValue instanceof ASN1PrintableString ||
            sAttrValue instanceof ASN1UniversalString ||
            sAttrValue instanceof ASN1UTF8String ||
            sAttrValue instanceof ASN1BMPString) {
          int sLen = ((ASN1String) sAttrValue).getString().length();
          if (sLen == 0) {
            throw new BadCertTemplateException("invalid length of title: 0");
          }
        }

        return new Attribute(attrType, new DERSet(sAttrValue));
      } else if (SubjectDirectoryAttributeType.countryOfCitizenship.oid().equals(attrType) ||
                 SubjectDirectoryAttributeType.countryOfResidence.oid().equals(attrType)) {
        String country = ASN1PrintableString.getInstance(sAttrValue).getString();
        if (!SubjectDnSpec.isValidCountryAreaCode(country)) {
          throw new BadCertTemplateException(
              "invalid country (" + attrType.getId() + "): " + country);
        }
      } else if (SubjectDirectoryAttributeType.gender.oid().equals(attrType)) {
        String gender = Asn1Util.getPrintableString(sAttrValue);
        if (!("M".equalsIgnoreCase(gender) || "F".equalsIgnoreCase(gender))) {
          throw new BadCertTemplateException("invalid gender: " + gender);
        }
      } else if (SubjectDirectoryAttributeType.dateOfBirth.oid().equals(attrType)) {
        ASN1GeneralizedTime.getInstance(sAttrValue);
      } else { // placeOfBirth
        DirectoryString.getInstance(sAttrValue);
      }
      return reqAttr;
    } else if (attrType.on(OIDs.TCG.tcg_attribute)) {
      ASN1Encodable sAttrValue = TcgParser.parseTcgAttributeValue(attrType, reqAttrValues);
      return new Attribute(attrType, new DERSet(sAttrValue));
    } else {
      return reqAttr;
    }
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
      stringType = StringType.utf8String; // default to UTF8String
    } else if (stringType == StringType.printableString) {
      if (!isPrintableString(tmpText)) {
        throw new BadCertTemplateException("'" + tmpText + "' contains non-printableString chars.");
      }
    }

    return stringType.createString(tmpText);
  }

  private static String checkText(String text, String typeDesc, RdnControl option)
      throws BadCertTemplateException {
    String tmpText = text.trim();

    if (option != null) {
      TextValidator pattern = option.pattern();
      if (pattern != null && !pattern.isValid(tmpText)) {
        throw new BadCertTemplateException(String.format(
            "invalid subject %s '%s' against regex '%s'", typeDesc, tmpText, pattern.pattern()));
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
            typeDesc, tmpText, len, maxLen));
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
