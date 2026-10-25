// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.oid.AttributeOIDs;
import org.xipki.codec.asn1.oid.OIDs;
import org.xipki.pkix.asn1.x500.RDN;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.Attribute;
import org.xipki.pkix.asn1.x509.EDIPartyName;
import org.xipki.pkix.asn1.x509.GeneralName;
import org.xipki.pkix.asn1.x509.OtherName;
import org.xipki.ca.api.profile.ctrl.GeneralNameTag;
import org.xipki.ca.api.profile.ctrl.RdnControl;
import org.xipki.ca.api.profile.ctrl.StringType;
import org.xipki.ca.api.profile.ctrl.SubjectControl;
import org.xipki.ca.api.profile.ctrl.SubjectDnSpec;
import org.xipki.ca.api.profile.ctrl.SubjectInfo;
import org.xipki.ca.api.profile.ctrl.TextValidator;
import org.xipki.ca.api.profile.id.SubjectDirectoryAttributeType;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.pkix.exception.BadCertTemplateException;
import org.xipki.pkix.util.X509Util;
import org.xipki.pkix.util.misc.CollectionUtil;
import org.xipki.ca.api.Range;

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
    List<RDN> requestedRdns = requestedSubject.getRDNs();
    List<RDN> rdns = new LinkedList<>();

    for (Asn1Oid type : scontrol.types()) {
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
          Asn1Primitive value = thisRdns[i].getFirst().getValue();
          rdns.add(createSubjectRdn(type, value, control));
        }
      }
    } // for

    X500Name grantedSubject = new X500Name(rdns.toArray(new RDN[0]));
    return new SubjectInfo(grantedSubject, null);
  } // method getSubject

  private static RDN createSubjectRdn(Asn1Oid type, Asn1Primitive value, RdnControl option)
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
      GeneralName requestedName, Set<GeneralNameTag> modes, Set<Asn1Oid> otherNameTypes)
      throws BadCertTemplateException {
    try {
      return doCreateGeneralName(requestedName, modes, otherNameTypes);
    } catch (CodecException e) {
      throw new BadCertTemplateException("error creating GeneralName", e);
    }
  }

  private static GeneralName doCreateGeneralName(
      GeneralName requestedName, Set<GeneralNameTag> modes, Set<Asn1Oid> otherNameTypes)
      throws BadCertTemplateException, CodecException {
    Args.notNull(requestedName, "requestedName");

    int tag = requestedName.getTagNo();
    if (tag != GeneralName.tag_otherName) {
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
        case GeneralName.tag_rfc822Name:
          return GeneralName.ofRfc822Name(requestedName.getRfc822Name());
        case GeneralName.tag_dNSName:
          return GeneralName.ofDnsName(requestedName.getDNSName());
        case GeneralName.tag_uri:
          return GeneralName.ofUri(requestedName.getUri());
        case GeneralName.tag_iPAddress:
          return GeneralName.ofIPAddress(requestedName.getIPAddress());
        case GeneralName.tag_registeredID:
          return GeneralName.ofRegisteredID(requestedName.getRegisteredID());
        case GeneralName.tag_directoryName:
          return GeneralName.ofDirectoryName(requestedName.getDirectoryName());
        case GeneralName.tag_ediPartyName: {
          EDIPartyName reqEdi = requestedName.getEdiPartyName();
          return GeneralName.ofEdiPartyName(
              new EDIPartyName(reqEdi.nameAssigner(), reqEdi.partyName()));
        }
        default:
          throw new IllegalStateException("should not reach here, unknown GeneralName tag " + tag);
      }
    } else {
      OtherName reqOtherName = requestedName.getOtherName();
      Asn1Oid type = reqOtherName.getTypeID();
      String typeText = type.getId();

      if (!modes.contains(GeneralNameTag.otherName)) {
        throw new BadCertTemplateException("otherName is not allowed");
      }

      if (otherNameTypes != null && !otherNameTypes.contains(type)) {
        throw new BadCertTemplateException("otherName with type " + typeText + " is not allowed");
      }

      return GeneralName.ofOtherName(reqOtherName);
    }
  } // method createGeneralName

  public static Attribute canonicalizeSubjectDirectoryAttribute(Attribute reqAttr)
      throws BadCertTemplateException {
    try {
      return doCanonicalizeSubjectDirectoryAttribute(reqAttr);
    } catch (CodecException | IllegalArgumentException e) {
      throw new BadCertTemplateException("error canonicalizing SubjectDirectoryAttribute", e);
    }
  }

  private static Attribute doCanonicalizeSubjectDirectoryAttribute(Attribute reqAttr)
      throws BadCertTemplateException, CodecException {
    Asn1Oid attrType = reqAttr.getAttrType();

    if (!(SubjectDirectoryAttributeType.title.oid().equals(attrType) ||
        SubjectDirectoryAttributeType.gender.oid().equals(attrType) ||
        SubjectDirectoryAttributeType.dateOfBirth.oid().equals(attrType) ||
        SubjectDirectoryAttributeType.countryOfCitizenship.oid().equals(attrType) ||
        SubjectDirectoryAttributeType.countryOfResidence.oid().equals(attrType))) {
      return reqAttr;
    }

    if (SubjectDirectoryAttributeType.title.oid().equals(attrType)) {
      int sLen = reqAttr.titleAttr().length();
      if (sLen == 0) {
        throw new BadCertTemplateException("invalid length of title: 0");
      }
    } else if (AttributeOIDs.countryOfCitizenship.equals(attrType) ||
               AttributeOIDs.countryOfResidence.equals(attrType)) {
      String country = AttributeOIDs.countryOfCitizenship.equals(attrType)
          ? reqAttr.countryOfCitizenship() : reqAttr.countryOfResidence();
      if (!SubjectDnSpec.isValidCountryAreaCode(country)) {
        throw new BadCertTemplateException(
            "invalid country (" + attrType.getId() + "): " + country);
      }
    } else if (AttributeOIDs.gender.equals(attrType)) {
      String gender = reqAttr.gender();
      if (!("M".equalsIgnoreCase(gender) || "F".equalsIgnoreCase(gender))) {
        throw new BadCertTemplateException("invalid gender: " + gender);
      }
    } else { // if (AttributeOIDs.dateOfBirth.equals(attrType)) {
      String dateOfBirth = reqAttr.getDateOfBirth().getText();
      for (int i = 8; i < 14; i++) {
        char c = dateOfBirth.charAt(i);
        if (c != '0') {
          throw new BadCertTemplateException("invalid dateOfBirth: " + dateOfBirth);
        }
      }
    }
    return reqAttr;
  }

  private static RDN[] getRdns(List<RDN> rdns, Asn1Oid type) {
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

  private static Asn1Primitive createRdnValue(
      Asn1Oid type, String text, RdnControl option)
      throws BadCertTemplateException {
    if (AttributeOIDs.emailAddress.equals(type)) {
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
