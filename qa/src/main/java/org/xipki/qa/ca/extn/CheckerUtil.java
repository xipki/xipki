// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca.extn;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.xipki.ca.api.profile.Certprofile.GeneralNameMode;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.pki.BadCertTemplateException;
import org.xipki.security.KeyUsage;
import org.xipki.util.CollectionUtil;
import org.xipki.util.Hex;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * Extensions checker.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CheckerUtil {

  static void addIfNotIn(Set<ASN1ObjectIdentifier> set, ASN1ObjectIdentifier oid) {
    set.add(oid);
  }

  static Map<ASN1ObjectIdentifier, QaExtensionValue> buildConstantExtensions(Map<String, ExtensionType> extensions)
      throws CertprofileException {
    if (extensions == null) {
      return null;
    }

    Map<ASN1ObjectIdentifier, QaExtensionValue> map = new HashMap<>();

    for (Entry<String, ExtensionType> entry : extensions.entrySet()) {
      String type = entry.getKey();
      ExtensionType extn = entry.getValue();
      if (extn.getConstant() == null) {
        continue;
      }

      ASN1ObjectIdentifier oid = extn.getType().toXiOid();
      if (Extension.subjectAlternativeName.equals(oid)
          || Extension.subjectInfoAccess.equals(oid)
          || Extension.biometricInfo.equals(oid)) {
        continue;
      }

      byte[] encodedValue;
      try {
        encodedValue = extn.getConstant().toASN1Encodable().toASN1Primitive().getEncoded();
      } catch (IOException | InvalidConfException ex) {
        throw new CertprofileException("could not parse the constant extension value of type" + type, ex);
      }

      QaExtensionValue extension = new QaExtensionValue(extn.critical(), encodedValue);
      map.put(oid, extension);
    }

    if (CollectionUtil.isEmpty(map)) {
      return null;
    }

    return Collections.unmodifiableMap(map);
  } // method buildConstantExtesions

  static ASN1Encodable readAsn1Encodable(byte[] encoded) throws CertprofileException {
    ASN1StreamParser parser = new ASN1StreamParser(encoded);
    try {
      return parser.readObject();
    } catch (IOException ex) {
      throw new CertprofileException("could not parse the constant extension value", ex);
    }
  } // method readAsn1Encodable

  static String hex(byte[] bytes) {
    return Hex.encode(bytes);
  }

  static Set<String> strInBnotInA(Collection<String> collectionA, Collection<String> collectionB) {
    if (collectionB == null) {
      return Collections.emptySet();
    }

    Set<String> result = new HashSet<>();
    for (String entry : collectionB) {
      if (collectionA == null || !collectionA.contains(entry)) {
        result.add(entry);
      }
    }
    return result;
  } // method strInBnotInA

  static GeneralName createGeneralName(GeneralName reqName, Set<GeneralNameMode> modes)
      throws BadCertTemplateException {
    int tag = reqName.getTagNo();
    GeneralNameMode mode = null;
    if (modes != null) {
      for (GeneralNameMode m : modes) {
        if (m.getTag().getTag() == tag) {
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
        return new GeneralName(tag, reqName.getName());
      case GeneralName.otherName: {
        ASN1Sequence reqSeq = ASN1Sequence.getInstance(reqName.getName());
        ASN1ObjectIdentifier type = ASN1ObjectIdentifier.getInstance(reqSeq.getObjectAt(0));
        if (mode != null && !mode.getAllowedTypes().contains(type)) {
          throw new BadCertTemplateException("otherName.type " + type.getId() + " is not allowed");
        }

        ASN1Encodable value = ASN1TaggedObject.getInstance(reqSeq.getObjectAt(1)).getBaseObject();
        String text;
        if (!(value instanceof ASN1String)) {
          throw new BadCertTemplateException("otherName.value is not a String");
        } else {
          text = ((ASN1String) value).getString();
        }

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(type);
        vector.add(new DERTaggedObject(true, 0, new DERUTF8String(text)));

        return new GeneralName(GeneralName.otherName, new DERSequence(vector));
      }
      case GeneralName.ediPartyName: {
        ASN1Sequence reqSeq = ASN1Sequence.getInstance(reqName.getName());

        int size = reqSeq.size();
        String nameAssigner = null;
        int idx = 0;
        if (size > 1) {
          DirectoryString ds = DirectoryString.getInstance(
              ASN1TaggedObject.getInstance(reqSeq.getObjectAt(idx++)).getBaseObject());
          nameAssigner = ds.getString();
        }

        DirectoryString ds = DirectoryString.getInstance(
            ASN1TaggedObject.getInstance(reqSeq.getObjectAt(idx)).getBaseObject());
        String partyName = ds.getString();

        ASN1EncodableVector vector = new ASN1EncodableVector();
        if (nameAssigner != null) {
          vector.add(new DERTaggedObject(false, 0, new DirectoryString(nameAssigner)));
        }
        vector.add(new DERTaggedObject(false, 1, new DirectoryString(partyName)));
        return new GeneralName(GeneralName.ediPartyName, new DERSequence(vector));
      }
      default:
        throw new IllegalStateException("should not reach here, unknown GeneralName tag " + tag);
    } // end switch
  } // method createGeneralName

  static Set<String> getKeyUsage(byte[] extensionValue) {
    Set<String> usages = new HashSet<>();
    org.bouncycastle.asn1.x509.KeyUsage reqKeyUsage = org.bouncycastle.asn1.x509.KeyUsage.getInstance(extensionValue);
    for (KeyUsage k : KeyUsage.values()) {
      if (reqKeyUsage.hasUsages(k.getBcUsage())) {
        usages.add(k.getName());
      }
    }

    return usages;
  } // method getKeyUsage

  static Set<String> getExtKeyUsage(byte[] extensionValue) {
    Set<String> usages = new HashSet<>();
    org.bouncycastle.asn1.x509.ExtendedKeyUsage reqKeyUsage =
        org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(extensionValue);
    for (KeyPurposeId usage : reqKeyUsage.getUsages()) {
      usages.add(usage.getId());
    }
    return usages;
  } // method getExtKeyUsage

  static void checkAia(StringBuilder failureMsg, AuthorityInformationAccess aia,
      ASN1ObjectIdentifier accessMethod, Set<String> expectedUris) {
    String typeDesc;
    if (X509ObjectIdentifiers.id_ad_ocsp.equals(accessMethod)) {
      typeDesc = "OCSP";
    } else if (X509ObjectIdentifiers.id_ad_caIssuers.equals(accessMethod)) {
      typeDesc = "caIssuer";
    } else {
      typeDesc = accessMethod.getId();
    }

    List<AccessDescription> isAccessDescriptions = new LinkedList<>();
    for (AccessDescription accessDescription : aia.getAccessDescriptions()) {
      if (accessMethod.equals(accessDescription.getAccessMethod())) {
        isAccessDescriptions.add(accessDescription);
      }
    }

    int size = isAccessDescriptions.size();
    if (size != expectedUris.size()) {
      addViolation(failureMsg, "number of AIA " + typeDesc + " URIs", size, expectedUris.size());
      return;
    }

    Set<String> isUris = new HashSet<>();
    for (AccessDescription isAccessDescription : isAccessDescriptions) {
      GeneralName isAccessLocation = isAccessDescription.getAccessLocation();
      if (isAccessLocation.getTagNo() != GeneralName.uniformResourceIdentifier) {
        addViolation(failureMsg, "tag of accessLocation of AIA ",
            isAccessLocation.getTagNo(), GeneralName.uniformResourceIdentifier);
      } else {
        String isOcspUri = ((ASN1String) isAccessLocation.getName()).getString();
        isUris.add(isOcspUri);
      }
    }

    Set<String> diffs = strInBnotInA(expectedUris, isUris);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append(typeDesc).append(" URIs ").append(diffs);
      failureMsg.append(" are present but not expected; ");
    }

    diffs = strInBnotInA(isUris, expectedUris);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append(typeDesc).append(" URIs ").append(diffs);
      failureMsg.append(" are absent but are required; ");
    }
  } // method checkAia

  static void addViolation(StringBuilder failureMsg, String field, Object is, Object expected) {
    failureMsg.append(field).append(" is '").append(is).append("' but expected '").append(expected).append("';");
  } // method addViolation

}
