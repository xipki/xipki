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

package org.xipki.security.cmp;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.xipki.security.ConcurrentBagEntrySigner;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.NoIdleSignerException;
import org.xipki.security.ObjectIdentifiers;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import static org.xipki.util.Args.notNull;

/**
 * CMP utility class.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CmpUtil {

  private CmpUtil() {
  }

  public static PKIMessage addProtection(PKIMessage pkiMessage, ConcurrentContentSigner signer,
      GeneralName signerName, boolean addSignerCert)
          throws CMPException, NoIdleSignerException {
    notNull(pkiMessage, "pkiMessage");
    notNull(signer, "signer");

    final GeneralName tmpSignerName;
    if (signerName != null) {
      tmpSignerName = signerName;
    } else {
      if (signer.getCertificate() == null) {
        throw new IllegalArgumentException("signer without certificate is not allowed");
      }
      X500Name x500Name = signer.getCertificate().getSubject();
      tmpSignerName = new GeneralName(x500Name);
    }

    ProtectedPKIMessageBuilder builder =
        newProtectedPKIMessageBuilder(pkiMessage, tmpSignerName, null);
    if (addSignerCert) {
      X509CertificateHolder signerCert = signer.getCertificate().toBcCert();
      builder.addCMPCertificate(signerCert);
    }

    ConcurrentBagEntrySigner signer0 = signer.borrowSigner();
    ProtectedPKIMessage signedMessage;
    try {
      signedMessage = builder.build(signer0.value());
    } finally {
      signer.requiteSigner(signer0);
    }
    return signedMessage.toASN1Structure();
  } // method addProtection

  public static PKIMessage addProtection(PKIMessage pkiMessage, char[] password,
      PBMParameter pbmParameter, GeneralName signerName, byte[] senderKid)
      throws CMPException {
    ProtectedPKIMessageBuilder builder =
        newProtectedPKIMessageBuilder(pkiMessage, signerName, senderKid);
    ProtectedPKIMessage signedMessage;
    try {
      PKMACBuilder pkMacBuilder = new PKMACBuilder(new JcePKMACValuesCalculator());
      pkMacBuilder.setParameters(pbmParameter);
      signedMessage = builder.build(pkMacBuilder.build(password));
    } catch (CRMFException ex) {
      throw new CMPException(ex.getMessage(), ex);
    }
    return signedMessage.toASN1Structure();
  } // method addProtection

  // CHECKSTYLE:SKIP
  private static ProtectedPKIMessageBuilder newProtectedPKIMessageBuilder(PKIMessage pkiMessage,
      GeneralName sender, byte[] senderKid) {
    PKIHeader header = pkiMessage.getHeader();
    ProtectedPKIMessageBuilder builder = new ProtectedPKIMessageBuilder(
        sender, header.getRecipient());
    PKIFreeText freeText = header.getFreeText();
    if (freeText != null) {
      builder.setFreeText(freeText);
    }

    InfoTypeAndValue[] generalInfo = header.getGeneralInfo();
    if (generalInfo != null) {
      for (InfoTypeAndValue gi : generalInfo) {
        builder.addGeneralInfo(gi);
      }
    }

    ASN1OctetString octet = header.getRecipKID();
    if (octet != null) {
      builder.setRecipKID(octet.getOctets());
    }

    octet = header.getRecipNonce();
    if (octet != null) {
      builder.setRecipNonce(octet.getOctets());
    }

    if (senderKid != null) {
      builder.setSenderKID(senderKid);
    }

    octet = header.getSenderNonce();
    if (octet != null) {
      builder.setSenderNonce(octet.getOctets());
    }

    octet = header.getTransactionID();
    if (octet != null) {
      builder.setTransactionID(octet.getOctets());
    }

    if (header.getMessageTime() != null) {
      builder.setMessageTime(new Date());
    }
    builder.setBody(pkiMessage.getBody());

    return builder;
  } // method newProtectedPKIMessageBuilder

  public static boolean isImplictConfirm(PKIHeader header) {
    notNull(header, "header");

    InfoTypeAndValue[] regInfos = header.getGeneralInfo();
    if (regInfos != null) {
      for (InfoTypeAndValue regInfo : regInfos) {
        if (CMPObjectIdentifiers.it_implicitConfirm.equals(regInfo.getInfoType())) {
          return true;
        }
      }
    }

    return false;
  } // method isImplictConfirm

  public static InfoTypeAndValue getImplictConfirmGeneralInfo() {
    return new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE);
  }

  public static CmpUtf8Pairs extractUtf8Pairs(InfoTypeAndValue[] generalInfo) {
    if (generalInfo != null) {
      for (InfoTypeAndValue itv : generalInfo) {
        if (CMPObjectIdentifiers.regInfo_utf8Pairs.equals(itv.getInfoType())) {
          String regInfoValue = ((ASN1String) itv.getInfoValue()).getString();
          return new CmpUtf8Pairs(regInfoValue);
        }
      }
    }

    return null;
  }

  public static String[] extractCertProfile(InfoTypeAndValue[] generalInfo) {
    if (generalInfo != null) {
      for (InfoTypeAndValue itv : generalInfo) {
        if (ObjectIdentifiers.CMP.id_it_certProfile.equals(itv.getInfoType())) {
          ASN1Sequence seq = ASN1Sequence.getInstance(itv.getInfoValue());
          List<String> list = new ArrayList<>(seq.size());
          for (int i = 0; i < seq.size(); i++) {
            list.add(((ASN1String) seq.getObjectAt(i)).getString().toLowerCase(Locale.ROOT));
          }
          return list.isEmpty() ? null : list.toArray(new String[0]);
        }
      }
    }

    return null;
  }

  public static CmpUtf8Pairs extractUtf8Pairs(AttributeTypeAndValue[] atvs) {
    if (atvs != null) {
      for (AttributeTypeAndValue atv : atvs) {
        if (CMPObjectIdentifiers.regInfo_utf8Pairs.equals(atv.getType())) {
          String regInfoValue = ((ASN1String) atv.getValue()).getString();
            return new CmpUtf8Pairs(regInfoValue);
        }
      }
    }

    return null;
  }

  public static InfoTypeAndValue buildInfoTypeAndValue(CmpUtf8Pairs utf8Pairs) {
    notNull(utf8Pairs, "utf8Pairs");
    return new InfoTypeAndValue(CMPObjectIdentifiers.regInfo_utf8Pairs,
        new DERUTF8String(utf8Pairs.encoded()));
  }

  public static AttributeTypeAndValue buildAttributeTypeAndValue(CmpUtf8Pairs utf8Pairs) {
    notNull(utf8Pairs, "utf8Pairs");
    return new AttributeTypeAndValue(CMPObjectIdentifiers.regInfo_utf8Pairs,
        new DERUTF8String(utf8Pairs.encoded()));
  }

}
