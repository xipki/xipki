// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.cmp;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.OIDs;
import org.xipki.security.XiContentSigner;
import org.xipki.security.exception.NoIdleSignerException;
import org.xipki.util.codec.Args;
import org.xipki.util.misc.StringUtil;

import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * CMP utility class.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CmpUtil {

  private static final Map<Integer, String> STATUS_TEXT_MAP = new HashMap<>();

  /**
   * <pre>
   * PKIFailureInfo ::= BIT STRING {
   * badAlg               (0), -- unrecognized or unsupported Algorithm
   *                           -- Identifier
   * badMessageCheck      (1), -- integrity check failed (e.g.,
   *                           -- signature did not verify)
   * badRequest           (2), -- transaction not permitted or supported
   * badTime              (3), -- messageTime was not sufficiently close to
   *                           -- the system time, as defined by local policy
   * badCertId            (4), -- no certificate could be found matching the
   *                           -- provided criteria
   * badDataFormat        (5), -- the data submitted has the wrong format
   * wrongAuthority       (6), -- the authority indicated in the request is
   *                           -- different from the one creating the response
   *                           -- token
   * incorrectData        (7), -- the requester's data is incorrect
   *                           -- (for notary services)
   * missingTimeStamp     (8), -- when the timestamp is missing but should be
   *                           -- there (by policy)
   * badPOP               (9)  -- the proof-of-possession failed
   * certRevoked         (10),
   * certConfirmed       (11),
   * wrongIntegrity      (12),
   * badRecipientNonce   (13),
   * timeNotAvailable    (14), -- the TSA's time source is not available
   * unacceptedPolicy    (15), -- the requested TSA policy is not supported by
   *                           -- the TSA
   * unacceptedExtension (16), -- the requested extension is not supported by
   *                           -- the TSA
   * addInfoNotAvailable (17)  -- the additional information requested could
   *                           -- not be understood or is not available
   * badSenderNonce      (18),
   * badCertTemplate     (19),
   * signerNotTrusted    (20),
   * transactionIdInUse  (21),
   * unsupportedVersion  (22),
   * notAuthorized       (23),
   * systemUnavail       (24),
   * systemFailure       (25), -- the request cannot be handled due to system
   *                           -- failure
   * duplicateCertReq    (26)
   * </pre>
   */
  private static final String[] FAILUREINFO_TEXTS = new String[] {
      // 0 - 3
      "incorrectData", "wrongAuthority", "badDataFormat", "badCertId",
      // 4 - 7
      "badTime", "badRequest", "badMessageCheck", "badAlg",
      // 8 - 11
      "unacceptedPolicy", "timeNotAvailable", "badRecipientNonce",
      "wrongIntegrity",
      // 12 - 15
      "certConfirmed", "certRevoked", "badPOP", "missingTimeStamp",
      // 16 - 19
      "notAuthorized", "unsupportedVersion", "transactionIdInUse",
      "signerNotTrusted",
      // 20 - 23
      "badCertTemplate", "badSenderNonce", "addInfoNotAvailable",
      "unacceptedExtension",
      // 24 -27
      "-", "-", "-", "-",
      // 28 - 31
      "-", "duplicateCertReq", "systemFailure", "systemUnavail"};

  static {
    STATUS_TEXT_MAP.put(-2, "xipki_noAnswer");
    STATUS_TEXT_MAP.put(-1, "xipki_responseError");
    STATUS_TEXT_MAP.put(PKIStatus.GRANTED, "accepted");
    STATUS_TEXT_MAP.put(PKIStatus.GRANTED_WITH_MODS, "grantedWithMods");
    STATUS_TEXT_MAP.put(PKIStatus.REJECTION, "rejection");
    STATUS_TEXT_MAP.put(PKIStatus.WAITING, "waiting");
    STATUS_TEXT_MAP.put(PKIStatus.REVOCATION_WARNING, "revocationWarning");
    STATUS_TEXT_MAP.put(PKIStatus.REVOCATION_NOTIFICATION,
        "revocationNotification");
    STATUS_TEXT_MAP.put(PKIStatus.KEY_UPDATE_WARNING, "keyUpdateWarning");
  }

  private CmpUtil() {
  }

  public static String formatPkiStatusInfo(
      int status, int failureInfo, String statusMessage) {
    BigInteger bi = BigInteger.valueOf(failureInfo);
    final int n = Math.min(bi.bitLength(), FAILUREINFO_TEXTS.length);

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < n; i++) {
      if (bi.testBit(i)) {
        sb.append(", ").append(FAILUREINFO_TEXTS[i]);
      }
    }

    String failInfoText = (sb.length() < 3) ? "" : sb.substring(2);

    return StringUtil.concatObjectsCap(200,
        "PKIStatusInfo {status = ", status, " (",
        STATUS_TEXT_MAP.get(status), "), ",
        "failureInfo = ", failureInfo, " (", failInfoText, "), ",
        "statusMessage = ", statusMessage, "}");
  }

  public static PKIMessage addProtection(
      PKIMessage pkiMessage, ConcurrentContentSigner signer,
      GeneralName signerName, boolean addSignerCert)
      throws CMPException, NoIdleSignerException {
    Args.notNull(pkiMessage, "pkiMessage");
    Args.notNull(signer, "signer");

    final GeneralName tmpSignerName;
    if (signerName != null) {
      tmpSignerName = signerName;
    } else {
      X500Name x500Name = Optional.ofNullable(signer.getCertificate())
          .orElseThrow(() -> new IllegalArgumentException(
              "signer without certificate is not allowed"))
          .getSubject();
      tmpSignerName = new GeneralName(x500Name);
    }

    ProtectedPKIMessageBuilder builder = newProtectedPKIMessageBuilder(
        pkiMessage, tmpSignerName, null);

    if (addSignerCert) {
      X509CertificateHolder signerCert = signer.getCertificate().toBcCert();
      builder.addCMPCertificate(signerCert);
    }

    XiContentSigner signer0 = signer.borrowSigner();
    ProtectedPKIMessage signedMessage;
    try {
      signedMessage = builder.build(signer0);
    } finally {
      signer.requiteSigner(signer0);
    }
    return signedMessage.toASN1Structure();
  }

  public static PKIMessage addProtection(
      PKIMessage pkiMessage, char[] password, PBMParameter pbmParameter,
      GeneralName signerName, byte[] senderKid)
      throws CMPException {
    ProtectedPKIMessageBuilder builder =
        newProtectedPKIMessageBuilder(pkiMessage, signerName, senderKid);

    try {
      PKMACBuilder pkMacBuilder =
          new PKMACBuilder(new JcePKMACValuesCalculator());
      pkMacBuilder.setParameters(pbmParameter);
      return builder.build(pkMacBuilder.build(password)).toASN1Structure();
    } catch (CRMFException ex) {
      throw new CMPException(ex.getMessage(), ex);
    }
  }

  private static ProtectedPKIMessageBuilder newProtectedPKIMessageBuilder(
      PKIMessage pkiMessage, GeneralName sender, byte[] senderKid) {
    PKIHeader header = pkiMessage.getHeader();
    ProtectedPKIMessageBuilder builder =
        new ProtectedPKIMessageBuilder(sender, header.getRecipient());
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
      builder.setMessageTime(Date.from(Instant.now()));
    }
    builder.setBody(pkiMessage.getBody());

    return builder;
  } // method newProtectedPKIMessageBuilder

  public static boolean isImplicitConfirm(PKIHeader header) {
    InfoTypeAndValue[] regInfos = Args.notNull(header, "header")
        .getGeneralInfo();
    if (regInfos != null) {
      for (InfoTypeAndValue regInfo : regInfos) {
        if (OIDs.CMP.it_implicitConfirm.equals(regInfo.getInfoType())) {
          return true;
        }
      }
    }

    return false;
  } // method isImplicitConfirm

  public static InfoTypeAndValue getImplicitConfirmGeneralInfo() {
    return new InfoTypeAndValue(OIDs.CMP.it_implicitConfirm, DERNull.INSTANCE);
  }

  public static CmpUtf8Pairs extractUtf8Pairs(InfoTypeAndValue[] generalInfo) {
    if (generalInfo != null) {
      for (InfoTypeAndValue itv : generalInfo) {
        if (OIDs.CMP.regInfo_utf8Pairs.equals(itv.getInfoType())) {
          return new CmpUtf8Pairs(((ASN1String) itv.getInfoValue())
              .getString());
        }
      }
    }

    return null;
  }

  public static String[] extractCertProfile(InfoTypeAndValue[] generalInfo) {
    if (generalInfo != null) {
      for (InfoTypeAndValue itv : generalInfo) {
        if (OIDs.CMP.id_it_certProfile.equals(itv.getInfoType())) {
          ASN1Sequence seq = ASN1Sequence.getInstance(itv.getInfoValue());
          List<String> list = new ArrayList<>(seq.size());
          for (int i = 0; i < seq.size(); i++) {
            list.add(((ASN1String) seq.getObjectAt(i)).getString()
                .toLowerCase(Locale.ROOT));
          }
          return list.isEmpty() ? null : list.toArray(new String[0]);
        }
      }
    }

    return null;
  }

  public static InfoTypeAndValue buildInfoTypeAndValue(CmpUtf8Pairs utf8Pairs) {
    Args.notNull(utf8Pairs, "utf8Pairs");
    return new InfoTypeAndValue(OIDs.CMP.regInfo_utf8Pairs,
        new DERUTF8String(utf8Pairs.encoded()));
  }

}
