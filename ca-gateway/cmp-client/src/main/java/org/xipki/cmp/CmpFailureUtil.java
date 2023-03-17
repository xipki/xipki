// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp;

import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

/**
 * CMP failure utility class.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CmpFailureUtil {

  private static final Map<Integer, String> STATUS_TEXT_MAP = new HashMap<>();

  private static final String[] FAILUREINFO_TEXTS = new String[] {
    // 0 - 3
    "incorrectData", "wrongAuthority", "badDataFormat", "badCertId",
    // 4 - 7
    "badTime", "badRequest", "badMessageCheck", "badAlg",
    // 8 - 11
    "unacceptedPolicy", "timeNotAvailable", "badRecipientNonce", "wrongIntegrity",
    // 12 - 15
    "certConfirmed", "certRevoked", "badPOP", "missingTimeStamp",
    // 16 - 19
    "notAuthorized", "unsupportedVersion", "transactionIdInUse", "signerNotTrusted",
    // 20 - 23
    "badCertTemplate", "badSenderNonce", "addInfoNotAvailable", "unacceptedExtension",
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
    STATUS_TEXT_MAP.put(PKIStatus.REVOCATION_NOTIFICATION, "revocationNotification");
    STATUS_TEXT_MAP.put(PKIStatus.KEY_UPDATE_WARNING, "keyUpdateWarning");
  } // method static

  private CmpFailureUtil() {
  }

  public static String formatPkiStatusInfo(org.bouncycastle.asn1.cmp.PKIStatusInfo pkiStatusInfo) {
    int status = Args.notNull(pkiStatusInfo, "pkiStatusInfo").getStatus().intValue();
    PKIFreeText text = pkiStatusInfo.getStatusString();
    String statusMessage = (text == null) ? null : text.getStringAtUTF8(0).getString();
    return formatPkiStatusInfo(status, pkiStatusInfo.getFailInfo().intValue(), statusMessage);
  } // method formatPkiStatusInfo

  public static String formatPkiStatusInfo(int status, int failureInfo, String statusMessage) {
    return StringUtil.concatObjectsCap(200, "PKIStatusInfo {status = ", status,
      " (", STATUS_TEXT_MAP.get(status), "), ", "failureInfo = ", failureInfo,
      " (", getFailureInfoText(failureInfo), "), ", "statusMessage = ", statusMessage, "}");
  } // method formatPkiStatusInfo

  public static String getFailureInfoText(int failureInfo) {
    BigInteger bi = BigInteger.valueOf(failureInfo);
    final int n = Math.min(bi.bitLength(), FAILUREINFO_TEXTS.length);

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < n; i++) {
      if (bi.testBit(i)) {
        sb.append(", ").append(FAILUREINFO_TEXTS[i]);
      }
    }

    return (sb.length() < 3) ? "" : sb.substring(2);
  } // method getFailureInfoText

}
