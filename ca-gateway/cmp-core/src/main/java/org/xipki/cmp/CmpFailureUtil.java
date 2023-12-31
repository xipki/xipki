// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp;

import org.bouncycastle.asn1.cmp.PKIStatus;
import org.xipki.util.StringUtil;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

/**
 * CMP failure utility class.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CmpFailureUtil {

  private static final Map<Integer, String> STATUS_TEXT_MAP = new HashMap<>();

  /**
   * <pre>
   * PKIFailureInfo ::= BIT STRING {
   * badAlg               (0),
   *   -- unrecognized or unsupported Algorithm Identifier
   * badMessageCheck      (1), -- integrity check failed (e.g., signature did not verify)
   * badRequest           (2),
   *   -- transaction not permitted or supported
   * badTime              (3), -- messageTime was not sufficiently close to the system time, as defined by local policy
   * badCertId            (4), -- no certificate could be found matching the provided criteria
   * badDataFormat        (5),
   *   -- the data submitted has the wrong format
   * wrongAuthority       (6), -- the authority indicated in the request is different from the one creating the
   *                           -- response token
   * incorrectData        (7), -- the requester's data is incorrect (for notary services)
   * missingTimeStamp     (8), -- when the timestamp is missing but should be there (by policy)
   * badPOP               (9)  -- the proof-of-possession failed
   * certRevoked         (10),
   * certConfirmed       (11),
   * wrongIntegrity      (12),
   * badRecipientNonce   (13),
   * timeNotAvailable    (14),
   *   -- the TSA's time source is not available
   * unacceptedPolicy    (15),
   *   -- the requested TSA policy is not supported by the TSA
   * unacceptedExtension (16),
   *   -- the requested extension is not supported by the TSA
   * addInfoNotAvailable (17)
   *   -- the additional information requested could not be understood
   *   -- or is not available
   * badSenderNonce      (18),
   * badCertTemplate     (19),
   * signerNotTrusted    (20),
   * transactionIdInUse  (21),
   * unsupportedVersion  (22),
   * notAuthorized       (23),
   * systemUnavail       (24),
   * systemFailure       (25),
   *   -- the request cannot be handled due to system failure
   * duplicateCertReq    (26)
   * </pre>
   */
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
  }

  private CmpFailureUtil() {
  }

  public static String formatPkiStatusInfo(int status, int failureInfo, String statusMessage) {
    return StringUtil.concatObjectsCap(200, "PKIStatusInfo {status = ", status,
      " (", STATUS_TEXT_MAP.get(status), "), ", "failureInfo = ", failureInfo,
      " (", getFailureInfoText(failureInfo), "), ", "statusMessage = ", statusMessage, "}");
  }

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
  }

}
