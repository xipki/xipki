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

package org.xipki.security.util;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;

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
    int failureInfo = pkiStatusInfo.getFailInfo().intValue();
    PKIFreeText text = pkiStatusInfo.getStatusString();
    String statusMessage = (text == null) ? null : text.getStringAt(0).getString();
    return formatPkiStatusInfo(status, failureInfo, statusMessage);
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
