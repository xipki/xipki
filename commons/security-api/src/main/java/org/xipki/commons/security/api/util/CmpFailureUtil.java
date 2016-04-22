/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.commons.security.api.util;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.xipki.commons.common.util.ParamUtil;

/**
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
    }

    private CmpFailureUtil() {
    }

    public static String formatPkiStatusInfo(
            final org.bouncycastle.asn1.cmp.PKIStatusInfo pkiStatusInfo) {
        ParamUtil.requireNonNull("pkiStatusInfo", pkiStatusInfo);
        int status = pkiStatusInfo.getStatus().intValue();
        int failureInfo = pkiStatusInfo.getFailInfo().intValue();
        PKIFreeText text = pkiStatusInfo.getStatusString();
        String statusMessage = (text == null)
                ? null
                : text.getStringAt(0).getString();

        return formatPkiStatusInfo(status, failureInfo, statusMessage);
    }

    public static String formatPkiStatusInfo(
            final int status,
            final int failureInfo,
            final String statusMessage) {
        StringBuilder sb = new StringBuilder(200);
        sb.append("PKIStatusInfo {status = ").append(status);
        sb.append(" (").append(STATUS_TEXT_MAP.get(status)).append("), ");
        sb.append("failureInfo = ").append(failureInfo);
        sb.append(" (").append(getFailureInfoText(failureInfo)).append("), ");
        sb.append("statusMessage = ").append(statusMessage).append("}");
        return sb.toString();
    }

    public static String getFailureInfoText(
            final int failureInfo) {
        BigInteger bi = BigInteger.valueOf(failureInfo);
        final int n = Math.min(bi.bitLength(), FAILUREINFO_TEXTS.length);

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            if (bi.testBit(i)) {
                sb.append(", ").append(FAILUREINFO_TEXTS[i]);
            }
        }

        return (sb.length() < 3)
                ? ""
                : sb.substring(2);
    }

}
