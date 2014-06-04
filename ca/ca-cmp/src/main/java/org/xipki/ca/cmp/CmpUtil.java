/*
 * Copyright (c) 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.cmp;

import java.math.BigInteger;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.ca.cmp.client.ClientErrorCode;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;

public class CmpUtil
{
    public static final Map<Integer, String> statusTextMap = new HashMap<Integer, String>();
    public static final String[] failureInfoTexts = new String[]
    {
        "incorrectData", "wrongAuthority", "badDataFormat", "badCertId", // 0 - 3
        "badTime", "badRequest", "badMessageCheck", "badAlg", // 4 - 7
        "unacceptedPolicy", "timeNotAvailable", "badRecipientNonce", "wrongIntegrity", // 8 - 11
        "certConfirmed", "certRevoked", "badPOP", "missingTimeStamp", // 12 - 15
        "notAuthorized", "unsupportedVersion", "transactionIdInUse", "signerNotTrusted", // 16 - 19
        "badCertTemplate", "badSenderNonce", "addInfoNotAvailable", "unacceptedExtension", // 20 - 23
        "-", "-", "-", "-", // 24 -27
        "-", "duplicateCertReq", "systemFailure", "systemUnavail"}; // 28 - 31

    static
    {
        statusTextMap.put(ClientErrorCode.PKIStatus_NO_ANSWER, "xipki_noAnswer");
        statusTextMap.put(ClientErrorCode.PKIStatus_RESPONSE_ERROR, "xipki_responseError");
        statusTextMap.put(PKIStatus.GRANTED, "accepted");
        statusTextMap.put(PKIStatus.GRANTED_WITH_MODS, "grantedWithMods");
        statusTextMap.put(PKIStatus.REJECTION, "rejection");
        statusTextMap.put(PKIStatus.WAITING, "waiting");
        statusTextMap.put(PKIStatus.REVOCATION_WARNING, "revocationWarning");
        statusTextMap.put(PKIStatus.REVOCATION_NOTIFICATION, "revocationNotification");
        statusTextMap.put(PKIStatus.KEY_UPDATE_WARNING, "keyUpdateWarning");
    }

    public static PKIMessage addProtection(PKIMessage pkiMessage,
            ConcurrentContentSigner signer, GeneralName signerName)
    throws CMPException, NoIdleSignerException
    {
        if(signerName == null)
        {
            X500Name x500Name = X500Name.getInstance(signer.getCertificate().getSubjectX500Principal().getEncoded());
            signerName = new GeneralName(x500Name);
        }
        PKIHeader header = pkiMessage.getHeader();
        ProtectedPKIMessageBuilder builder = new ProtectedPKIMessageBuilder(
                signerName, header.getRecipient());
        PKIFreeText freeText = header.getFreeText();
        if(freeText != null)
        {
            builder.setFreeText(freeText);
        }

        InfoTypeAndValue[] generalInfo = header.getGeneralInfo();
        if(generalInfo != null)
        {
            for(InfoTypeAndValue gi : generalInfo)
            {
                builder.addGeneralInfo(gi);
            }
        }

        ASN1OctetString octet = header.getRecipKID();
        if(octet != null)
        {
            builder.setRecipKID(octet.getOctets());
        }

        octet = header.getRecipNonce();
        if(octet != null)
        {
            builder.setRecipNonce(octet.getOctets());
        }

        octet = header.getSenderKID();
        if(octet != null)
        {
            builder.setSenderKID(octet.getOctets());
        }

        octet = header.getSenderNonce();
        if(octet != null)
        {
            builder.setSenderNonce(octet.getOctets());
        }

        octet = header.getTransactionID();
        if(octet != null)
        {
            builder.setTransactionID(octet.getOctets());
        }

        if(header.getMessageTime() != null)
        {
            builder.setMessageTime(new Date());
        }
        builder.setBody(pkiMessage.getBody());

        ContentSigner realSigner = signer.borrowContentSigner();
        try
        {
             ProtectedPKIMessage signedMessage = builder.build(realSigner);
             return signedMessage.toASN1Structure();
        }finally
        {
            signer.returnContentSigner(realSigner);
        }
    }

    public static boolean isImplictConfirm(PKIHeader header)
    {
        InfoTypeAndValue[] regInfos = header.getGeneralInfo();
        if(regInfos != null)
        {
            for (InfoTypeAndValue regInfo : regInfos)
            {
                if(CMPObjectIdentifiers.it_implicitConfirm.equals(regInfo.getInfoType()))
                {
                    return true;
                }
            }
        }
        return false;
    }

    public static InfoTypeAndValue getImplictConfirmGeneralInfo()
    {
        return new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE);
    }

    public static String formatPKIStatusInfo(org.xipki.ca.common.PKIStatusInfo pkiStatusInfo)
    {
        int status = pkiStatusInfo.getStatus();
        int failureInfo = pkiStatusInfo.getPkiFailureInfo();
        String statusMessage = pkiStatusInfo.getStatusMessage();
        return formatPKIStatusInfo(status, failureInfo, statusMessage);
    }

    public static String formatPKIStatusInfo(PKIStatusInfo pkiStatusInfo)
    {
        int status = pkiStatusInfo.getStatus().intValue();
        int failureInfo = pkiStatusInfo.getFailInfo().intValue();
        PKIFreeText text = pkiStatusInfo.getStatusString();
        String statusMessage = text == null ? null : text.getStringAt(0).getString();

        return formatPKIStatusInfo(status, failureInfo, statusMessage);
    }

    public static String formatPKIStatusInfo(int status, int failureInfo, String statusMessage)
    {
        StringBuilder sb = new StringBuilder("PKIStatusInfo {");
        sb.append("status = ");
        sb.append(status);
        sb.append(" (").append(statusTextMap.get(status)).append("), ");
        sb.append("failureInfo = ");
        sb.append(failureInfo).append(" (").append(getFailureInfoText(failureInfo)).append("), ");
        sb.append("statusMessage = ").append(statusMessage);
        sb.append("}");
        return sb.toString();
    }

    public static String getFailureInfoText(int failureInfo)
    {
        BigInteger b = BigInteger.valueOf(failureInfo);
        final int n = Math.min(b.bitLength(), failureInfoTexts.length);

        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < n; i++)
        {
            if(b.testBit(i))
            {
                sb.append(", ").append(failureInfoTexts[i]);
            }
        }

        return sb.length() < 3 ? "" : sb.substring(2);
    }

}
