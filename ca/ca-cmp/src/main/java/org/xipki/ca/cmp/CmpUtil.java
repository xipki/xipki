/*
 * Copyright 2014 xipki.org
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
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;

public class CmpUtil
{
    public static final Map<Integer, String> statusTextMap = new HashMap<Integer, String>();
    public static final Map<Integer, String> failureInfoTextMap = new HashMap<Integer, String>();

    static
    {
        statusTextMap.put(PKIStatus.GRANTED, "accepted");
        statusTextMap.put(PKIStatus.GRANTED_WITH_MODS, "grantedWithMods");
        statusTextMap.put(PKIStatus.REJECTION, "rejection");
        statusTextMap.put(PKIStatus.WAITING, "waiting");
        statusTextMap.put(PKIStatus.REVOCATION_WARNING, "revocationWarning");
        statusTextMap.put(PKIStatus.REVOCATION_NOTIFICATION, "revocationNotification");
        statusTextMap.put(PKIStatus.KEY_UPDATE_WARNING, "keyUpdateWarning");

        failureInfoTextMap.put(PKIFailureInfo.badAlg, "badAlg");
        failureInfoTextMap.put(PKIFailureInfo.badMessageCheck, "badMessageCheck");
        failureInfoTextMap.put(PKIFailureInfo.badRequest, "badRequest");
        failureInfoTextMap.put(PKIFailureInfo.badTime, "badTime");
        failureInfoTextMap.put(PKIFailureInfo.badCertId, "badCertId");
        failureInfoTextMap.put(PKIFailureInfo.badDataFormat, "badDataFormat");
        failureInfoTextMap.put(PKIFailureInfo.wrongAuthority, "wrongAuthority");
        failureInfoTextMap.put(PKIFailureInfo.incorrectData, "incorrectData");
        failureInfoTextMap.put(PKIFailureInfo.missingTimeStamp, "missingTimeStamp");
        failureInfoTextMap.put(PKIFailureInfo.badPOP, "badPOP");
        failureInfoTextMap.put(PKIFailureInfo.certRevoked, "certRevoked");
        failureInfoTextMap.put(PKIFailureInfo.certConfirmed, "certConfirmed");
        failureInfoTextMap.put(PKIFailureInfo.wrongIntegrity, "wrongIntegrity");
        failureInfoTextMap.put(PKIFailureInfo.badRecipientNonce, "badRecipientNonce");
        failureInfoTextMap.put(PKIFailureInfo.timeNotAvailable, "timeNotAvailable");
        failureInfoTextMap.put(PKIFailureInfo.unacceptedPolicy, "unacceptedPolicy");
        failureInfoTextMap.put(PKIFailureInfo.unacceptedExtension, "unacceptedExtension");
        failureInfoTextMap.put(PKIFailureInfo.addInfoNotAvailable, "addInfoNotAvailable");
        failureInfoTextMap.put(PKIFailureInfo.badSenderNonce, "badSenderNonce");
        failureInfoTextMap.put(PKIFailureInfo.badCertTemplate, "badCertTemplate");
        failureInfoTextMap.put(PKIFailureInfo.signerNotTrusted, "signerNotTrusted");
        failureInfoTextMap.put(PKIFailureInfo.transactionIdInUse, "transactionIdInUse");
        failureInfoTextMap.put(PKIFailureInfo.unsupportedVersion, "unsupportedVersion");
        failureInfoTextMap.put(PKIFailureInfo.notAuthorized, "notAuthorized");
        failureInfoTextMap.put(PKIFailureInfo.systemUnavail, "systemUnavail");
        failureInfoTextMap.put(PKIFailureInfo.systemFailure, "systemFailure");
        failureInfoTextMap.put(PKIFailureInfo.duplicateCertReq, "duplicateCertReq");
    }

    public static PKIMessage addProtection(PKIMessage pkiMessage,
            ConcurrentContentSigner signer, GeneralName signerName,
            int signServiceTimeout)
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

        ContentSigner realSigner = signer.borrowContentSigner(signServiceTimeout);
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
        String s = statusTextMap.get(status);
        sb.append("status = ").append(status).append(" (").append(s).append("), ");
        s = failureInfoTextMap.get(status);
        sb.append("failureInfo = ").append(failureInfo).append(" (").append(s).append("), ");
        sb.append("statusMessage = ").append(statusMessage);
        sb.append("}");
        return sb.toString();
    }

}
