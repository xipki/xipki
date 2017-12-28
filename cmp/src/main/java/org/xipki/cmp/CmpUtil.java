/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.cmp;

import java.util.Date;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.ConcurrentBagEntrySigner;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.exception.NoIdleSignerException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CmpUtil {

    private CmpUtil() {
    }

    public static PKIMessage addProtection(final PKIMessage pkiMessage,
            final ConcurrentContentSigner signer, final GeneralName signerName,
            final boolean addSignerCert) throws CMPException, NoIdleSignerException {
        ParamUtil.requireNonNull("pkiMessage", pkiMessage);
        ParamUtil.requireNonNull("signer", signer);

        final GeneralName tmpSignerName;
        if (signerName != null) {
            tmpSignerName = signerName;
        } else {
            if (signer.getCertificate() == null) {
                throw new IllegalArgumentException("signer without certificate is not allowed");
            }
            X500Name x500Name = X500Name.getInstance(
                    signer.getCertificate().getSubjectX500Principal().getEncoded());
            tmpSignerName = new GeneralName(x500Name);
        }
        PKIHeader header = pkiMessage.getHeader();
        ProtectedPKIMessageBuilder builder = new ProtectedPKIMessageBuilder(
                tmpSignerName, header.getRecipient());
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

        octet = header.getSenderKID();
        if (octet != null) {
            builder.setSenderKID(octet.getOctets());
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

        if (addSignerCert) {
            X509CertificateHolder signerCert = signer.getCertificateAsBcObject();
            builder.addCMPCertificate(signerCert);
        }

        ConcurrentBagEntrySigner signer0 = signer.borrowContentSigner();
        ProtectedPKIMessage signedMessage;
        try {
            signedMessage = builder.build(signer0.value());
        } finally {
            signer.requiteContentSigner(signer0);
        }
        return signedMessage.toASN1Structure();
    } // method addProtection

    public static boolean isImplictConfirm(final PKIHeader header) {
        ParamUtil.requireNonNull("header", header);

        InfoTypeAndValue[] regInfos = header.getGeneralInfo();
        if (regInfos == null) {
            return false;
        }

        for (InfoTypeAndValue regInfo : regInfos) {
            if (CMPObjectIdentifiers.it_implicitConfirm.equals(regInfo.getInfoType())) {
                return true;
            }
        }
        return false;
    }

    public static InfoTypeAndValue getImplictConfirmGeneralInfo() {
        return new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE);
    }

    public static CmpUtf8Pairs extract(final InfoTypeAndValue[] regInfos) {
        if (regInfos == null) {
            return null;
        }

        for (InfoTypeAndValue regInfo : regInfos) {
            if (CMPObjectIdentifiers.regInfo_utf8Pairs.equals(regInfo.getInfoType())) {
                String regInfoValue = ((ASN1String) regInfo.getInfoValue()).getString();
                return new CmpUtf8Pairs(regInfoValue);
            }
        }

        return null;
    }

    public static CmpUtf8Pairs extract(final AttributeTypeAndValue[] atvs) {
        if (atvs == null) {
            return null;
        }

        for (AttributeTypeAndValue atv : atvs) {
            if (CMPObjectIdentifiers.regInfo_utf8Pairs.equals(atv.getType())) {
                String regInfoValue = ((ASN1String) atv.getValue()).getString();
                return new CmpUtf8Pairs(regInfoValue);
            }
        }

        return null;
    }

    public static InfoTypeAndValue buildInfoTypeAndValue(final CmpUtf8Pairs utf8Pairs) {
        ParamUtil.requireNonNull("utf8Pairs", utf8Pairs);
        return new InfoTypeAndValue(CMPObjectIdentifiers.regInfo_utf8Pairs,
                new DERUTF8String(utf8Pairs.encoded()));
    }

    public static AttributeTypeAndValue buildAttributeTypeAndValue(final CmpUtf8Pairs utf8Pairs) {
        ParamUtil.requireNonNull("utf8Pairs", utf8Pairs);
        return new AttributeTypeAndValue(CMPObjectIdentifiers.regInfo_utf8Pairs,
                new DERUTF8String(utf8Pairs.encoded()));
    }

}
