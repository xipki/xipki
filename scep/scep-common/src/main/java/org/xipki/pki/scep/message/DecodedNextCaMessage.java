/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.pki.scep.message;

import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.CollectionStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.pki.scep.exception.MessageDecodingException;
import org.xipki.pki.scep.util.ScepUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DecodedNextCaMessage {

    private static final Logger LOG = LoggerFactory.getLogger(DecodedNextCaMessage.class);

    private AuthorityCertStore authorityCertStore;

    private X509Certificate signatureCert;

    private ASN1ObjectIdentifier digestAlgorithm;

    private Boolean signatureValid;

    private Date signingTime;

    private String failureMessage;

    public DecodedNextCaMessage() {
    }

    public AuthorityCertStore getAuthorityCertStore() {
        return authorityCertStore;
    }

    public void setAuthorityCertStore(
            final AuthorityCertStore authorityCertStore) {
        this.authorityCertStore = authorityCertStore;
    }

    public X509Certificate getSignatureCert() {
        return signatureCert;
    }

    public void setSignatureCert(
            final X509Certificate signatureCert) {
        this.signatureCert = signatureCert;
    }

    public void setDigestAlgorithm(
            final ASN1ObjectIdentifier digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public void setSignatureValid(
            final Boolean signatureValid) {
        this.signatureValid = signatureValid;
    }

    public ASN1ObjectIdentifier getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public String getFailureMessage() {
        return failureMessage;
    }

    public void setFailureMessage(
            final String failureMessage) {
        this.failureMessage = failureMessage;
    }

    public Boolean isSignatureValid() {
        return signatureValid;
    }

    public Date getSigningTime() {
        return signingTime;
    }

    public void setSigningTime(
            final Date signingTime) {
        this.signingTime = signingTime;
    }

    @SuppressWarnings("unchecked")
    public static DecodedNextCaMessage decode(
            final CMSSignedData pkiMessage,
            final CollectionStore<X509CertificateHolder> certStore)
    throws MessageDecodingException {
        ParamUtil.requireNonNull("pkiMessage", pkiMessage);

        SignerInformationStore signerStore = pkiMessage.getSignerInfos();
        Collection<SignerInformation> signerInfos = signerStore.getSigners();
        if (signerInfos.size() != 1) {
            throw new MessageDecodingException(
                    "number of signerInfos is not 1, but " + signerInfos.size());
        }

        SignerInformation signerInfo = signerInfos.iterator().next();

        SignerId sid = signerInfo.getSID();

        Collection<?> signedDataCerts = null;
        if (certStore != null) {
            signedDataCerts = certStore.getMatches(sid);
        }

        if (signedDataCerts == null || signedDataCerts.isEmpty()) {
            signedDataCerts = pkiMessage.getCertificates().getMatches(signerInfo.getSID());
        }

        if (signedDataCerts == null || signedDataCerts.size() != 1) {
            throw new MessageDecodingException(
                    "could not find embedded certificate to verify the signature");
        }

        AttributeTable signedAttrs = signerInfo.getSignedAttributes();
        if (signedAttrs == null) {
            throw new MessageDecodingException("missing signed attributes");
        }

        Date signingTime = null;
        // signingTime
        ASN1Encodable attrValue = ScepUtil.getFirstAttrValue(signedAttrs,
                CMSAttributes.signingTime);
        if (attrValue != null) {
            signingTime = Time.getInstance(attrValue).getDate();
        }

        DecodedNextCaMessage ret = new DecodedNextCaMessage();
        if (signingTime != null) {
            ret.setSigningTime(signingTime);
        }

        ASN1ObjectIdentifier digestAlgOID = signerInfo.getDigestAlgorithmID().getAlgorithm();
        ret.setDigestAlgorithm(digestAlgOID);

        String sigAlgOID = signerInfo.getEncryptionAlgOID();
        if (!PKCSObjectIdentifiers.rsaEncryption.getId().equals(sigAlgOID)) {
            ASN1ObjectIdentifier localDigestAlgOID;
            try {
                localDigestAlgOID = ScepUtil.extractDigesetAlgorithmIdentifier(
                        signerInfo.getEncryptionAlgOID(), signerInfo.getEncryptionAlgParams());
            } catch (Exception ex) {
                final String msg =
                        "could not extract digest algorithm from signerInfo.signatureAlgorithm: "
                        + ex.getMessage();
                LOG.error(msg);
                LOG.debug(msg, ex);
                ret.setFailureMessage(msg);
                return ret;
            }
            if (!digestAlgOID.equals(localDigestAlgOID)) {
                ret.setFailureMessage("digestAlgorithm and encryptionAlgorithm do not use"
                        + " the same digestAlgorithm");
                return ret;
            }
        } // end if

        X509CertificateHolder localSignerCert =
                (X509CertificateHolder) signedDataCerts.iterator().next();
        X509Certificate signerCert;
        try {
            signerCert = new X509CertificateObject(localSignerCert.toASN1Structure());
        } catch (CertificateParsingException ex) {
            final String msg = "could not construct X509CertificateObject: " + ex.getMessage();
            LOG.error(msg);
            LOG.debug(msg, ex);
            ret.setFailureMessage(msg);
            return ret;
        }
        ret.setSignatureCert(signerCert);

        // validate the signature
        SignerInformationVerifier verifier;
        try {
            verifier = new JcaSimpleSignerInfoVerifierBuilder().build(
                    signerCert.getPublicKey());
        } catch (OperatorCreationException ex) {
            final String msg = "could not build signature verifier: " + ex.getMessage();
            LOG.error(msg);
            LOG.debug(msg, ex);
            ret.setFailureMessage(msg);
            return ret;
        }

        boolean signatureValid;
        try {
            signatureValid = signerInfo.verify(verifier);
        } catch (CMSException ex) {
            final String msg = "could not verify the signature: " + ex.getMessage();
            LOG.error(msg);
            LOG.debug(msg, ex);
            ret.setFailureMessage(msg);
            return ret;
        }

        ret.setSignatureValid(signatureValid);
        if (!signatureValid) {
            return ret;
        }

        // MessageData
        CMSTypedData signedContent = pkiMessage.getSignedContent();
        ASN1ObjectIdentifier signedContentType = signedContent.getContentType();
        if (!CMSObjectIdentifiers.signedData.equals(signedContentType)) {
            // fall back: some SCEP client use id-data
            if (!CMSObjectIdentifiers.data.equals(signedContentType)) {
                ret.setFailureMessage("either id-signedData or id-data is excepted, but not '"
                        + signedContentType.getId());
                return ret;
            }
        }

        ContentInfo contentInfo = ContentInfo.getInstance((byte[]) signedContent.getContent());
        SignedData signedData = SignedData.getInstance(contentInfo.getContent());

        List<X509Certificate> certs;
        try {
            certs = ScepUtil.getCertsFromSignedData(signedData);
        } catch (CertificateException ex) {
            final String msg = "error while extracting Certificates from the message: "
                    + ex.getMessage();
            LOG.error(msg);
            LOG.debug(msg, ex);
            ret.setFailureMessage(msg);
            return ret;
        }

        final int n = certs.size();

        X509Certificate cACert = null;
        List<X509Certificate> rACerts = new LinkedList<X509Certificate>();
        for (int i = 0; i < n; i++) {
            X509Certificate c = certs.get(i);
            if (c.getBasicConstraints() > -1) {
                if (cACert != null) {
                    final String msg =
                            "multiple CA certificates is returned, but exactly 1 is expected";
                    LOG.error(msg);
                    ret.setFailureMessage(msg);
                    return ret;
                }
                cACert = c;
            } else {
                rACerts.add(c);
            }
        } // end for

        if (cACert == null) {
            final String msg = "no CA certificate is returned";
            LOG.error(msg);
            ret.setFailureMessage(msg);
            return ret;
        }

        X509Certificate[] locaRaCerts;
        if (rACerts.isEmpty()) {
            locaRaCerts = null;
        } else {
            locaRaCerts = rACerts.toArray(new X509Certificate[0]);
        }

        AuthorityCertStore authorityCertStore = AuthorityCertStore.getInstance(cACert, locaRaCerts);
        ret.setAuthorityCertStore(authorityCertStore);

        return ret;
    } // method decode

}
