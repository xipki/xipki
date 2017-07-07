// #THIRDPARTY# BouncyCastle

package org.xipki.security.bc;

import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.CertStatus;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.ContentSigner;

/**
 * Generator for basic OCSP response objects.
 */
// CHECKSTYLE:SKIP
public class XipkiBasicOCSPRespBuilder {
    private List<ResponseObject> list = new ArrayList<>();
    private Extensions responseExtensions = null;
    private ResponderID responderId;

    private class ResponseObject {
        CertID certId;
        CertStatus certStatus;
        ASN1GeneralizedTime thisUpdate;
        ASN1GeneralizedTime nextUpdate;
        Extensions extensions;

        public ResponseObject(
            CertID certId,
            CertificateStatus certStatus,
            Date thisUpdate,
            Date nextUpdate,
            Extensions extensions) {
            this.certId = certId;

            if (certStatus == null) {
                this.certStatus = new CertStatus();
            } else if (certStatus instanceof UnknownStatus) {
                this.certStatus = new CertStatus(2, DERNull.INSTANCE);
            } else {
                RevokedStatus rs = (RevokedStatus)certStatus;

                if (rs.hasRevocationReason()) {
                    this.certStatus = new CertStatus(new RevokedInfo(
                            new ASN1GeneralizedTime(rs.getRevocationTime()),
                            CRLReason.lookup(rs.getRevocationReason())));
                } else {
                    this.certStatus = new CertStatus(new RevokedInfo(
                            new ASN1GeneralizedTime(rs.getRevocationTime()),
                            null));
                }
            }

            this.thisUpdate = new DERGeneralizedTime(thisUpdate);

            if (nextUpdate != null) {
                this.nextUpdate = new DERGeneralizedTime(nextUpdate);
            } else {
                this.nextUpdate = null;
            }

            this.extensions = extensions;
        }

        public SingleResponse toResponse()
            throws Exception {
            return new SingleResponse(certId, certStatus, thisUpdate, nextUpdate, extensions);
        }
    }

    /**
     * basic constructor.
     */
    public XipkiBasicOCSPRespBuilder(
        ResponderID responderId) {
        this.responderId = responderId;
    }

    /**
     * Add a response for a particular Certificate ID.
     *
     * @param certID certificate ID details
     * @param certStatus status of the certificate - null if okay
     */
    public XipkiBasicOCSPRespBuilder addResponse(
        CertID certId,
        CertificateStatus certStatus) {
        this.addResponse(certId, certStatus, new Date(), null, null);

        return this;
    }

    /**
     * Add a response for a particular Certificate ID.
     *
     * @param certID certificate ID details
     * @param certStatus status of the certificate - null if okay
     * @param singleExtensions optional extensions
     */
    public XipkiBasicOCSPRespBuilder addResponse(
        CertID certId,
        CertificateStatus certStatus,
        Extensions singleExtensions) {
        this.addResponse(certId, certStatus, new Date(), null, singleExtensions);

        return this;
    }

    /**
     * Add a response for a particular Certificate ID.
     *
     * @param certID certificate ID details
     * @param nextUpdate date when next update should be requested
     * @param certStatus status of the certificate - null if okay
     * @param singleExtensions optional extensions
     */
    public XipkiBasicOCSPRespBuilder addResponse(
        CertID certId,
        CertificateStatus certStatus,
        Date nextUpdate,
        Extensions singleExtensions) {
        this.addResponse(certId, certStatus, new Date(), nextUpdate, singleExtensions);

        return this;
    }

    /**
     * Add a response for a particular Certificate ID.
     *
     * @param certID certificate ID details
     * @param thisUpdate date this response was valid on
     * @param nextUpdate date when next update should be requested
     * @param certStatus status of the certificate - null if okay
     * @param singleExtensions optional extensions
     */
    public XipkiBasicOCSPRespBuilder addResponse(
        CertID certId,
        CertificateStatus certStatus,
        Date thisUpdate,
        Date nextUpdate,
        Extensions singleExtensions) {
        list.add(new ResponseObject(certId, certStatus, thisUpdate, nextUpdate, singleExtensions));

        return this;
    }

    /**
     * Set the extensions for the response.
     *
     * @param responseExtensions the extension object to carry.
     */
    public XipkiBasicOCSPRespBuilder setResponseExtensions(
        Extensions  responseExtensions) {
        this.responseExtensions = responseExtensions;

        return this;
    }

    public BasicOCSPResponse build(
        ContentSigner signer,
        Certificate[] chain,
        Date producedAt)
            throws OCSPException {
        Iterator<ResponseObject> it = list.iterator();

        ASN1EncodableVector responses = new ASN1EncodableVector();

        while (it.hasNext()) {
            try {
                responses.add(((ResponseObject)it.next()).toResponse());
            } catch (Exception ex) {
                throw new OCSPException("exception creating Request", ex);
            }
        }

        ResponseData  tbsResp = new ResponseData(responderId,
                new ASN1GeneralizedTime(producedAt), new DERSequence(responses),
                responseExtensions);
        DERBitString    bitSig;

        try {
            OutputStream sigOut = signer.getOutputStream();

            sigOut.write(tbsResp.getEncoded(ASN1Encoding.DER));
            sigOut.close();

            bitSig = new DERBitString(signer.getSignature());
        } catch (Exception ex) {
            throw new OCSPException("exception processing TBSRequest: " + ex.getMessage(), ex);
        }

        AlgorithmIdentifier sigAlgId = signer.getAlgorithmIdentifier();

        DERSequence chainSeq = null;
        if (chain != null && chain.length > 0) {
            ASN1EncodableVector vec = new ASN1EncodableVector();

            for (int i = 0; i != chain.length; i++) {
                vec.add(chain[i]);
            }

            chainSeq = new DERSequence(vec);
        }

        return new BasicOCSPResponse(tbsResp, sigAlgId, bitSig, chainSeq);
    }
}
