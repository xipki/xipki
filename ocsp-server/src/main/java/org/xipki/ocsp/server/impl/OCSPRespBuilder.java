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

package org.xipki.ocsp.server.impl;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.common.ASN1Type;
import org.xipki.ocsp.server.impl.type.CertID;
import org.xipki.ocsp.server.impl.type.Extensions;
import org.xipki.ocsp.server.impl.type.ResponderID;
import org.xipki.ocsp.server.impl.type.ResponseData;
import org.xipki.ocsp.server.impl.type.SingleResponse;
import org.xipki.ocsp.server.impl.type.TaggedCertSequence;
import org.xipki.security.ConcurrentBagEntrySigner;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.XiContentSigner;
import org.xipki.security.exception.NoIdleSignerException;

/**
 * Generator for OCSP response objects.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

// CHECKSTYLE:SKIP
public class OCSPRespBuilder {
    private static final byte[] successfulStatus = Hex.decode("0a0100");
    private static final byte[] responseTypeBasic = Hex.decode("06092b0601050507300101");

    private List<SingleResponse> list = new LinkedList<>();
    private Extensions responseExtensions = null;
    private ResponderID responderId;

    /**
     * basic constructor.
     *
     * @param responderId
     *          Responder ID
     */
    public OCSPRespBuilder(ResponderID responderId) {
        this.responderId = responderId;
    }

    /**
     * Add a response for a particular Certificate ID.
     *
     * @param certId certificate ID details
     * @param thisUpdate date this response was valid on
     * @param nextUpdate date when next update should be requested
     * @param certStatus status of the certificate - null if okay
     * @param singleExtensions optional extensions
     */
    public void addResponse(CertID certId, byte[] certStatus,
            Date thisUpdate, Date nextUpdate, Extensions singleExtensions) {
        list.add(new SingleResponse(certId, certStatus, thisUpdate, nextUpdate, singleExtensions));
    }

    /**
     * Set the extensions for the response.
     *
     * @param responseExtensions the extension object to carry.
     */
    public void setResponseExtensions(
        Extensions  responseExtensions) {
        this.responseExtensions = responseExtensions;
    }

    // CHECKSTYLE:SKIP
    public byte[] buildOCSPResponse(ConcurrentContentSigner signer,
            TaggedCertSequence taggedCertSequence, Date producedAt)
            throws OCSPException, NoIdleSignerException {
        ResponseData responseData = new ResponseData(0,
                responderId, producedAt, list, responseExtensions);

        byte[] tbs = new byte[responseData.encodedLength()];
        responseData.write(tbs, 0);

        ConcurrentBagEntrySigner signer0 = signer.borrowSigner();

        byte[] signature;
        byte[] sigAlgId;

        try {
            XiContentSigner csigner0 = signer0.value();
            OutputStream sigOut = csigner0.getOutputStream();
            try {
                sigOut.write(tbs);
                sigOut.close();
            } catch (IOException ex) {
                throw new OCSPException("exception signing TBSRequest: " + ex.getMessage(), ex);
            }

            signature = csigner0.getSignature();
            sigAlgId = csigner0.getEncodedAlgorithmIdentifier();
        } finally {
            signer.requiteSigner(signer0);
        }

        // ----- Get the length -----
        // BasicOCSPResponse.signature
        int signatureBodyLen = signature.length + 1;
        int signatureLen = getLen(signatureBodyLen);

        // BasicOCSPResponse
        int basicResponseBodyLen = tbs.length + sigAlgId.length + signatureLen;
        if (taggedCertSequence != null) {
            basicResponseBodyLen += taggedCertSequence.encodedLength();
        }
        int basicResponseLen = getLen(basicResponseBodyLen);

        // OCSPResponse.[0].responseBytes
        int responseBytesBodyLen = responseTypeBasic.length
                + getLen(basicResponseLen); // Header of OCTET STRING
        int responseBytesLen = getLen(responseBytesBodyLen);

        // OCSPResponse.[0]
        int taggedResponseBytesLen = getLen(responseBytesLen);

        // OCSPResponse
        int ocspResponseBodyLen = successfulStatus.length + taggedResponseBytesLen;
        int ocspResponseLen = getLen(ocspResponseBodyLen);

        // encode
        byte[] out = new byte[ocspResponseLen];
        int offset = 0;
        offset += ASN1Type.writeHeader((byte) 0x30, ocspResponseBodyLen, out, offset);
        // OCSPResponse.responseStatus
        offset += arraycopy(successfulStatus, out, offset);

        // OCSPResponse.[0]
        offset += ASN1Type.writeHeader((byte) 0xA0, responseBytesLen, out, offset);

        // OCSPResponse.[0]responseBytes
        offset += ASN1Type.writeHeader((byte) 0x30, responseBytesBodyLen, out, offset);

        // OCSPResponse.[0]responseBytes.responseType
        offset += arraycopy(responseTypeBasic, out, offset);

        // OCSPResponse.[0]responseBytes.responseType
        offset += ASN1Type.writeHeader((byte) 0x04, basicResponseLen, out, offset); // OCET STRING

        // BasicOCSPResponse
        offset += ASN1Type.writeHeader((byte) 0x30, basicResponseBodyLen, out, offset);
        // BasicOCSPResponse.tbsResponseData
        offset += arraycopy(tbs, out, offset);

        // BasicOCSPResponse.signatureAlgorithm
        offset += arraycopy(sigAlgId, out, offset);

        // BasicOCSPResponse.signature
        offset += ASN1Type.writeHeader((byte) 0x03, signatureBodyLen, out, offset);
        out[offset++] = 0x00; // skipping bits
        offset += arraycopy(signature, out, offset);

        if (taggedCertSequence != null) {
            offset += taggedCertSequence.write(out, offset);
        }
        return out;
    }

    private static int getLen(int bodyLen) {
        return ASN1Type.getHeaderLen(bodyLen) + bodyLen;
    }

    private static int arraycopy(byte[] src, byte[] dest, int destPos) {
        System.arraycopy(src, 0, dest, destPos, src.length);
        return src.length;
    }

}
