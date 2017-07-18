/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.ocsp.server.impl;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.ocsp.server.impl.type.CertID;
import org.xipki.ocsp.server.impl.type.ResponseData;
import org.xipki.ocsp.server.impl.type.SingleResponse;
import org.xipki.security.ConcurrentBagEntrySigner;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.exception.NoIdleSignerException;

/**
 * Generator for OCSP response objects.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

// CHECKSTYLE:SKIP
public class OCSPRespBuilder {
    private static final byte[] successfulStatus;
    private static final byte[] responseTypeBasic;

    private List<SingleResponse> list = new LinkedList<>();
    private byte[] responseExtensions = null;
    private byte[] responderId;

    static {
        try {
            successfulStatus = new OCSPResponseStatus(OCSPResponseStatus.SUCCESSFUL).getEncoded();
            responseTypeBasic = OCSPObjectIdentifiers.id_pkix_ocsp_basic.getEncoded();
        } catch (IOException ex) {
            throw new ExceptionInInitializerError(ex);
        }
    }

    /**
     * basic constructor.
     */
    public OCSPRespBuilder(
        byte[] responderId) {
        this.responderId = responderId;
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
    public void addResponse(CertID certId, byte[] certStatus,
            Date thisUpdate, Date nextUpdate, byte[] singleExtensions) {
        list.add(new SingleResponse(certId, certStatus, thisUpdate, nextUpdate, singleExtensions));
    }

    /**
     * Set the extensions for the response.
     *
     * @param responseExtensions the extension object to carry.
     */
    public void setResponseExtensions(
        byte[]  responseExtensions) {
        this.responseExtensions = responseExtensions;
    }

    // CHECKSTYLE:SKIP
    public byte[] buildOCSPResponse(ConcurrentContentSigner signer, byte[] encodedSigAlgId,
            byte[] encodedChain, Date producedAt)
            throws OCSPException, NoIdleSignerException {
        ResponseData responseData = new ResponseData(0,
                responderId, producedAt, list, responseExtensions);

        byte[] encodedTbsResp = new byte[responseData.encodedLength()];
        responseData.write(encodedTbsResp, 0);

        ConcurrentBagEntrySigner signer0 = signer.borrowContentSigner();

        byte[] signature;
        try {
            ContentSigner csigner0 = signer0.value();
            OutputStream sigOut = csigner0.getOutputStream();
            try {
                sigOut.write(encodedTbsResp);
                sigOut.close();
            } catch (IOException ex) {
                throw new OCSPException("exception signing TBSRequest: " + ex.getMessage(), ex);
            }

            signature = csigner0.getSignature();
            if (encodedSigAlgId == null) {
                try {
                    encodedSigAlgId = csigner0.getAlgorithmIdentifier().getEncoded();
                } catch (IOException ex) {
                    throw new OCSPException("exception processing SignatureAlgorithm", ex);
                }
            }
        } finally {
            signer.requiteContentSigner(signer0);
        }

        // ----- Get the length -----
        // BasicOCSPResponse.signature
        int signatureBodyLen = signature.length + 1;
        int signatureLen = getLen(signatureBodyLen);

        // BasicOCSPResponse
        int basicResponseBodyLen = encodedTbsResp.length + encodedSigAlgId.length
                + signatureLen;
        if (encodedChain != null) {
            basicResponseBodyLen += encodedChain.length;
        }
        int basicResponseLen = getLen(basicResponseBodyLen);

        // OCSPResponse.[0].responseBytes
        int responseBytesBodyLen = responseTypeBasic.length
                + getLen(basicResponseLen); // Header of OCTET STRING
        int responseBytesLen = getLen(responseBytesBodyLen);

        // OCSPResponse.[0]
        int taggedResponseBytesLen = getLen(responseBytesLen);

        // OCSPResponse
        int ocspResponseBodyLen = successfulStatus.length
                    + taggedResponseBytesLen;
        int ocspResponseLen = getLen(ocspResponseBodyLen);

        // encode
        byte[] out = new byte[ocspResponseLen];
        int offset = 0;
        offset += writeHeader((byte) 0x30, ocspResponseBodyLen, out, offset);
        // OCSPResponse.responseStatus
        offset += arraycopy(successfulStatus, out, offset);

        // OCSPResponse.[0]
        offset += writeHeader((byte) 0xA0, responseBytesLen, out, offset);

        // OCSPResponse.[0]responseBytes
        offset += writeHeader((byte) 0x30, responseBytesBodyLen, out, offset);

        // OCSPResponse.[0]responseBytes.responseType
        offset += arraycopy(responseTypeBasic, out, offset);

        // OCSPResponse.[0]responseBytes.responseType
        offset += writeHeader((byte) 0x04, basicResponseLen, out, offset); // OCET STRING

        // BasicOCSPResponse
        offset += writeHeader((byte) 0x30, basicResponseBodyLen, out, offset);
        // BasicOCSPResponse.tbsResponseData
        offset += arraycopy(encodedTbsResp, out, offset);

        // BasicOCSPResponse.signatureAlgorithm
        offset += arraycopy(encodedSigAlgId, out, offset);

        // BasicOCSPResponse.signature
        offset += writeHeader((byte) 0x03, signatureBodyLen, out, offset);
        out[offset++] = 0x00; // skipping bits
        offset += arraycopy(signature, out, offset);

        if (encodedChain != null) {
            offset += arraycopy(encodedChain, out, offset);
        }
        return out;
    }

    private static int getLen(int bodyLen) {
        int headerLen;
        if (bodyLen < 0x80) {
            headerLen = 2;
        } else if (bodyLen < 0x100) {
            headerLen = 3;
        } else if (bodyLen < 0x10000) {
            headerLen = 4;
        } else if (bodyLen < 0x1000000) {
            headerLen = 5;
        } else {
            headerLen = 6;
        }
        return headerLen + bodyLen;
    }

    private static int writeHeader(byte tag, int bodyLen, byte[] out, int offset) {
        out[offset++] = tag;
        if (bodyLen < 0x80) {
            out[offset] = (byte) bodyLen;
            return 2;
        } else if (bodyLen < 0x100) {
            out[offset++] = (byte) 0x81;
            out[offset] = (byte) bodyLen;
            return 3;
        } else if (bodyLen < 0x10000) {
            out[offset++] = (byte) 0x82;
            out[offset++] = (byte) (       bodyLen >> 8);
            out[offset]   = (byte) (0xFF & bodyLen);
            return 4;
        } else if (bodyLen < 0x1000000) {
            out[offset++] = (byte) 0x83;
            out[offset++] = (byte) (        bodyLen >> 16);
            out[offset++] = (byte) (0xFF & (bodyLen >> 8));
            out[offset]   = (byte) (0xFF &  bodyLen);
            return 5;
        } else {
            out[offset++] = (byte) 0x84;
            out[offset++] = (byte) (        bodyLen >> 24);
            out[offset++] = (byte) (0xFF & (bodyLen >> 16));
            out[offset++] = (byte) (0xFF & (bodyLen >> 8));
            out[offset]   = (byte) (0xFF &  bodyLen);
            return 6;
        }
    }

    private static int arraycopy(byte[] src, byte[] dest, int destPos) {
        System.arraycopy(src, 0, dest, destPos, src.length);
        return src.length;
    }

}
