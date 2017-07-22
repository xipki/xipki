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

package org.xipki.ocsp.server.impl.type;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.xipki.ocsp.api.RequestIssuer;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class OcspRequest {

    static class Header {
        int tagIndex;
        byte tag;
        int len;
        int readerIndex;

        Header(int tagIndex, byte tag, int len, int readerIndex) {
            this.tagIndex = tagIndex;
            this.tag = tag;
            this.len = len;
            this.readerIndex = readerIndex;
        }

        @Override
        public String toString() {
            return "tag=0x" + Integer.toHexString(0xFF & tag)
                    + ", len=" + len
                    + ", tagIndex=" + tagIndex
                    + ", readerIndex=" + readerIndex;
        }
    }

    private final int version;

    private final List<Extension> extensions;

    private final List<CertID> requestList;

    public OcspRequest(int version, List<CertID> requestList, List<Extension> extensions) {
        this.version = version;
        this.requestList = requestList;
        this.extensions = extensions ;
    }

    public static OcspRequest getInstance(byte[] request) throws EncodingException {
        // OCSPRequest
        Header hdr = readHeader(request, 0);
        // tbsRequest
        Header hdrTbs = readHeader(request, hdr.readerIndex);

        int version = 0;

        // First element of the tbsRequest
        hdr = readHeader(request, hdrTbs.readerIndex);
        boolean tagged = (hdr.tag & 0x80) != 0;
        int tag = hdr.tag & 0x1F;

        if (tagged) {
            if (tag == 0) {
                Header hdr0 = readHeader(request, hdr.readerIndex);
                if (hdr0.len == 1) {
                    version = 0xFF & request[hdr0.readerIndex];
                } else {
                    throw new EncodingException("version too large");
                }
            }

            // read till requestList
            while ((hdr.tag & 0x80) != 0) {
                hdr = readHeader(request, hdr.readerIndex + hdr.len);
            }
        }

        List<CertID> requestList = new LinkedList<>();
        Header hdrRequestList = hdr;

        Header hdrSingleReq = readHeader(request, hdr.readerIndex);
        // requestList
        while (true) {
            Header hdrCertId = readHeader(request, hdrSingleReq.readerIndex);
            Header hdrHashAlgo = readHeader(request, hdrCertId.readerIndex);
            Header hdrNameHash = readHeader(request, hdrHashAlgo.readerIndex + hdrHashAlgo.len);
            Header hdrKeyHash = readHeader(request, hdrNameHash.readerIndex + hdrNameHash.len);
            Header hdrSerial = readHeader(request, hdrKeyHash.readerIndex + hdrKeyHash.len);
            RequestIssuer issuer = new RequestIssuer(request, hdrCertId.readerIndex,
                    hdrKeyHash.readerIndex + hdrKeyHash.len - hdrCertId.readerIndex);

            BigInteger serialNumber = new BigInteger(readContent(request, hdrSerial));
            CertID certId = new CertID(issuer, serialNumber);
            requestList.add(certId);

            int nextIndex = hdrSingleReq.readerIndex + hdrSingleReq.len;
            if (nextIndex < hdrRequestList.readerIndex + hdrRequestList.len) {
                hdrSingleReq = readHeader(request, nextIndex);
            } else {
                break;
            }
        }

        // extensions
        List<Extension> extensions = new LinkedList<>();
        int extensionsOffset = hdrRequestList.readerIndex + hdrRequestList.len;

        if (extensionsOffset < hdrTbs.readerIndex + hdrTbs.len) {
            hdr = readHeader(request, extensionsOffset);
            tag = hdr.tag;
            if ((tag & 0x80) == 0 || (tag & 0x1F) != 2) {
                throw new EncodingException("invalid element after requestList");
            }
            Header hdrExtensions = readHeader(request, hdr.readerIndex);

            Header hdrExtension = readHeader(request, hdrExtensions.readerIndex);
            while (true) {
                int extensionLen =
                        hdrExtension.readerIndex - hdrExtension.tagIndex + hdrExtension.len;
                Extension extn = Extension.getInstance(
                        request, hdrExtension.tagIndex, extensionLen);
                if (extn != null) {
                    extensions.add(extn);
                }

                int nextIndex = hdrExtension.readerIndex + hdrExtension.len;
                if (nextIndex < hdrExtensions.readerIndex + hdrExtensions.len) {
                    hdrExtension = readHeader(request, nextIndex);
                } else {
                    break;
                }
            }
        }

        return new OcspRequest(version, requestList, extensions);
    }

    public static OcspRequest getInstance(OCSPRequest req) throws EncodingException {
        TBSRequest tbsReq0 = req.getTbsRequest();
        int version = tbsReq0.getVersion().getValue().intValue();

        org.bouncycastle.asn1.x509.Extensions extensions0 = tbsReq0.getRequestExtensions();
        Set<String> criticalExtensionOids = new HashSet<>();
        if (extensions0 != null) {
            for (ASN1ObjectIdentifier oid : extensions0.getCriticalExtensionOIDs()) {
                criticalExtensionOids.add(oid.getId());
            }
        }

        ASN1Sequence requestList0 = tbsReq0.getRequestList();

        final int n = requestList0.size();
        List<CertID> requestList = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            Request singleReq0 = Request.getInstance(requestList0.getObjectAt(i));
            org.bouncycastle.asn1.ocsp.CertID certId0 = singleReq0.getReqCert();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try {
                out.write(certId0.getHashAlgorithm().getEncoded());
                out.write(certId0.getIssuerNameHash().getEncoded());
                out.write(certId0.getIssuerKeyHash().getEncoded());
            } catch (IOException ex) {
                throw new EncodingException(ex.getMessage(), ex);
            }

            byte[] encodedIssuer = out.toByteArray();
            RequestIssuer issuer = new RequestIssuer(encodedIssuer,0, encodedIssuer.length);
            CertID certId = new CertID(issuer, certId0.getSerialNumber().getValue());
            requestList.add(certId);
        }

        List<Extension> extensions = new LinkedList<>();
        if (extensions0 != null) {
            ASN1ObjectIdentifier[] extOids = extensions0.getExtensionOIDs();
            for (ASN1ObjectIdentifier oid : extOids) {
                org.bouncycastle.asn1.x509.Extension extension0 = extensions0.getExtension(oid);
                byte[] encoded;
                try {
                    encoded = extension0.getEncoded();
                } catch (IOException ex) {
                    throw new EncodingException("error encoding Extension", ex);
                }
                extensions.add(Extension.getInstance(encoded, 0, encoded.length));
            }
        }

        return new OcspRequest(version, requestList, extensions);
    }

    public static int readRequestVersion(byte[] request) throws EncodingException {
        // OCSPRequest
        Header hdr = readHeader(request, 0);
        // tbsRequest
        hdr = readHeader(request, hdr.readerIndex);
        // First element of the tbsRequest
        hdr = readHeader(request, hdr.readerIndex);
        if ((hdr.tag & 0x1F) != 0) {
            // version not present, default to 0
            return 0;
        } else {
            hdr = readHeader(request, hdr.readerIndex);
            if (hdr.len == 1) {
                return 0xFF & request[hdr.readerIndex];
            } else {
                throw new EncodingException("version too large");
            }
        }
    }

    public static boolean containsSignature(byte[] request) throws EncodingException {
        // OCSPRequest
        Header hdr = readHeader(request, 0);
        // tbsRequest
        Header hdrTbs = readHeader(request, hdr.readerIndex);
        int signatureIndex = hdrTbs.readerIndex + hdrTbs.len;
        return signatureIndex < request.length;
    }

    static Header readHeader(final byte[] encoded, final int readerIndex)
            throws EncodingException {
        int off = readerIndex;
        byte tag = encoded[off++];
        int len = 0xFF & encoded[off++];
        if (len >= 0x80) {
            int lenSize = len & 0x7F;
            if (lenSize == 1) {
                len = 0xFF & encoded[off++];
            } else if (lenSize == 2) {
                len = ((0xFF & encoded[off++]) << 8)
                        | (0xFF & encoded[off++]);
            } else if (lenSize == 3) {
                len = ((0xFF & encoded[off++]) << 16)
                        | ((0xFF & encoded[off++]) << 8)
                        | (0xFF & encoded[off++]);
            } else if (lenSize == 4) {
                len = ((0xFF & encoded[off++]) << 24)
                        | ((0xFF & encoded[off++]) << 16)
                        | ((0xFF & encoded[off++]) << 8)
                        | (0xFF & encoded[off++]);
            } else {
                throw new EncodingException("invalid length field at " + readerIndex);
            }
        }
        return new Header(readerIndex, tag, len, off);
    }

    private static byte[] readContent(byte[] encoded, Header header) {
        byte[] content = new byte[header.len];
        System.arraycopy(encoded, header.readerIndex, content, 0, header.len);
        return content;
    }

    public int version() {
        return version;
    }

    public List<CertID> requestList() {
        return requestList;
    }

    public List<Extension> extensions() {
        return extensions;
    }

}
