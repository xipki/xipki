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

package org.xipki.pki.ocsp.server.impl.type;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.security.HashAlgoType;
import org.xipki.security.ObjectIdentifiers;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class OcspRequest {

    private static class Header {
        byte tag;
        int len;
        int readerIndex;

        Header(byte tag, int len, int readerIndex) {
            this.tag = tag;
            this.len = len;
            this.readerIndex = readerIndex;
        }

        @Override
        public String toString() {
            return "tag=0x" + Integer.toHexString(0xFF & tag)
                    + ", len=" + len
                    + ", readerIndex=" + readerIndex;
        }
    }

    private static final String id_pkix_ocsp_nonce;
    private static final String id_pkix_ocsp_prefSigAlgs;

    private static final byte[] bytes_id_pkix_ocsp_nonce;
    private static final byte[] bytes_id_pkix_ocsp_prefSigAlgs;

    private final int version;

    private final byte[] nonce;

    private final List<CertID> requestList;

    private final List<AlgorithmIdentifier> prefSigAlgs;

    private final Set<String> criticalExtensionTypes;

    static {
        id_pkix_ocsp_nonce = OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId();
        id_pkix_ocsp_prefSigAlgs = ObjectIdentifiers.id_pkix_ocsp_prefSigAlgs.getId();
        try {
            bytes_id_pkix_ocsp_nonce =
                    OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getEncoded();
            bytes_id_pkix_ocsp_prefSigAlgs =
                    ObjectIdentifiers.id_pkix_ocsp_prefSigAlgs.getEncoded();
        } catch (IOException ex) {
            throw new IllegalStateException("could not happen", ex);
        }
    }

    public OcspRequest(int version, byte[] nonce, List<CertID> requestList,
            List<AlgorithmIdentifier> prefSigAlgs, Set<String> criticalExtensionTypes) {
        this.version = version;
        this.nonce = nonce;
        this.requestList = requestList;
        this.prefSigAlgs = prefSigAlgs;
        this.criticalExtensionTypes = criticalExtensionTypes ;
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
            Header hdrHashAlgoOid = readHeader(request, hdrHashAlgo.readerIndex);
            byte[] encodedOid = readContent(request, hdrHashAlgo.readerIndex,
                    hdrHashAlgoOid.readerIndex - hdrHashAlgo.readerIndex + hdrHashAlgoOid.len);
            HashAlgoType hashAlgo = HashAlgoType.getInstanceForEncoded(encodedOid);
            if (hashAlgo == null) {
                throw new EncodingException(
                        "unsupported hash algorithm " + Hex.toHexString(encodedOid));
            }

            Header hdrNameHash = readHeader(request, hdrHashAlgo.readerIndex + hdrHashAlgo.len);
            byte[] nameHash = readContent(request, hdrNameHash);

            Header hdrKeyHash = readHeader(request, hdrNameHash.readerIndex + hdrNameHash.len);
            byte[] keyHash = readContent(request, hdrKeyHash);

            Header hdrSerial = readHeader(request, hdrKeyHash.readerIndex + hdrKeyHash.len);
            BigInteger serialNumber = new BigInteger(readContent(request, hdrSerial));
            CertID certId = new CertID(hashAlgo, nameHash, keyHash, serialNumber);
            requestList.add(certId);

            int nextIndex = hdrSingleReq.readerIndex + hdrSingleReq.len;
            if (nextIndex < hdrRequestList.readerIndex + hdrRequestList.len) {
                hdrSingleReq = readHeader(request, nextIndex);
            } else {
                break;
            }
        }

        // extensions
        byte[] nonce = null;
        List<AlgorithmIdentifier> prefSigAlgs = new LinkedList<>();
        Set<String> criticalExtensionTypes = new HashSet<>();

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
                Header hdrExtnId = readHeader(request, hdrExtension.readerIndex);
                Header hdr0 = readHeader(request, hdrExtnId.readerIndex + hdrExtnId.len);

                boolean critical;
                Header hdrExtnValue;
                if (hdr0.tag == 0x04) {
                    hdrExtnValue = hdr0;
                    critical = false;
                } else {
                    critical = request[hdr0.readerIndex] == (byte) 0xFF;
                    hdrExtnValue = readHeader(request, hdr0.readerIndex + hdr0.len);
                }

                byte[] encodedOid = readContent(request, hdrExtension.readerIndex,
                        hdrExtnId.readerIndex - hdrExtension.readerIndex + hdrExtnId.len);

                if (Arrays.equals(bytes_id_pkix_ocsp_nonce, encodedOid)) {
                    if (critical) {
                        criticalExtensionTypes.add(id_pkix_ocsp_nonce);
                    }
                    nonce = readContent(request, hdrExtnValue);
                } else if (Arrays.equals(bytes_id_pkix_ocsp_prefSigAlgs, encodedOid)) {
                    if (critical) {
                        criticalExtensionTypes.add(id_pkix_ocsp_prefSigAlgs);
                    }
                    byte[] extnValue = readContent(request, hdrExtnValue);
                    ASN1Sequence seq = ASN1Sequence.getInstance(extnValue);
                    final int n = seq.size();
                    for (int i = 0; i < n; i++) {
                        AlgorithmIdentifier algId =
                                AlgorithmIdentifier.getInstance(seq.getObjectAt(i));
                        prefSigAlgs.add(algId);
                    }
                } else {
                    if (critical) {
                        throw new EncodingException("could not parse critical extension "
                                + ASN1ObjectIdentifier.getInstance(encodedOid).getId());
                    }
                }

                int nextIndex = hdrExtension.readerIndex + hdrExtension.len;
                if (nextIndex < hdrExtensions.readerIndex + hdrExtensions.len) {
                    hdrExtension = readHeader(request, nextIndex);
                } else {
                    break;
                }
            }
        }

        return new OcspRequest(version, nonce, requestList, prefSigAlgs, criticalExtensionTypes);
    }

    public static OcspRequest getInstance(OCSPRequest req) throws EncodingException {
        TBSRequest tbsReq0 = req.getTbsRequest();
        int version = tbsReq0.getVersion().getValue().intValue();

        Extensions extensions0 = tbsReq0.getRequestExtensions();
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

            ASN1ObjectIdentifier oid = certId0.getHashAlgorithm().getAlgorithm();
            HashAlgoType hashAlgo = HashAlgoType.getHashAlgoType(oid);
            if (hashAlgo == null) {
                throw new EncodingException("unsupported hash algorithm " + oid.getId());
            }

            CertID certId = new CertID(
                    hashAlgo,
                    certId0.getIssuerNameHash().getOctets(),
                    certId0.getIssuerKeyHash().getOctets(),
                    certId0.getSerialNumber().getValue());
            requestList.add(certId);
        }

        byte[] nonce = null;
        List<AlgorithmIdentifier> prefSigAlgs = new LinkedList<>();

        if (extensions0 != null) {
            Extension extn = extensions0.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (extn != null) {
                nonce = extn.getExtnValue().getOctets();
            }

            extn = extensions0.getExtension(ObjectIdentifiers.id_pkix_ocsp_prefSigAlgs);
            if (extn != null) {
                ASN1Sequence seq = ASN1Sequence.getInstance(extn.getParsedValue());
                final int n2 = seq.size();
                for (int i = 0; i < n2; i++) {
                    prefSigAlgs.add(AlgorithmIdentifier.getInstance(
                            seq.getObjectAt(i)));
                }
            }
        }

        return new OcspRequest(version, nonce, requestList, prefSigAlgs, criticalExtensionOids);
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

    private static Header readHeader(final byte[] encoded, final int readerIndex)
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
        return new Header(tag, len, off);
    }

    private static byte[] readContent(byte[] encoded, int offset, int len) {
        byte[] content = new byte[len];
        System.arraycopy(encoded, offset, content, 0, len);
        return content;
    }

    private static byte[] readContent(byte[] encoded, Header header) {
        byte[] content = new byte[header.len];
        System.arraycopy(encoded, header.readerIndex, content, 0, header.len);
        return content;
    }

    public int version() {
        return version;
    }

    public byte[] nonce() {
        return nonce;
    }

    public List<CertID> requestList() {
        return requestList;
    }

    public List<AlgorithmIdentifier> prefSigAlgs() {
        return prefSigAlgs;
    }

    public Set<String> criticalExtensionTypes() {
        return criticalExtensionTypes;
    }

}
