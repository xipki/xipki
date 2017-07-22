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

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.ASN1Type;
import org.xipki.ocsp.server.impl.type.OcspRequest.Header;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class Extension extends ASN1Type {

    private static final Logger LOG = LoggerFactory.getLogger(Extension.class);

    private static final byte[] bytes_critical = Hex.decode("0101FF");

    private final OID extnType;

    private final byte[] encoded;

    private final int from;

    private final boolean critical;

    private final int encodedLength;

    private final int extnValueFrom;

    private final int extnValueLength;

    public Extension(OID extnType, boolean critical, byte[] extnValue) {
        int bodyLen = extnType.encodedLength();
        if (critical) {
            bodyLen += 3;
        }
        bodyLen += getLen(extnValue.length);

        this.extnType = extnType;
        this.critical = critical;
        encodedLength = getLen(bodyLen);
        extnValueLength = extnValue.length;
        extnValueFrom = encodedLength - extnValueLength;
        from = 0;
        encoded = new byte[encodedLength];

        int offset = writeHeader((byte) 0x30, bodyLen, encoded, 0);
        offset += extnType.write(encoded, offset);
        if (critical) {
            offset += arraycopy(bytes_critical, encoded, offset);
        }
        offset += writeHeader((byte) 0x04, extnValue.length, encoded, offset);
        arraycopy(extnValue, encoded, offset);
    }

    private Extension(OID extnType, byte[] encoded, int from, boolean critical, int encodedLength,
            int extnValueFrom, int extnValueLength) {
        super();
        this.extnType = extnType;
        this.encoded = encoded;
        this.from = from;
        this.critical = critical;
        this.encodedLength = encodedLength;
        this.extnValueFrom = extnValueFrom;
        this.extnValueLength = extnValueLength;
    }

    public static Extension getInstance(byte[] encoded, int from, int len)
            throws EncodingException {
        Header hdrExtn = OcspRequest.readHeader(encoded, from);
        Header hdrOid = OcspRequest.readHeader(encoded, hdrExtn.readerIndex);
        Header hdrNext = OcspRequest.readHeader(encoded, hdrOid.readerIndex + hdrOid.len);
        Header hdrExtValue;

        boolean critical;
        if (hdrNext.tag == 0x01) { // criticial
            critical = encoded[hdrNext.readerIndex] == (byte) 0xFF;
            hdrExtValue = OcspRequest.readHeader(encoded, hdrNext.readerIndex + hdrNext.len);
        } else {
            critical = false;
            hdrExtValue = hdrNext;
        }

        OID extnType = OID.getInstanceForEncoded(encoded, hdrOid.tagIndex);
        if (extnType == null) {
            byte[] bytes = new byte[hdrOid.readerIndex - hdrOid.tagIndex + hdrOid.len];
            System.arraycopy(encoded, hdrOid.tag, bytes, 0, bytes.length);
            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(bytes);
            LOG.warn("unknown extension {}", oid.getId());
            if (critical) {
                throw new EncodingException("unkown critical extension: " + oid.getId());
            } else {
                return null;
            }
        }

        int extnValueFrom = hdrExtValue.readerIndex;
        int extnValueLength = hdrExtValue.len;

        return new Extension(extnType, encoded, from, critical, len,
                extnValueFrom, extnValueLength);
    }

    public boolean isCritical() {
        return critical;
    }

    public OID extnType() {
        return extnType;
    }

    public int extnValueLength() {
        return extnValueLength;
    }

    @Override
    public int encodedLength() {
        return encodedLength;
    }

    public InputStream getExtnValueStream() {
        return new ByteArrayInputStream(encoded, extnValueFrom, extnValueLength);
    }

    @Override
    public int write(byte[] out, int offset) {
        System.arraycopy(encoded, from, out, offset, encodedLength);
        return encodedLength;
    }

    public int writeExtnValue(byte[] out, int offset) {
        System.arraycopy(encoded, extnValueFrom, out, offset, extnValueLength);
        return extnValueLength;
    }

}
