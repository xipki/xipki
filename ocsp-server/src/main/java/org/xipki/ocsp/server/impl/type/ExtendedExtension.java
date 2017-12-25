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

package org.xipki.ocsp.server.impl.type;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.server.impl.type.OcspRequest.Header;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class ExtendedExtension extends Extension {

    private static final Logger LOG = LoggerFactory.getLogger(ExtendedExtension.class);

    private static final byte[] bytes_critical = Hex.decode("0101FF");

    private final OID extnType;

    private final byte[] encoded;

    private final int from;

    private final boolean critical;

    private final int encodedLength;

    private final int extnValueFrom;

    private final int extnValueLength;

    public ExtendedExtension(OID extnType, boolean critical, byte[] extnValue) {
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

    private ExtendedExtension(OID extnType, byte[] encoded, int from, boolean critical,
            int encodedLength, int extnValueFrom, int extnValueLength) {
        super();
        this.extnType = extnType;
        this.encoded = encoded;
        this.from = from;
        this.critical = critical;
        this.encodedLength = encodedLength;
        this.extnValueFrom = extnValueFrom;
        this.extnValueLength = extnValueLength;
    }

    public static ExtendedExtension getInstance(byte[] encoded, int from, int len)
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

        return new ExtendedExtension(extnType, encoded, from, critical, len,
                extnValueFrom, extnValueLength);
    }

    public static int getEncodedLength(OID extnType, boolean critical, int extnValueLength) {
        int bodyLen = extnType.encodedLength();
        if (critical) {
            bodyLen += 3;
        }
        bodyLen += getLen(extnValueLength);
        return getLen(bodyLen);
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
