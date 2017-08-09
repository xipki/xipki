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
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;
import org.xipki.common.ASN1Type;
import org.xipki.ocsp.server.impl.type.ExtendedExtension;
import org.xipki.ocsp.server.impl.type.Extension;
import org.xipki.ocsp.server.impl.type.OID;
import org.xipki.ocsp.server.impl.type.WritableOnlyExtension;
import org.xipki.security.CrlReason;
import org.xipki.security.HashAlgoType;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

class Template {

    private static final Map<HashAlgoType, byte[]> extnCerthashPrefixMap = new HashMap<>();

    private static final byte[] extnInvalidityDate;

    private static final byte[] extnArchiveCutof;

    private static final byte[] revokedInfoNoReasonPrefix = new byte[]{(byte) 0xA1, 0x11};

    private static final byte[] revokedInfoWithReasonPrefix = new byte[]{(byte) 0xA1, 0x16};

    private static final byte[] reasonPrefix = new byte[]{(byte) 0xa0, 0x03, 0x0a, 0x01};

    static {
        // CertHash
        for (HashAlgoType h : HashAlgoType.values()) {
            int hlen = h.length();

            AlgorithmIdentifier algId = new AlgorithmIdentifier(h.oid(), DERNull.INSTANCE);
            byte[] encoded;
            try {
                encoded = new CertHash(algId, new byte[hlen]).getEncoded();
            } catch (IOException ex) {
                throw new ExceptionInInitializerError("could not processing encoding of CertHash");
            }
            byte[] prefix = Arrays.copyOf(encoded, encoded.length - hlen);
            extnCerthashPrefixMap.put(h, prefix);
        }

        Extension extension = new ExtendedExtension(OID.ID_INVALIDITY_DATE, false,
                new byte[17]);
        extnInvalidityDate = new byte[extension.encodedLength()];
        extension.write(extnInvalidityDate, 0);

        extension = new ExtendedExtension(OID.ID_PKIX_OCSP_ARCHIVE_CUTOFF, false,
                new byte[17]);
        extnArchiveCutof = new byte[extension.encodedLength()];
        extension.write(extnArchiveCutof, 0);
    }

    public static WritableOnlyExtension getCertHashExtension(HashAlgoType hashAlgo,
            byte[] certHash) {
        if (hashAlgo.length() != certHash.length) {
            throw new IllegalArgumentException("hashAlgo and certHash do not match");
        }
        byte[] encodedPrefix = extnCerthashPrefixMap.get(hashAlgo);
        byte[] rv = new byte[encodedPrefix.length + certHash.length];
        System.arraycopy(encodedPrefix, 0, rv, 0, encodedPrefix.length);
        System.arraycopy(certHash, 0, rv, encodedPrefix.length, certHash.length);

        return new WritableOnlyExtension(rv);
    }

    public static WritableOnlyExtension getInvalidityDateExtension(Date invalidityDate) {
        int len = extnInvalidityDate.length;
        byte[] encoded = new byte[len];
        System.arraycopy(extnInvalidityDate, 0, encoded, 0, len - 17);
        ASN1Type.writeGeneralizedTime(invalidityDate, encoded, len - 17);
        return new WritableOnlyExtension(encoded);
    }

    public static WritableOnlyExtension getArchiveOffExtension(Date archiveCutoff) {
        int len = extnArchiveCutof.length;
        byte[] encoded = new byte[len];
        System.arraycopy(extnArchiveCutof, 0, encoded, 0, len - 17);
        ASN1Type.writeGeneralizedTime(archiveCutoff, encoded, len - 17);
        return new WritableOnlyExtension(encoded);
    }

    public static byte[] getEncodeRevokedInfo(CrlReason reason, Date revocationTime) {
        if (reason == null) {
            byte[] encoded = new byte[19];
            System.arraycopy(revokedInfoNoReasonPrefix, 0, encoded, 0, 2);
            ASN1Type.writeGeneralizedTime(revocationTime, encoded, 2);
            return encoded;
        } else {
            byte[] encoded = new byte[24];
            System.arraycopy(revokedInfoWithReasonPrefix, 0, encoded, 0, 2);
            ASN1Type.writeGeneralizedTime(revocationTime, encoded, 2);
            System.arraycopy(reasonPrefix, 0, encoded, 19, 4);
            encoded[23] = (byte) reason.code();
            return encoded;
        }
    }

}
