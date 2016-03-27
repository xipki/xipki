/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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

package org.xipki.commons.pkcs11proxy.common;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.commons.security.api.BadAsn1ObjectException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Asn1Util {

    private Asn1Util() {
    }

    public static void requireRange(
            final ASN1Sequence seq,
            final int minSize,
            final int maxSize)
    throws BadAsn1ObjectException {
        int size = seq.size();
        if (size < minSize || size > maxSize) {
            String msg = String.format("seq.size() must not be out of the range [%d, %d]: %d",
                    minSize, maxSize, size);
            throw new IllegalArgumentException(msg);
        }
    }

    public static ASN1Sequence getSequence(
            final ASN1Encodable object)
    throws BadAsn1ObjectException {
        try {
            return ASN1Sequence.getInstance(object);
        } catch (IllegalArgumentException ex) {
            throw new BadAsn1ObjectException(
                    "invalid object Sequence: " + ex.getMessage(), ex);
        }
    }

    public static Certificate getCertificate(
            final ASN1Encodable object)
    throws BadAsn1ObjectException {
        try {
            return Certificate.getInstance(object);
        } catch (IllegalArgumentException ex) {
            throw new BadAsn1ObjectException(
                    "invalid object Certificate: " + ex.getMessage(), ex);
        }
    }

    public static BigInteger getInteger(
            final ASN1Encodable object)
    throws BadAsn1ObjectException {
        try {
            return ASN1Integer.getInstance(object).getValue();
        } catch (IllegalArgumentException ex) {
            throw new BadAsn1ObjectException(
                    "invalid object ASN1Integer: " + ex.getMessage(), ex);
        }
    }

    public static String getUtf8String(
            final ASN1Encodable object)
    throws BadAsn1ObjectException {
        try {
            return DERUTF8String.getInstance(object).getString();
        } catch (IllegalArgumentException ex) {
            throw new BadAsn1ObjectException(
                    "invalid object UTF8String: " + ex.getMessage(), ex);
        }
    }

    public static byte[] getOctetStringBytes(
            final ASN1Encodable object)
    throws BadAsn1ObjectException {
        try {
            return DEROctetString.getInstance(object).getOctets();
        } catch (IllegalArgumentException ex) {
            throw new BadAsn1ObjectException(
                    "invalid object OctetString: " + ex.getMessage(), ex);
        }
    }

    public static ASN1ObjectIdentifier getObjectIdentifier(
            final ASN1Encodable object)
    throws BadAsn1ObjectException {
        try {
            return ASN1ObjectIdentifier.getInstance(object);
        } catch (IllegalArgumentException ex) {
            throw new BadAsn1ObjectException(
                    "invalid object ObjectIdentifier: " + ex.getMessage(), ex);
        }
    }

}
