/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.security.api.p11.remote;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.xipki.security.api.BadASN1ObjectException;
import org.xipki.security.api.p11.P11KeyIdentifier;

/**
 *
 * <pre>
 * SlotIdentifier ::= CHOICE
 * {
 *     keyLabel   UTF8STRING,
 *     keyId      OCTET STRING
 * }
 * </pre>
 *
 * @author Lijun Liao
 */

public class KeyIdentifier extends ASN1Object {

    private P11KeyIdentifier keyId;

    public KeyIdentifier(
            final P11KeyIdentifier keyId) {
        if (keyId == null) {
            throw new IllegalArgumentException("keyId could not be null");
        }

        this.keyId = keyId;
    }

    public static KeyIdentifier getInstance(
            final Object obj)
    throws BadASN1ObjectException {
        if (obj == null || obj instanceof KeyIdentifier) {
            return (KeyIdentifier) obj;
        }

        try {
            if (obj instanceof ASN1OctetString) {
                byte[] keyIdBytes = ((ASN1OctetString) obj).getOctets();
                P11KeyIdentifier keyIdentifier = new P11KeyIdentifier(keyIdBytes);
                return new KeyIdentifier(keyIdentifier);
            } else if (obj instanceof ASN1String) {
                String keyLabel = ((ASN1String) obj).getString();
                P11KeyIdentifier keyIdentifier = new P11KeyIdentifier(keyLabel);
                return new KeyIdentifier(keyIdentifier);
            }

            if (obj instanceof byte[]) {
                return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
            }
        } catch (IllegalArgumentException | IOException e) {
            throw new BadASN1ObjectException("unable to parse encoded KeyIdentifier");
        }

        throw new BadASN1ObjectException("unknown object in KeyIdentifier.getInstance(): "
                + obj.getClass().getName());
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        if (keyId.getKeyLabel() != null) {
            return new DERUTF8String(keyId.getKeyLabel());
        } else {
            return new DEROctetString(keyId.getKeyId());
        }
    }

    public P11KeyIdentifier getKeyId() {
        return keyId;
    }

}
