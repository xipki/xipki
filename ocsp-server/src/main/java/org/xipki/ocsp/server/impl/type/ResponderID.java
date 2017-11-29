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

import java.io.IOException;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.common.ASN1Type;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class ResponderID extends ASN1Type {

    private final byte[] encoded;

    private final int encodedLength;

    public ResponderID(byte[] key) throws IOException {
        this.encoded = new org.bouncycastle.asn1.ocsp.ResponderID(
                new DEROctetString(key)).getEncoded();
        this.encodedLength = encoded.length;
    }

    public ResponderID(X500Name name) throws IOException {
        this.encoded = new org.bouncycastle.asn1.ocsp.ResponderID(name).getEncoded();
        this.encodedLength = encoded.length;
    }

    @Override
    public int encodedLength() {
        return encodedLength;
    }

    @Override
    public int write(byte[] out, int offset) {
        return arraycopy(encoded, out, offset);
    }

}
