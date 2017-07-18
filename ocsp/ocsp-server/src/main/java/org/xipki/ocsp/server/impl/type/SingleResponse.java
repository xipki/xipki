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

import java.util.Date;

import org.bouncycastle.asn1.BERTags;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class SingleResponse extends ASN1Type {

    private final CertID certId;

    private final byte[] certStatus;

    private final Date thisUpdate;

    private final Date nextUpdate;

    private final byte[] extensions;

    private final int bodyLength;

    private final int encodedLength;

    public SingleResponse(CertID certId, byte[] certStatus, Date thisUpdate, Date nextUpdate,
            byte[] extensions) {
        this.certId = certId;
        this.certStatus = certStatus;
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
        this.extensions = extensions;

        int len = certId.encodedLength();
        len += certStatus.length;
        len += 17; // thisUpdate
        if (nextUpdate != null) {
            len += 2; // explicit tag
            len += 17;
        }

        if (extensions != null) {
            len += getHeaderLen(extensions.length); // explicit tag
            len += extensions.length;
        }

        this.bodyLength = len;
        this.encodedLength = getHeaderLen(bodyLength) + bodyLength;
    }

    @Override
    public int encodedLength() {
        return encodedLength;
    }

    @Override
    public int write(final byte[] out, final int offset) {
        int idx = offset;
        idx += writeHeader(BERTags.SEQUENCE | BERTags.CONSTRUCTED, bodyLength, out, idx);
        idx += certId.write(out, idx);
        idx += arraycopy(certStatus, out, idx);
        idx += writeGeneralizedTime(thisUpdate, out, idx);
        if (nextUpdate != null) {
            idx += writeHeader(BERTags.TAGGED | BERTags.CONSTRUCTED | 0,
                    17, out, idx);
            idx += writeGeneralizedTime(nextUpdate, out, idx);
        }

        if (extensions != null) {
            idx += writeHeader(BERTags.TAGGED | BERTags.CONSTRUCTED | 1,
                    extensions.length, out, idx);
            idx += arraycopy(extensions, out, idx);
        }
        return idx - offset;
    }

}
