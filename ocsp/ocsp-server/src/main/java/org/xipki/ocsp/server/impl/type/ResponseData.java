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
import java.util.List;

import org.bouncycastle.asn1.BERTags;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class ResponseData extends ASN1Type {

    private final int version;

    private final byte[] responderId;

    private final Date producedAt;

    private final List<SingleResponse> responses;

    private final byte[] extensions;

    private final int bodyLength;

    private final int encodedLength;

    public ResponseData(int version, byte[] responderId, Date producedAt,
            List<SingleResponse> responses, byte[] extensions) {
        if (version < 0 || version > 127) {
            throw new IllegalArgumentException("invalid version: " + version);
        }
        this.version = version;
        this.responderId = responderId;
        this.producedAt = producedAt;
        this.responses = responses;
        this.extensions = extensions;

        int len = 0;
        if (version != 0) {
            len += 5;
        }
        len += responderId.length;

        // producedAt
        len += 17;

        // responses
        int responsesBodyLen = 0;
        for (SingleResponse sr : responses) {
            responsesBodyLen += sr.encodedLength();
        }
        len += getHeaderLen(responsesBodyLen) + responsesBodyLen;

        // extensions
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

        // version
        if (version != 0) {
            idx += writeHeader(BERTags.TAGGED | BERTags.CONSTRUCTED, 3, out, idx);
            idx += writeHeader(BERTags.INTEGER, 1, out, idx);
            out[idx++] = (byte) version;
        }

        idx += arraycopy(responderId, out, idx);
        idx += writeGeneralizedTime(producedAt, out, idx);

        // responses
        int responsesBodyLen = 0;
        for (SingleResponse sr : responses) {
            responsesBodyLen += sr.encodedLength();
        }
        idx += writeHeader(BERTags.SEQUENCE | BERTags.CONSTRUCTED, responsesBodyLen, out, idx);
        for (SingleResponse sr : responses) {
            idx += sr.write(out, idx);
        }

        if (extensions != null) {
            idx += writeHeader(BERTags.TAGGED | BERTags.CONSTRUCTED | 1,
                    extensions.length, out, idx);
            idx += arraycopy(extensions, out, idx);
        }

        return idx - offset;
    }

}
