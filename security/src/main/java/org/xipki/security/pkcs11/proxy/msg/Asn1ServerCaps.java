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

package org.xipki.security.pkcs11.proxy.msg;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.exception.BadAsn1ObjectException;

/**
 * <pre>
 * ServerCaps ::= SEQUENCE {
 *     readOnly      BOOLEAN,
 *     versions      SET OF ServerVersion }
 *
 * ServerVersion ::= INTEGER
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Asn1ServerCaps extends ASN1Object {

    private final Set<Short> versions;

    private final boolean readOnly;

    public Asn1ServerCaps(final boolean readOnly, final Set<Short> versions) {
        this.readOnly = readOnly;
        this.versions = Collections.unmodifiableSet(
                ParamUtil.requireNonEmpty("versions", versions));
    }

    private Asn1ServerCaps(final ASN1Sequence seq) throws BadAsn1ObjectException {
        Asn1Util.requireRange(seq, 2, 2);
        try {
            this.readOnly = ASN1Boolean.getInstance(seq.getObjectAt(0)).isTrue();
        } catch (IllegalArgumentException ex) {
            throw new BadAsn1ObjectException("invalid readOnly: " + ex.getMessage(), ex);
        }

        ASN1Sequence vecVersions;
        try {
            vecVersions = ASN1Sequence.getInstance(seq.getObjectAt(1));
        } catch (IllegalArgumentException ex) {
            throw new BadAsn1ObjectException("invalid versions: " + ex.getMessage(), ex);
        }

        int count = vecVersions.size();

        Set<Short> tmpVersions = new HashSet<>(count * 2);
        for (int i = 0; i < count; i++) {
            ASN1Integer asn1Int;
            try {
                asn1Int = ASN1Integer.getInstance(vecVersions.getObjectAt(i));
            } catch (IllegalArgumentException ex) {
                throw new BadAsn1ObjectException("invalid version: " + ex.getMessage(), ex);
            }
            tmpVersions.add(asn1Int.getValue().shortValue());
        }
        this.versions = Collections.unmodifiableSet(tmpVersions);
    }

    public static Asn1ServerCaps getInstance(final Object obj)
            throws BadAsn1ObjectException {
        if (obj == null || obj instanceof Asn1ServerCaps) {
            return (Asn1ServerCaps) obj;
        }

        try {
            if (obj instanceof ASN1Sequence) {
                return new Asn1ServerCaps((ASN1Sequence) obj);
            } else if (obj instanceof byte[]) {
                return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
            } else {
                throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
            }
        } catch (IOException | IllegalArgumentException ex) {
            throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(),
                    ex);
        }
    }

    public Set<Short> versions() {
        return versions;
    }

    public boolean isReadOnly() {
        return readOnly;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vecVersions = new ASN1EncodableVector();
        for (Short version : versions) {
            vecVersions.add(new ASN1Integer(BigInteger.valueOf(version)));
        }

        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(ASN1Boolean.getInstance(readOnly));
        vec.add(new DERSequence(vecVersions));
        return new DERSequence(vec);
    }
}
