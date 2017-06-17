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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.exception.BadAsn1ObjectException;

/**
 *
 * <pre>
 * DigestSecretKeyTemplate ::= SEQUENCE {
 *     entityId       EntityIdentifier,
 *     mechanism      Mechanism}
 * </pre>
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class Asn1DigestSecretKeyTemplate extends ASN1Object {

    private final Asn1P11EntityIdentifier identityId;

    private final Asn1Mechanism mechanism;

    private Asn1DigestSecretKeyTemplate(final ASN1Sequence seq) throws BadAsn1ObjectException {
        Asn1Util.requireRange(seq, 2, 2);
        int idx = 0;
        this.identityId = Asn1P11EntityIdentifier.getInstance(seq.getObjectAt(idx++));
        this.mechanism = Asn1Mechanism.getInstance(seq.getObjectAt(idx++));
    }

    public Asn1DigestSecretKeyTemplate(final Asn1P11EntityIdentifier identityId,
            final long mechanism) {
        this.identityId = ParamUtil.requireNonNull("identityId", identityId);
        this.mechanism = new Asn1Mechanism(mechanism, null);
    }

    public static Asn1DigestSecretKeyTemplate getInstance(final Object obj)
            throws BadAsn1ObjectException {
        if (obj == null || obj instanceof Asn1DigestSecretKeyTemplate) {
            return (Asn1DigestSecretKeyTemplate) obj;
        }

        try {
            if (obj instanceof ASN1Sequence) {
                return new Asn1DigestSecretKeyTemplate((ASN1Sequence) obj);
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

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(identityId);
        vector.add(mechanism);
        return new DERSequence(vector);
    }

    public Asn1P11EntityIdentifier identityId() {
        return identityId;
    }

    public Asn1Mechanism mechanism() {
        return mechanism;
    }
}
