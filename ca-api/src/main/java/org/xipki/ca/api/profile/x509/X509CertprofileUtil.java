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

package org.xipki.ca.api.profile.x509;

import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x509.GeneralName;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.profile.GeneralNameMode;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

public class X509CertprofileUtil {

    /**
     * Creates GeneralName.
     *
     * @param requestedName
     *          Requested name. Must not be {@code null}.
     * @param modes
     *          Modes to be considered. Must not be {@code null}.
     * @return the created GeneralName
     * @throws BadCertTemplateException
     *         If requestedName is invalid or contains entries which are not allowed in the modes.
     */
    public static GeneralName createGeneralName(final GeneralName requestedName,
            final Set<GeneralNameMode> modes) throws BadCertTemplateException {
        ParamUtil.requireNonNull("requestedName", requestedName);

        int tag = requestedName.getTagNo();
        GeneralNameMode mode = null;
        if (modes != null) {
            for (GeneralNameMode m : modes) {
                if (m.tag().tag() == tag) {
                    mode = m;
                    break;
                }
            }

            if (mode == null) {
                throw new BadCertTemplateException("generalName tag " + tag + " is not allowed");
            }
        }

        switch (tag) {
        case GeneralName.rfc822Name:
        case GeneralName.dNSName:
        case GeneralName.uniformResourceIdentifier:
        case GeneralName.iPAddress:
        case GeneralName.registeredID:
        case GeneralName.directoryName:
            return new GeneralName(tag, requestedName.getName());
        case GeneralName.otherName:
            ASN1Sequence reqSeq = ASN1Sequence.getInstance(requestedName.getName());
            int size = reqSeq.size();
            if (size != 2) {
                throw new BadCertTemplateException("invalid otherName sequence: size is not 2: "
                        + size);
            }

            ASN1ObjectIdentifier type = ASN1ObjectIdentifier.getInstance(reqSeq.getObjectAt(0));
            if (mode != null && !mode.allowedTypes().contains(type)) {
                throw new BadCertTemplateException(
                        "otherName.type " + type.getId() + " is not allowed");
            }

            ASN1Encodable asn1 = reqSeq.getObjectAt(1);
            if (! (asn1 instanceof ASN1TaggedObject)) {
                throw new BadCertTemplateException("otherName.value is not tagged Object");
            }

            int tagNo = ASN1TaggedObject.getInstance(asn1).getTagNo();
            if (tagNo != 0) {
                throw new BadCertTemplateException("otherName.value does not have tag 0: " + tagNo);
            }

            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(type);
            vector.add(new DERTaggedObject(true, 0,
                    ASN1TaggedObject.getInstance(asn1).getObject()));
            DERSequence seq = new DERSequence(vector);

            return new GeneralName(GeneralName.otherName, seq);
        case GeneralName.ediPartyName:
            reqSeq = ASN1Sequence.getInstance(requestedName.getName());

            size = reqSeq.size();
            String nameAssigner = null;
            int idx = 0;
            if (size > 1) {
                DirectoryString ds = DirectoryString.getInstance(
                        ASN1TaggedObject.getInstance(reqSeq.getObjectAt(idx++)).getObject());
                nameAssigner = ds.getString();
            }

            DirectoryString ds = DirectoryString.getInstance(
                    ASN1TaggedObject.getInstance(reqSeq.getObjectAt(idx++)).getObject());
            String partyName = ds.getString();

            vector = new ASN1EncodableVector();
            if (nameAssigner != null) {
                vector.add(new DERTaggedObject(false, 0, new DirectoryString(nameAssigner)));
            }
            vector.add(new DERTaggedObject(false, 1, new DirectoryString(partyName)));
            seq = new DERSequence(vector);
            return new GeneralName(GeneralName.ediPartyName, seq);
        default:
            throw new RuntimeException("should not reach here, unknown GeneralName tag " + tag);
        } // end switch (tag)
    } // method createGeneralName

}
