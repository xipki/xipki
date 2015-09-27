/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

package org.xipki.scep4j.message;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * @author Lijun Liao
 */

public class IssuerAndSubject
    extends ASN1Object
{
    private X500Name issuer;
    private X500Name subject;

    public static IssuerAndSubject getInstance(
            final Object obj)
    {
        if (obj instanceof IssuerAndSubject)
        {
            return (IssuerAndSubject) obj;
        } else if (obj != null)
        {
            return new IssuerAndSubject(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private IssuerAndSubject(
            final ASN1Sequence seq)
    {
        this.issuer = X500Name.getInstance(seq.getObjectAt(0));
        this.subject = X500Name.getInstance(seq.getObjectAt(1));
    }

    public IssuerAndSubject(
            final X500Name issuer,
            final X500Name subject)
    {
        this.issuer = issuer;
        this.subject = subject;
    }

    public X500Name getIssuer()
    {
        return issuer;
    }

    public X500Name getSubject()
    {
        return subject;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector    v = new ASN1EncodableVector();

        v.add(issuer);
        v.add(subject);

        return new DERSequence(v);
    }
}
