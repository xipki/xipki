/*
 * Copyright (c) 2015 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
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
            return (IssuerAndSubject)obj;
        }
        else if (obj != null)
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
