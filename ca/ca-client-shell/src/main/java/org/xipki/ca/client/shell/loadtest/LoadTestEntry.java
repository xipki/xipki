/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.client.shell.loadtest;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.common.SecurityUtil;
import org.xipki.common.ObjectIdentifiers;
import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class LoadTestEntry
{
    public static enum RandomDN
    {
        GIVENNAME,
        SURNAME,
        STREET,
        POSTALCODE,
        O,
        OU,
        CN;

        static RandomDN getInstance(String text)
        {
            ParamChecker.assertNotNull("text", text);
            for(RandomDN value : values())
            {
                if(value.name().equalsIgnoreCase(text))
                {
                    return value;
                }
            }
            return null;
        }
    }

    private static class IncreasableSubject
    {
        private final X500Name subjectTemplate;
        private final ASN1ObjectIdentifier subjectRDNForIncrement;

        private IncreasableSubject(String subjectTemplate, RandomDN randomDN)
        {
            this.subjectTemplate = SecurityUtil.sortX509Name(new X500Name(subjectTemplate));

            switch(randomDN)
            {
                case GIVENNAME:
                    this.subjectRDNForIncrement = ObjectIdentifiers.DN_GIVENNAME;
                    break;
                case SURNAME:
                    this.subjectRDNForIncrement = ObjectIdentifiers.DN_SURNAME;
                    break;
                case STREET:
                    this.subjectRDNForIncrement = ObjectIdentifiers.DN_STREET;
                    break;
                case POSTALCODE:
                    this.subjectRDNForIncrement = ObjectIdentifiers.DN_POSTAL_CODE;
                    break;
                case O:
                    this.subjectRDNForIncrement = ObjectIdentifiers.DN_O;
                    break;
                case OU:
                    this.subjectRDNForIncrement = ObjectIdentifiers.DN_OU;
                    break;
                case CN:
                    this.subjectRDNForIncrement = ObjectIdentifiers.DN_CN;
                    break;
                default:
                    throw new RuntimeException("should not reach here");
            }

            if(this.subjectRDNForIncrement != null &&
                    this.subjectTemplate.getRDNs(this.subjectRDNForIncrement).length == 0)
            {
                throw new IllegalArgumentException("subjectTemplate does not contain DN field " +
                        ObjectIdentifiers.oidToDisplayName(this.subjectRDNForIncrement));
            }
        }

        private X500Name getX500Name(long index)
        {
            RDN[] baseRDNs = subjectTemplate.getRDNs();

            final int n = baseRDNs.length;
            RDN[] newRDNS = new RDN[n];

            boolean incremented = false;
            for(int i = 0; i < n; i++)
            {
                RDN rdn = baseRDNs[i];
                if(incremented == false)
                {
                    if(rdn.getFirst().getType().equals(subjectRDNForIncrement))
                    {
                        String text = IETFUtils.valueToString(rdn.getFirst().getValue());
                        rdn = new RDN(subjectRDNForIncrement, new DERUTF8String(text + index));
                        incremented = true;
                    }
                }

                newRDNS[i] = rdn;
            }
            return new X500Name(newRDNS);
        }
    }

    private final String certProfile;
    private final KeyEntry keyEntry;
    private final IncreasableSubject subject;

    public LoadTestEntry(String certProfile, KeyEntry keyEntry, String subjectTemplate, RandomDN randomDN)
    {
        ParamChecker.assertNotEmpty("certProfile", certProfile);
        ParamChecker.assertNotNull("keyEntry", keyEntry);
        ParamChecker.assertNotNull("subjectTemplate", subjectTemplate);
        ParamChecker.assertNotNull("randomDN", randomDN);

        this.certProfile = certProfile;
        this.keyEntry = keyEntry;
        this.subject = new IncreasableSubject(subjectTemplate, randomDN);
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo(long index)
    {
        return keyEntry.getSubjectPublicKeyInfo(index);
    }

    public X500Name getX500Name(long index)
    {
        return subject.getX500Name(index);
    }

    public String getCertProfile()
    {
        return certProfile;
    }

}
