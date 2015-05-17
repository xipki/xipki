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

package org.xipki.ca.certprofile;

import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.xipki.ca.certprofile.x509.jaxb.BiometricInfo;
import org.xipki.ca.certprofile.x509.jaxb.BiometricTypeType;
import org.xipki.ca.certprofile.x509.jaxb.TripleState;
import org.xipki.common.ParamChecker;
import org.xipki.common.util.AlgorithmUtil;

/**
 * @author Lijun Liao
 */

public class BiometricInfoOption
{
    private final Set<Integer> predefinedTypes;
    private final Set<ASN1ObjectIdentifier> idTypes;
    private final Set<ASN1ObjectIdentifier> hashAlgorithms;
    private final TripleState sourceDataUriOccurrence;

    public BiometricInfoOption(
            final BiometricInfo jaxb)
    throws NoSuchAlgorithmException
    {
        ParamChecker.assertNotNull("jaxb", jaxb);
        this.sourceDataUriOccurrence = jaxb.getIncludeSourceDataUri();
        this.hashAlgorithms = XmlX509CertprofileUtil.toOIDSet(jaxb.getHashAlgorithm());

        for(ASN1ObjectIdentifier m : hashAlgorithms)
        {
            AlgorithmUtil.getHashOutputSizeInOctets(m);
        }

        this.predefinedTypes = new HashSet<>();
        this.idTypes = new HashSet<>();
        for(BiometricTypeType m : jaxb.getType())
        {
            if(m.getPredefined() != null)
            {
                predefinedTypes.add(m.getPredefined().getValue());
            }
            else if(m.getOid() != null)
            {
                idTypes.add(new ASN1ObjectIdentifier(m.getOid().getValue()));
            }
            else
            {
                throw new RuntimeException("should not reach here, invalid biometricType");
            }
        }
    }

    public boolean isTypePermitted(TypeOfBiometricData type)
    {
        if(type.isPredefined())
        {
            return predefinedTypes.contains(type.getPredefinedBiometricType());
        }
        else
        {
            return idTypes.contains(type.getBiometricDataOid());
        }
    }

    public boolean isHashAlgorithmPermitted(ASN1ObjectIdentifier hashAlgorithm)
    {
        return hashAlgorithms.contains(hashAlgorithm);
    }

    public TripleState getSourceDataUriOccurrence()
    {
        return sourceDataUriOccurrence;
    }

}
