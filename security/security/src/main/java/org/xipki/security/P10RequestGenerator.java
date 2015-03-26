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

package org.xipki.security;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.xipki.common.CmpUtf8Pairs;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.SecurityUtil;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public class P10RequestGenerator
{

    public PKCS10CertificationRequest generateRequest(
            final SecurityFactory securityFactory,
            final String signerType,
            final String signerConf,
            final SubjectPublicKeyInfo subjectPublicKeyInfo,
            final String subject,
            List<Extension> extensions)
    throws PasswordResolverException, SignerException
    {
        X500Name subjectDN = new X500Name(subject);
        return generateRequest(securityFactory, signerType, signerConf, subjectPublicKeyInfo, subjectDN, extensions);
    }

    public PKCS10CertificationRequest generateRequest(
            final SecurityFactory securityFactory,
            final String signerType,
            final String signerConf,
            final SubjectPublicKeyInfo subjectPublicKeyInfo,
            final X500Name subjectDN,
            final List<Extension> extensions)
    throws PasswordResolverException, SignerException
    {
        ConcurrentContentSigner signer = securityFactory.createSigner(signerType, signerConf,
                (X509Certificate[]) null);
        ContentSigner contentSigner;
        try
        {
            contentSigner = signer.borrowContentSigner();
        } catch (NoIdleSignerException e)
        {
            throw new SignerException(e.getMessage(), e);
        }
        try
        {
            return generateRequest(contentSigner, subjectPublicKeyInfo, subjectDN, extensions);
        }finally
        {
            signer.returnContentSigner(contentSigner);
        }
    }

    public PKCS10CertificationRequest generateRequest(
            final ContentSigner contentSigner,
            final SubjectPublicKeyInfo subjectPublicKeyInfo,
            final X500Name subjectDN,
            final List<Extension> extensions)
    {
        PKCS10CertificationRequestBuilder p10ReqBuilder =
                new PKCS10CertificationRequestBuilder(subjectDN, subjectPublicKeyInfo);
        if(CollectionUtil.isNotEmpty(extensions))
        {
            Extensions _extensions = new Extensions(extensions.toArray(new Extension[0]));
            p10ReqBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, _extensions);
        }
        return p10ReqBuilder.build(contentSigner);
    }

    public static Extension createExtensionSubjectAltName(
            final List<String> taggedValues,
            final boolean critical)
    throws BadInputException
    {
        GeneralNames names = createGeneralNames(taggedValues);
        if(names == null)
        {
            return null;
        }

        try
        {
            return new Extension(Extension.subjectAlternativeName, critical, names.getEncoded());
        } catch (IOException e)
        {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public static GeneralNames createGeneralNames(
            final List<String> taggedValues)
    throws BadInputException
    {
        if(CollectionUtil.isEmpty(taggedValues))
        {
            return null;
        }

        int n = taggedValues.size();
        GeneralName[] names = new GeneralName[n];
        for(int i = 0; i < n; i++)
        {
            names[i] = createGeneralName(taggedValues.get(i));
        }
        return new GeneralNames(names);
    }

    public static Extension createExtensionSubjectInfoAccess(
            final List<String> accessMethodAndLocations,
            final boolean critical)
    throws BadInputException
    {
        if(CollectionUtil.isEmpty(accessMethodAndLocations))
        {
            return null;
        }

        ASN1EncodableVector vector = new ASN1EncodableVector();
        for(String accessMethodAndLocation : accessMethodAndLocations)
        {
            vector.add(createAccessDescription(accessMethodAndLocation));
        }
        ASN1Sequence seq = new DERSequence(vector);
        try
        {
            return new Extension(Extension.subjectInfoAccess, critical, seq.getEncoded());
        } catch (IOException e)
        {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public static AccessDescription createAccessDescription(
            final String accessMethodAndLocation)
    throws BadInputException
    {
        CmpUtf8Pairs pairs;
        try
        {
            pairs = new CmpUtf8Pairs(accessMethodAndLocation);
        }catch(IllegalArgumentException e)
        {
            throw new BadInputException("invalid accessMethodAndLocation " + accessMethodAndLocation);
        }

        Set<String> oids = pairs.getNames();
        if(oids == null || oids.size() != 1)
        {
            throw new BadInputException("invalid accessMethodAndLocation " + accessMethodAndLocation);
        }

        String accessMethodS = oids.iterator().next();
        String taggedValue = pairs.getValue(accessMethodS);
        ASN1ObjectIdentifier accessMethod = new ASN1ObjectIdentifier(accessMethodS);

        GeneralName location = createGeneralName(taggedValue);
        return new AccessDescription(accessMethod, location);
    }

    /**
     *
     * @param taggedValue [tag]value, and the value for tags otherName and ediPartyName is type=value.
     * @param modes
     * @return
     * @throws BadInputException
     */
    public static GeneralName createGeneralName(
            final String taggedValue)
    throws BadInputException
    {
        int tag = -1;
        String value = null;
        if(taggedValue.charAt(0) == '[')
        {
            int idx = taggedValue.indexOf(']', 1);
            if(idx > 1 && idx < taggedValue.length() - 1)
            {
                String tagS = taggedValue.substring(1, idx);
                try
                {
                    tag = Integer.parseInt(tagS);
                    value = taggedValue.substring(idx + 1);
                }catch(NumberFormatException e)
                {
                }
            }
        }

        if(tag == -1)
        {
            throw new BadInputException("invalid taggedValue " + taggedValue);
        }

        switch(tag)
        {
        case GeneralName.otherName:
        {
            int idxSep = value.indexOf("=");
            if(idxSep == -1 || idxSep == 0 || idxSep == value.length() - 1)
            {
                throw new BadInputException("invalid otherName " + value);
            }
            String otherTypeOid = value.substring(0, idxSep);
            ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(otherTypeOid);
            String otherValue = value.substring(idxSep + 1);
            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(type);
            vector.add(new DERTaggedObject(true, 0, new DERUTF8String(otherValue)));
            DERSequence seq = new DERSequence(vector);
            return new GeneralName(GeneralName.otherName, seq);
        }
        case GeneralName.rfc822Name:
            return new GeneralName(tag, value);
        case GeneralName.dNSName:
            return new GeneralName(tag, value);
        case GeneralName.directoryName:
        {
            X500Name x500Name = SecurityUtil.reverse(new X500Name(value));
            return new GeneralName(GeneralName.directoryName, x500Name);
        }
        case GeneralName.ediPartyName:
        {
            int idxSep = value.indexOf("=");
            if(idxSep == -1 || idxSep == value.length() - 1)
            {
                throw new BadInputException("invalid ediPartyName " + value);
            }
            String nameAssigner = idxSep == 0 ? null : value.substring(0, idxSep);
            String partyName = value.substring(idxSep + 1);
            ASN1EncodableVector vector = new ASN1EncodableVector();
            if(nameAssigner != null)
            {
                vector.add(new DERTaggedObject(false, 0, new DirectoryString(nameAssigner)));
            }
            vector.add(new DERTaggedObject(false, 1, new DirectoryString(partyName)));
            ASN1Sequence seq = new DERSequence(vector);
            return new GeneralName(GeneralName.ediPartyName, seq);
        }
        case GeneralName.uniformResourceIdentifier:
            return new GeneralName(tag, value);
        case GeneralName.iPAddress:
            return new GeneralName(tag, value);
        case GeneralName.registeredID:
            return new GeneralName(tag, value);
        default:
            throw new RuntimeException("unsupported tag " + tag);
        } // end switch(tag)
    }

}
