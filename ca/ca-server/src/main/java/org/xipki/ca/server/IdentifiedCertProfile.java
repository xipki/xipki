/*
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.server;

import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.ca.api.profile.BadCertTemplateException;
import org.xipki.ca.api.profile.BadFormatException;
import org.xipki.ca.api.profile.CertProfile;
import org.xipki.ca.api.profile.CertProfileException;
import org.xipki.ca.api.profile.ExtensionOccurrence;
import org.xipki.ca.api.profile.ExtensionTuples;
import org.xipki.ca.api.profile.SubjectInfo;
import org.xipki.security.common.EnvironmentParameterResolver;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class IdentifiedCertProfile extends CertProfile
{
    private final String name;
    private final CertProfile certProfile;

    public IdentifiedCertProfile(String name, CertProfile certProfile)
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotNull("certProfile", certProfile);

        this.name = name;
        this.certProfile = certProfile;
    }

    public String getName()
    {
        return name;
    }

    @Override
    public void initialize(String data)
    throws CertProfileException
    {
        certProfile.initialize(data);
    }

    @Override
    public void setEnvironmentParameterResolver(EnvironmentParameterResolver parameterResolver)
    {
        certProfile.setEnvironmentParameterResolver(parameterResolver);
    }

    @Override
    public Date getNotBefore(Date notBefore)
    {
        return certProfile.getNotBefore(notBefore);
    }

    @Override
    public Integer getValidity()
    {
        return certProfile.getValidity();
    }

    @Override
    public SubjectInfo getSubject(X500Name requestedSubject)
    throws CertProfileException, BadCertTemplateException
    {
        return certProfile.getSubject(requestedSubject);
    }

    @Override
    public ExtensionTuples getExtensions(X500Name requestedSubject, Extensions requestedExtensions)
    throws CertProfileException, BadCertTemplateException
    {
        return certProfile.getExtensions(requestedSubject, requestedExtensions);
    }

    @Override
    public boolean isOnlyForRA()
    {
        return certProfile.isOnlyForRA();
    }

    @Override
    public ExtensionOccurrence getOccurenceOfAuthorityKeyIdentifier()
    {
        return certProfile.getOccurenceOfAuthorityKeyIdentifier();
    }

    @Override
    public ExtensionOccurrence getOccurenceOfSubjectKeyIdentifier()
    {
        return certProfile.getOccurenceOfSubjectKeyIdentifier();
    }

    @Override
    public ExtensionOccurrence getOccurenceOfCRLDistributinPoints()
    {
        return certProfile.getOccurenceOfCRLDistributinPoints();
    }

    @Override
    public ExtensionOccurrence getOccurenceOfAuthorityInfoAccess()
    {
        return certProfile.getOccurenceOfAuthorityInfoAccess();
    }

    @Override
    public void checkPublicKey(SubjectPublicKeyInfo publicKey)
    throws BadCertTemplateException
    {
        certProfile.checkPublicKey(publicKey);
    }

    @Override
    public boolean incSerialNumberIfSubjectExists()
    {
        return certProfile.incSerialNumberIfSubjectExists();
    }

    @Override
    public void shutdown()
    {
        certProfile.shutdown();
    }

    @Override
    public boolean includeIssuerAndSerialInAKI()
    {
        return certProfile.includeIssuerAndSerialInAKI();
    }

    @Override
    public String incSerialNumber(String currentSerialNumber)
    throws BadFormatException
    {
        return certProfile.incSerialNumber(currentSerialNumber);
    }

    @Override
    public ExtensionOccurrence getOccurenceOfFreshestCRL()
    {
        return certProfile.getOccurenceOfFreshestCRL();
    }

    @Override
    public ExtensionOccurrence getOccurenceOfIssuerAltName()
    {
        return certProfile.getOccurenceOfIssuerAltName();
    }

}
