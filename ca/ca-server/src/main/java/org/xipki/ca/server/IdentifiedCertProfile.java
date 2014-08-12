/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
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
import org.xipki.ca.api.profile.SpecialCertProfileBehavior;
import org.xipki.ca.api.profile.SubjectInfo;
import org.xipki.security.common.EnvironmentParameterResolver;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class IdentifiedCertProfile
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

    public void initialize(String data)
    throws CertProfileException
    {
        certProfile.initialize(data);
    }

    public SpecialCertProfileBehavior getSpecialCertProfileBehavior()
    {
        return certProfile.getSpecialCertProfileBehavior();
    }

    public void setEnvironmentParameterResolver(EnvironmentParameterResolver parameterResolver)
    {
        certProfile.setEnvironmentParameterResolver(parameterResolver);
    }

    public Date getNotBefore(Date notBefore)
    {
        return certProfile.getNotBefore(notBefore);
    }

    public Integer getValidity()
    {
        return certProfile.getValidity();
    }

    public SubjectInfo getSubject(X500Name requestedSubject)
    throws CertProfileException, BadCertTemplateException
    {
        return certProfile.getSubject(requestedSubject);
    }

    public ExtensionTuples getExtensions(X500Name requestedSubject, Extensions requestedExtensions)
    throws CertProfileException, BadCertTemplateException
    {
        return certProfile.getExtensions(requestedSubject, requestedExtensions);
    }

    public boolean isOnlyForRA()
    {
        return certProfile.isOnlyForRA();
    }

    public ExtensionOccurrence getOccurenceOfAuthorityKeyIdentifier()
    {
        return certProfile.getOccurenceOfAuthorityKeyIdentifier();
    }

    public ExtensionOccurrence getOccurenceOfSubjectKeyIdentifier()
    {
        return certProfile.getOccurenceOfSubjectKeyIdentifier();
    }

    public ExtensionOccurrence getOccurenceOfCRLDistributinPoints()
    {
        return certProfile.getOccurenceOfCRLDistributinPoints();
    }

    public ExtensionOccurrence getOccurenceOfAuthorityInfoAccess()
    {
        return certProfile.getOccurenceOfAuthorityInfoAccess();
    }

    public void checkPublicKey(SubjectPublicKeyInfo publicKey)
    throws BadCertTemplateException
    {
        certProfile.checkPublicKey(publicKey);
    }

    public boolean incSerialNumberIfSubjectExists()
    {
        return certProfile.incSerialNumberIfSubjectExists();
    }

    public void shutdown()
    {
        certProfile.shutdown();
    }

    public boolean includeIssuerAndSerialInAKI()
    {
        return certProfile.includeIssuerAndSerialInAKI();
    }

    public String incSerialNumber(String currentSerialNumber)
    throws BadFormatException
    {
        return certProfile.incSerialNumber(currentSerialNumber);
    }

    public ExtensionOccurrence getOccurenceOfFreshestCRL()
    {
        return certProfile.getOccurenceOfFreshestCRL();
    }

    public ExtensionOccurrence getOccurenceOfIssuerAltName()
    {
        return certProfile.getOccurenceOfIssuerAltName();
    }

    public boolean isDuplicateKeyPermitted()
    {
        return certProfile.isDuplicateKeyPermitted();
    }

    public boolean isDuplicateSubjectPermitted()
    {
        return certProfile.isDuplicateSubjectPermitted();
    }

    public boolean isSerialNumberInReqPermitted()
    {
        return certProfile.isSerialNumberInReqPermitted();
    }

    public  String getParameter(String paramName)
    {
        return certProfile.getParameter(paramName);
    }

}
