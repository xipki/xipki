/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.api.profile;

import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.security.common.EnvironmentParameterResolver;

/**
 * @author Lijun Liao
 */

public abstract class CertProfile
{
    public boolean isOnlyForRA()
    {
        return false;
    }

    public abstract void initialize(String data)
    throws CertProfileException;

    public void shutdown()
    {
    }

    public SpecialCertProfileBehavior getSpecialCertProfileBehavior()
    {
        return null;
    }

    public abstract void setEnvironmentParameterResolver(EnvironmentParameterResolver parameterResolver);

    public abstract Date getNotBefore(Date notBefore);

    public abstract Integer getValidity();

    public abstract void checkPublicKey(SubjectPublicKeyInfo publicKey)
    throws BadCertTemplateException;

    public abstract SubjectInfo getSubject(X500Name requestedSubject)
    throws CertProfileException, BadCertTemplateException;

    public abstract ExtensionOccurrence getOccurenceOfAuthorityKeyIdentifier();

    /**
     * Whether include subject and serial number of the issuer certificate in the
     * AuthorityKeyIdentifier extension.
     * @return
     */
    public boolean includeIssuerAndSerialInAKI()
    {
        return false;
    }

    public abstract ExtensionOccurrence getOccurenceOfSubjectKeyIdentifier();

    public abstract ExtensionOccurrence getOccurenceOfCRLDistributinPoints();

    public ExtensionOccurrence getOccurenceOfFreshestCRL()
    {
        return ExtensionOccurrence.NONCRITICAL_OPTIONAL;
    }

    public ExtensionOccurrence getOccurenceOfIssuerAltName()
    {
        return ExtensionOccurrence.NONCRITICAL_OPTIONAL;
    }

    public abstract ExtensionOccurrence getOccurenceOfAuthorityInfoAccess();

    public abstract ExtensionTuples getExtensions(X500Name requestedSubject, Extensions requestedExtensions)
    throws CertProfileException, BadCertTemplateException;

    public abstract boolean incSerialNumberIfSubjectExists();

    public String incSerialNumber(String currentSerialNumber)
    throws BadFormatException
    {
        try
        {
            int currentSN = currentSerialNumber == null ? 0 : Integer.parseInt(currentSerialNumber.trim());
            return Integer.toString(currentSN + 1);
        }catch(NumberFormatException e)
        {
            throw new BadFormatException("invalid serialNumber attribute " + currentSerialNumber);
        }
    }
}
