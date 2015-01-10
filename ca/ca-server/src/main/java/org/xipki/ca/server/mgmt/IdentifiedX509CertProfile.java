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

package org.xipki.ca.server.mgmt;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.BadFormatException;
import org.xipki.ca.api.CertProfileException;
import org.xipki.ca.api.CertValidity;
import org.xipki.ca.api.EnvironmentParameterResolver;
import org.xipki.ca.api.profile.ExtensionOccurrence;
import org.xipki.ca.api.profile.ExtensionTuples;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.SubjectInfo;
import org.xipki.ca.api.profile.x509.ExtKeyUsageOccurrence;
import org.xipki.ca.api.profile.x509.KeyUsage;
import org.xipki.ca.api.profile.x509.KeyUsageOccurrence;
import org.xipki.ca.api.profile.x509.SpecialX509CertProfileBehavior;
import org.xipki.ca.api.profile.x509.X509CertProfile;
import org.xipki.ca.api.profile.x509.X509Util;
import org.xipki.ca.server.CrlSigner;
import org.xipki.ca.server.PublicCAInfo;
import org.xipki.ca.server.certprofile.x509.DefaultX509CertProfile;
import org.xipki.ca.server.mgmt.api.CertProfileEntry;
import org.xipki.common.ObjectIdentifiers;
import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class IdentifiedX509CertProfile
{
    private static final Set<ASN1ObjectIdentifier> criticalOnlyExtensionTypes;
    private static final Set<ASN1ObjectIdentifier> noncriticalOnlyExtensionTypes;
    private static final Set<ASN1ObjectIdentifier> caOnlyExtensionTypes;

    static
    {
        criticalOnlyExtensionTypes = new HashSet<>();
        criticalOnlyExtensionTypes.add(Extension.basicConstraints);
        criticalOnlyExtensionTypes.add(Extension.keyUsage);
        criticalOnlyExtensionTypes.add(Extension.policyMappings);
        criticalOnlyExtensionTypes.add(Extension.nameConstraints);
        criticalOnlyExtensionTypes.add(Extension.policyConstraints);
        criticalOnlyExtensionTypes.add(Extension.inhibitAnyPolicy);

        noncriticalOnlyExtensionTypes = new HashSet<>();
        noncriticalOnlyExtensionTypes.add(Extension.authorityKeyIdentifier);
        noncriticalOnlyExtensionTypes.add(Extension.subjectKeyIdentifier);
        noncriticalOnlyExtensionTypes.add(Extension.issuerAlternativeName);
        noncriticalOnlyExtensionTypes.add(Extension.subjectDirectoryAttributes);
        noncriticalOnlyExtensionTypes.add(Extension.freshestCRL);
        noncriticalOnlyExtensionTypes.add(Extension.authorityInfoAccess);
        noncriticalOnlyExtensionTypes.add(Extension.subjectInfoAccess);

        caOnlyExtensionTypes = new HashSet<>();
        caOnlyExtensionTypes.add(Extension.policyMappings);
        caOnlyExtensionTypes.add(Extension.nameConstraints);
        caOnlyExtensionTypes.add(Extension.policyConstraints);
        caOnlyExtensionTypes.add(Extension.inhibitAnyPolicy);
    }

    private final CertProfileEntry entry;
    private final X509CertProfile certProfile;
    private EnvironmentParameterResolver parameterResolver;

    public IdentifiedX509CertProfile(CertProfileEntry entry, String realType)
    throws CertProfileException
    {
        ParamChecker.assertNotNull("entry", entry);
        this.entry = entry;
        X509CertProfile tmpCertProfile = null;

        final String type = realType == null ?  entry.getType() : realType;
        String className;
        if(type.equalsIgnoreCase("xml"))
        {
            tmpCertProfile = new DefaultX509CertProfile();
        }
        else if(type.toLowerCase().startsWith("java:"))
        {
            className = type.substring("java:".length());
            try
            {
                Class<?> clazz = Class.forName(className);
                tmpCertProfile = (X509CertProfile) clazz.newInstance();
            }catch(ClassNotFoundException | InstantiationException  | IllegalAccessException | ClassCastException e)
            {
                throw new CertProfileException("invalid type " + type + ", " + e.getClass().getName() +
                        ": " + e.getMessage());
            }
        }
        else
        {
            throw new CertProfileException("invalid type " + type);
        }

        tmpCertProfile.initialize(entry.getConf());

        if(parameterResolver != null)
        {
            tmpCertProfile.setEnvironmentParameterResolver(parameterResolver);
        }

        if(tmpCertProfile.getSpecialCertProfileBehavior() == SpecialX509CertProfileBehavior.gematik_gSMC_K)
        {
            String paramName = SpecialX509CertProfileBehavior.PARAMETER_MAXLIFTIME;
            String s = tmpCertProfile.getParameter(paramName);
            if(s == null)
            {
                throw new CertProfileException("parameter " + paramName + " is not defined");
            }

            s = s.trim();
            int i;
            try
            {
                i = Integer.parseInt(s);
            }catch(NumberFormatException e)
            {
                throw new CertProfileException("invalid " + paramName + ": " + s);
            }
            if(i < 1)
            {
                throw new CertProfileException("invalid " + paramName + ": " + s);
            }
        }

        this.certProfile = tmpCertProfile;
    }

    public String getName()
    {
        return entry.getName();
    }

    public CertProfileEntry getEntry()
    {
        return entry;
    }

    public SpecialX509CertProfileBehavior getSpecialCertProfileBehavior()
    {
        return certProfile.getSpecialCertProfileBehavior();
    }

    public void setEnvironmentParameterResolver(EnvironmentParameterResolver parameterResolver)
    {
        this.parameterResolver = parameterResolver;
        if(certProfile != null)
        {
            certProfile.setEnvironmentParameterResolver(parameterResolver);
        }
    }

    public Date getNotBefore(Date notBefore)
    {
        return certProfile.getNotBefore(notBefore);
    }

    public CertValidity getValidity()
    {
        return certProfile.getValidity();
    }

    public boolean hasMidnightNotBefore()
    {
        return certProfile.hasMidnightNotBefore();
    }

    public TimeZone getTimezone()
    {
        return certProfile.getTimezone();
    }

    public SubjectInfo getSubject(X500Name requestedSubject)
    throws CertProfileException, BadCertTemplateException
    {
        return certProfile.getSubject(requestedSubject);
    }

    public ExtensionTuples getExtensions(
            X500Name requestedSubject, Extensions requestedExtensions,
            SubjectPublicKeyInfo publicKeyInfo,
            PublicCAInfo publicCaInfo, CrlSigner crlSigner)
    throws CertProfileException, BadCertTemplateException
    {
        ExtensionTuples tuples = new ExtensionTuples();
        Set<ASN1ObjectIdentifier> allowedRequestExtensions = certProfile.getAllowedRequestExtensions();

        Set<ASN1ObjectIdentifier> consideredExtensionTypes = new HashSet<>();

        // SubjectKeyIdentifier
        MessageDigest sha1;
        try
        {
            sha1 = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e)
        {
            throw new CertProfileException(e.getMessage(), e);
        }
        byte[] skiValue = sha1.digest(publicKeyInfo.getPublicKeyData().getBytes());

        Map<ASN1ObjectIdentifier, ExtensionOccurrence> occurrences = new HashMap<>(certProfile.getExtensionOccurences());
        ASN1ObjectIdentifier extType = Extension.subjectKeyIdentifier;
        ExtensionOccurrence extOccurrence = occurrences.remove(extType);
        if(extOccurrence != null)
        {
            consideredExtensionTypes.add(extType);
            SubjectKeyIdentifier value = new SubjectKeyIdentifier(skiValue);
            tuples.addExtension(extType, extOccurrence.isCritical(), value);
        }

        // Authority key identifier
        extType = Extension.authorityKeyIdentifier;
        extOccurrence = occurrences.remove(extType);
        if(extOccurrence != null)
        {
            byte[] ikiValue = publicCaInfo.getSubjectKeyIdentifer();
            AuthorityKeyIdentifier value = null;
            if(ikiValue != null)
            {
                consideredExtensionTypes.add(extType);
                if(certProfile.includeIssuerAndSerialInAKI())
                {
                    GeneralNames x509CaSubject = new GeneralNames(new GeneralName(publicCaInfo.getX500Subject()));
                    value = new AuthorityKeyIdentifier(ikiValue, x509CaSubject, publicCaInfo.getSerialNumber());
                }
                else
                {
                    value = new AuthorityKeyIdentifier(ikiValue);
                }
            }

            if(value == null)
            {
                if(extOccurrence.isRequired())
                {
                    throw new CertProfileException("Could not add required extension authorityKeyIdentifier");
                }
            } else
            {
                tuples.addExtension(extType, extOccurrence.isCritical(), value);
            }
        }

        // IssuerAltName
        extType = Extension.issuerAlternativeName;
        extOccurrence = occurrences.remove(extType);
        if(extOccurrence != null)
        {
            consideredExtensionTypes.add(extType);
            if(publicCaInfo.getSubjectAltName() != null)
            {
                tuples.addExtension(extType, extOccurrence.isCritical(), publicCaInfo.getSubjectAltName());
            }
        }

        // AuthorityInfoAccess
        extType = Extension.authorityInfoAccess;
        extOccurrence = occurrences.remove(extType);
        if(extOccurrence != null)
        {
            consideredExtensionTypes.add(extType);
            AuthorityInformationAccess value = X509Util.createAuthorityInformationAccess(publicCaInfo.getOcspUris());
            if(value == null)
            {
                if(extOccurrence.isRequired())
                {
                    throw new CertProfileException("Could not add required extension authorityInfoAccess");
                }
            }
            else
            {
                tuples.addExtension(extType, extOccurrence.isCritical(), value);
            }
        }

        if(occurrences.containsKey(Extension.cRLDistributionPoints) || occurrences.containsKey(Extension.freshestCRL))
        {
            X500Principal crlSignerSubject = null;
            if(crlSigner != null && crlSigner.getSigner() != null)
            {
                X509Certificate crlSignerCert =  crlSigner.getSigner().getCertificate();
                if(crlSignerCert != null)
                {
                    crlSignerSubject = crlSignerCert.getSubjectX500Principal();
                }
            }

            X500Principal x500CaPrincipal = publicCaInfo.getSubject();

            // CRLDistributionPoints
            extType = Extension.cRLDistributionPoints;
            extOccurrence = occurrences.remove(extType);
            if(extOccurrence != null)
            {
                consideredExtensionTypes.add(extType);
                CRLDistPoint value;
                try
                {
                    value = X509Util.createCRLDistributionPoints(publicCaInfo.getCrlUris(),
                            x500CaPrincipal, crlSignerSubject);
                } catch (IOException e)
                {
                    throw new CertProfileException(e.getMessage(), e);
                }

                if(value == null)
                {
                    if(extOccurrence.isRequired())
                    {
                        throw new CertProfileException("Could not add required extension CRLDistributionPoints");
                    }
                }
                else
                {
                    tuples.addExtension(extType, extOccurrence.isCritical(), value);
                }
            }

            // FreshestCRL
            extType = Extension.freshestCRL;
            extOccurrence = occurrences.remove(extType);
            if(extOccurrence != null)
            {
                consideredExtensionTypes.add(extType);
                CRLDistPoint value;
                try
                {
                    value = X509Util.createCRLDistributionPoints(publicCaInfo.getDeltaCrlUris(),
                            x500CaPrincipal, crlSignerSubject);
                } catch (IOException e)
                {
                    throw new CertProfileException(e.getMessage(), e);
                }
                if(value == null)
                {
                    if(extOccurrence.isRequired())
                    {
                        throw new CertProfileException("Could not add required extension freshestCRL");
                    }
                }
                else
                {
                    tuples.addExtension(extType, extOccurrence.isCritical(), value);
                }
            }
        }

        // BasicConstraints
        extType = Extension.basicConstraints;
        extOccurrence = occurrences.remove(extType);
        if(extOccurrence != null)
        {
            consideredExtensionTypes.add(extType);
            BasicConstraints value = X509Util.createBasicConstraints(certProfile.isCA(),
                    certProfile.getPathLenBasicConstraint());
            if(value == null)
            {
                if(extOccurrence.isRequired())
                {
                    throw new CertProfileException("Could not add required extension BasicConstraints");
                }
            }
            else
            {
                tuples.addExtension(extType, extOccurrence.isCritical(), value);
            }
        }

        // KeyUsage
        extType = Extension.keyUsage;
        extOccurrence = occurrences.remove(extType);
        if(extOccurrence != null)
        {
            consideredExtensionTypes.add(extType);
            Set<KeyUsage> usages = new HashSet<>();
            Set<KeyUsageOccurrence> usageOccs = certProfile.getKeyUsage();
            for(KeyUsageOccurrence k : usageOccs)
            {
                if(k.isRequired())
                {
                    usages.add(k.getKeyUsage());
                }
            }

            // the optional KeyUsage will only be set if requested explicitly
            if(requestedExtensions != null && allowedRequestExtensions.contains(extType))
            {
                Extension extension = requestedExtensions.getExtension(extType);
                if(extension != null)
                {
                    org.bouncycastle.asn1.x509.KeyUsage reqKeyUsage =
                            org.bouncycastle.asn1.x509.KeyUsage.getInstance(extension.getParsedValue());
                    for(KeyUsageOccurrence k : usageOccs)
                    {
                        if(k.isRequired())
                        {
                            continue;
                        }

                        if(reqKeyUsage.hasUsages(k.getKeyUsage().getBit()))
                        {
                            usages.add(k.getKeyUsage());
                        }
                    }
                }
            }

            org.bouncycastle.asn1.x509.KeyUsage value = X509Util.createKeyUsage(usages);
            if(value == null)
            {
                if(extOccurrence.isRequired())
                {
                    throw new CertProfileException("Could not add required extension KeyUsage");
                }
            }
            else
            {
                tuples.addExtension(extType, extOccurrence.isCritical(), value);
            }
        }

        // ExtendedKeyUsage
        extType = Extension.extendedKeyUsage;
        extOccurrence = occurrences.remove(extType);
        if(extOccurrence != null)
        {
            consideredExtensionTypes.add(extType);
            Set<ASN1ObjectIdentifier> usages = new HashSet<>();
            Set<ExtKeyUsageOccurrence> usageOccs = certProfile.getExtendedKeyUsages();
            for(ExtKeyUsageOccurrence k : usageOccs)
            {
                if(k.isRequired())
                {
                    usages.add(k.getExtKeyUsage());
                }
            }

            // the optional ExtKeyUsage will only be set if requested explicitly
            if(requestedExtensions != null && allowedRequestExtensions.contains(extType))
            {
                Extension extension = requestedExtensions.getExtension(extType);
                if(extension != null)
                {
                    ExtendedKeyUsage reqKeyUsage =
                            ExtendedKeyUsage.getInstance(extension.getParsedValue());
                    for(ExtKeyUsageOccurrence k : usageOccs)
                    {
                        if(k.isRequired())
                        {
                            continue;
                        }

                        if(reqKeyUsage.hasKeyPurposeId(KeyPurposeId.getInstance(k.getExtKeyUsage())))
                        {
                            usages.add(k.getExtKeyUsage());
                        }
                    }
                }
            }

            ExtendedKeyUsage value = X509Util.createExtendedUsage(usages);
            if(value == null)
            {
                if(extOccurrence.isRequired())
                {
                    throw new CertProfileException("Could not add required extension ExtendedKeyUsage");
                }
            } else
            {
                tuples.addExtension(extType, extOccurrence.isCritical(), value);
            }
        }

        // ocsp-nocheck
        extType = ObjectIdentifiers.id_extension_pkix_ocsp_nocheck;
        extOccurrence = occurrences.remove(extType);
        if(extOccurrence != null)
        {
            consideredExtensionTypes.add(extType);
            if(requestedExtensions != null && allowedRequestExtensions.contains(extType))
            {
                // the extension ocsp-nocheck will only be set if requested explicitly
                Extension extension = requestedExtensions.getExtension(extType);
                if(extension != null)
                {
                    tuples.addExtension(extType, extOccurrence.isCritical(), DERNull.INSTANCE);
                }
            }
        }

        // SubjectAltName
        extType = Extension.subjectAlternativeName;
        extOccurrence = occurrences.remove(extType);
        if(extOccurrence != null)
        {
            consideredExtensionTypes.add(extType);
            // TODO
        }

        // SubjectAltName
        extType = Extension.subjectInfoAccess;
        extOccurrence = occurrences.remove(extType);
        if(extOccurrence != null)
        {
            consideredExtensionTypes.add(extType);
            // TODO
        }

        // Admission
        extType = ObjectIdentifiers.id_extension_admission;
        extOccurrence = occurrences.remove(extType);
        if(extOccurrence != null)
        {
            consideredExtensionTypes.add(extType);
            ExtensionValue extValue = certProfile.getExtValueAdmission();
            addExtension(tuples, extType, "admission", extValue, extOccurrence);
        }

        // CertificatePolicies
        extType = Extension.certificatePolicies;
        extOccurrence = occurrences.remove(extType);
        if(extOccurrence != null)
        {
            consideredExtensionTypes.add(extType);
            ExtensionValue extValue = certProfile.getExtValueCertificatePolicies();
            addExtension(tuples, extType, "certificatePolicies", extValue, extOccurrence);
        }

        // InhibitAnyPolicy
        extType = Extension.inhibitAnyPolicy;
        extOccurrence = occurrences.remove(extType);
        if(extOccurrence != null)
        {
            consideredExtensionTypes.add(extType);
            ExtensionValue extValue = certProfile.getExtValueInhibitAnyPolicy();
            addExtension(tuples, extType, "inhibitAnyPolicy", extValue, extOccurrence);
        }

        // NameConstraints
        extType = Extension.nameConstraints;
        extOccurrence = occurrences.remove(extType);
        if(extOccurrence != null)
        {
            consideredExtensionTypes.add(extType);
            ExtensionValue extValue = certProfile.getExtValueNameConstraints();
            addExtension(tuples, extType, "nameConstraints", extValue, extOccurrence);
        }

        // PolicyConstraints
        extType = Extension.policyConstraints;
        extOccurrence = occurrences.remove(extType);
        if(extOccurrence != null)
        {
            consideredExtensionTypes.add(extType);
            ExtensionValue extValue = certProfile.getExtValuePolicyConstraints();
            addExtension(tuples, extType, "policyConstraints", extValue, extOccurrence);
        }

        // PolicyMapping
        extType = Extension.policyMappings;
        extOccurrence = occurrences.remove(extType);
        if(extOccurrence != null)
        {
            consideredExtensionTypes.add(extType);
            ExtensionValue extValue = certProfile.getExtValuePolicyMappings();
            addExtension(tuples, extType, "policyMappings", extValue, extOccurrence);
        }

        ExtensionTuples subtuples = certProfile.getExtensions(occurrences, requestedSubject, requestedExtensions);
        if(subtuples != null)
        {
            for(ASN1ObjectIdentifier consideredExtType : consideredExtensionTypes)
            {
                subtuples.removeExtensionTuple(consideredExtType);
            }

            for(ASN1ObjectIdentifier type : subtuples.getExtensionTypes())
            {
                tuples.addExtension(type, subtuples.getExtensionValue(type));
            }
        }

        return tuples;
    }

    private static void addExtension(ExtensionTuples tuples, ASN1ObjectIdentifier extType,
            String description, ExtensionValue extValue, ExtensionOccurrence extOccurrence)
    throws CertProfileException
    {
        if(extValue == null)
        {
            if(extOccurrence.isRequired())
            {
                throw new CertProfileException("Could not add required extension " + description);
            }
        } else
        {
            tuples.addExtension(extType, extValue);
        }
    }

    public boolean isCA()
    {
        return certProfile.isCA();
    }

    public boolean isOnlyForRA()
    {
        return certProfile.isOnlyForRA();
    }

    public boolean isOnlyForQA()
    {
        return certProfile.isOnlyForQA();
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
        if(certProfile != null)
        {
            certProfile.shutdown();
        }
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

    public Map<ASN1ObjectIdentifier, ExtensionOccurrence> getExtensionOccurences()
    {
        return certProfile.getExtensionOccurences();
    }

    public Set<KeyUsageOccurrence> getKeyUsage()
    {
        return certProfile.getKeyUsage();
    }

    public Integer getPathLenBasicConstraint()
    {
        return certProfile.getPathLenBasicConstraint();
    }

    public Set<ExtKeyUsageOccurrence> getExtendedKeyUsages()
    {
        return certProfile.getExtendedKeyUsages();
    }

    public void validate()
    throws CertProfileException
    {
        if(isOnlyForQA())
        {
            return;
        }

        StringBuilder msg = new StringBuilder();

        Map<ASN1ObjectIdentifier, ExtensionOccurrence> occurrences = getExtensionOccurences();
        boolean ca = isCA();

        Set<ASN1ObjectIdentifier> set = new HashSet<>();
        if(ca == false)
        {
            set.clear();
            for(ASN1ObjectIdentifier type : caOnlyExtensionTypes)
            {
                if(occurrences.containsKey(type))
                {
                    set.add(type);
                }
            }

            if(set.isEmpty() == false)
            {
                msg.append("EE profile contains CA-only extensions ").append(toString(set)).append(", ");
            }
        }

        set.clear();
        for(ASN1ObjectIdentifier type : occurrences.keySet())
        {
            ExtensionOccurrence occurrence = occurrences.get(type);
            if(criticalOnlyExtensionTypes.contains(type))
            {
                if(occurrence.isCritical() == false)
                {
                    set.add(type);
                }
            }
        }

        if(set.isEmpty() == false)
        {
            msg.append("Critical only extensions are marked as non-critical ").append(toString(set)).append(", ");
        }

        set.clear();
        for(ASN1ObjectIdentifier type : occurrences.keySet())
        {
            ExtensionOccurrence occurrence = occurrences.get(type);
            if(noncriticalOnlyExtensionTypes.contains(type))
            {
                if(occurrence.isCritical())
                {
                    set.add(type);
                }
            }
        }

        if(set.isEmpty() == false)
        {
            msg.append("None-critical extensions are marked as critical ").append(toString(set)).append(", ");
        }

        Set<KeyUsageOccurrence> usages = getKeyUsage();

        boolean b = containsKeyusage(usages, KeyUsage.digitalSignature);
        if(b == false)
        {
            b = containsKeyusage(usages, KeyUsage.contentCommitment);
        }
        if(b == false)
        {
            b = containsKeyusage(usages, KeyUsage.keyCertSign);
        }
        if(b == false)
        {
            b = containsKeyusage(usages, KeyUsage.cRLSign);
        }

        if(b)
        {
            ASN1ObjectIdentifier[] types = new ASN1ObjectIdentifier[]
                    {Extension.basicConstraints, Extension.keyUsage};

            set.clear();
            for(ASN1ObjectIdentifier type : types)
            {
                if(occurrences.containsKey(type) == false || occurrences.get(type).isRequired() == false)
                {
                    set.add(type);
                }
            }

            if(set.isEmpty() == false)
            {
                msg.append("Required extensions are not marked as required ").append(toString(set)).append(", ");
            }
        }

        if(ca)
        {
            if(containsKeyusage(usages, KeyUsage.keyCertSign) == false)
            {
                msg.append("CA profile does not contain keyUsage ").append(KeyUsage.keyCertSign).append(", ");
            }
        } else
        {
            KeyUsage[] caOnlyUsages = new KeyUsage[]
                    {KeyUsage.keyCertSign, KeyUsage.cRLSign};

            Set<KeyUsage> setUsages = new HashSet<>();
            for(KeyUsage caOnlyUsage : caOnlyUsages)
            {
                if(containsKeyusage(usages, caOnlyUsage))
                {
                    setUsages.add(caOnlyUsage);
                }
            }

            if(set.isEmpty() == false)
            {
                msg.append("EE profile contains CA-only keyUsage ").append(setUsages).append(", ");
            }
        }

        int len = msg.length();
        if(len > 2)
        {
            msg.delete(len - 2, len);
            throw new CertProfileException(msg.toString());
        }
    }

    private static String toString(Set<ASN1ObjectIdentifier> oids)
    {
        if(oids == null)
        {
            return "null";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for(ASN1ObjectIdentifier oid : oids)
        {
            String name = ObjectIdentifiers.getName(oid);
            if(name != null)
            {
                sb.append(name);
                sb.append(" (").append(oid.getId()).append(")");
            } else
            {
                sb.append(oid.getId());
            }
            sb.append(", ");
        }
        if(oids.isEmpty() == false)
        {
            int len = sb.length();
            sb.delete(len - 2, len);
        }
        sb.append("]");

        return sb.toString();
    }

    private static boolean containsKeyusage(Set<KeyUsageOccurrence> usageOccurrences, KeyUsage usage)
    {
        for(KeyUsageOccurrence entry : usageOccurrences)
        {
            if(usage == entry.getKeyUsage())
            {
                return true;
            }
        }
        return false;
    }
}
