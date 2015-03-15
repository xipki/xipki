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

package org.xipki.ca.server.impl;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
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
import org.xipki.ca.api.CertprofileException;
import org.xipki.ca.api.EnvironmentParameterResolver;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.api.profile.ExtensionControl;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.GeneralNameMode;
import org.xipki.ca.api.profile.SubjectInfo;
import org.xipki.ca.api.profile.x509.ExtKeyUsageControl;
import org.xipki.ca.api.profile.x509.KeyUsageControl;
import org.xipki.ca.api.profile.x509.SpecialX509CertprofileBehavior;
import org.xipki.ca.api.profile.x509.X509Certprofile;
import org.xipki.ca.api.profile.x509.X509CertVersion;
import org.xipki.ca.api.profile.x509.X509Util;
import org.xipki.ca.certprofile.XmlX509Certprofile;
import org.xipki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.common.XipkiCmpConstants;
import org.xipki.common.KeyUsage;
import org.xipki.common.ObjectIdentifiers;
import org.xipki.common.ParamChecker;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.SecurityUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.security.api.ExtensionExistence;

/**
 * @author Lijun Liao
 */

class IdentifiedX509Certprofile
{
    private static final Set<ASN1ObjectIdentifier> criticalOnlyExtensionTypes;
    private static final Set<ASN1ObjectIdentifier> noncriticalOnlyExtensionTypes;
    private static final Set<ASN1ObjectIdentifier> caOnlyExtensionTypes;
    private static final Set<ASN1ObjectIdentifier> noneRequestExtensionTypes;

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

        noneRequestExtensionTypes = new HashSet<ASN1ObjectIdentifier>();
        noneRequestExtensionTypes.add(Extension.subjectKeyIdentifier);
        noneRequestExtensionTypes.add(Extension.authorityKeyIdentifier);
        noneRequestExtensionTypes.add(Extension.issuerAlternativeName);
        noneRequestExtensionTypes.add(Extension.cRLDistributionPoints);
        noneRequestExtensionTypes.add(Extension.freshestCRL);
        noneRequestExtensionTypes.add(Extension.basicConstraints);
        noneRequestExtensionTypes.add(Extension.inhibitAnyPolicy);
    }

    private final CertprofileEntry entry;
    private final X509Certprofile certprofile;
    private EnvironmentParameterResolver parameterResolver;

    public IdentifiedX509Certprofile(CertprofileEntry entry, String realType)
    throws CertprofileException
    {
        ParamChecker.assertNotNull("entry", entry);
        this.entry = entry;
        X509Certprofile tmpCertprofile = null;

        final String type = realType == null ?  entry.getType() : realType;
        String className;
        if(type.equalsIgnoreCase("xml"))
        {
            tmpCertprofile = new XmlX509Certprofile();
        }
        else if(StringUtil.startsWithIgnoreCase(type, "java:"))
        {
            className = type.substring("java:".length());
            try
            {
                Class<?> clazz = Class.forName(className);
                tmpCertprofile = (X509Certprofile) clazz.newInstance();
            }catch(ClassNotFoundException | InstantiationException  | IllegalAccessException | ClassCastException e)
            {
                throw new CertprofileException("invalid type " + type + ", " + e.getClass().getName() +
                        ": " + e.getMessage());
            }
        }
        else
        {
            throw new CertprofileException("invalid type " + type);
        }

        tmpCertprofile.initialize(entry.getConf());

        if(parameterResolver != null)
        {
            tmpCertprofile.setEnvironmentParameterResolver(parameterResolver);
        }

        if(tmpCertprofile.getSpecialCertprofileBehavior() == SpecialX509CertprofileBehavior.gematik_gSMC_K)
        {
            String paramName = SpecialX509CertprofileBehavior.PARAMETER_MAXLIFTIME;
            String s = tmpCertprofile.getParameter(paramName);
            if(s == null)
            {
                throw new CertprofileException("parameter " + paramName + " is not defined");
            }

            s = s.trim();
            int i;
            try
            {
                i = Integer.parseInt(s);
            }catch(NumberFormatException e)
            {
                throw new CertprofileException("invalid " + paramName + ": " + s);
            }
            if(i < 1)
            {
                throw new CertprofileException("invalid " + paramName + ": " + s);
            }
        }

        this.certprofile = tmpCertprofile;
    }

    public String getName()
    {
        return entry.getName();
    }

    public CertprofileEntry getEntry()
    {
        return entry;
    }

    public X509CertVersion getVersion()
    {
        return certprofile.getVersion();
    }

    public Set<ASN1ObjectIdentifier> getSignatureAlgorithms()
    {
        return certprofile.getSignatureAlgorithms();
    }

    public SpecialX509CertprofileBehavior getSpecialCertprofileBehavior()
    {
        return certprofile.getSpecialCertprofileBehavior();
    }

    public void setEnvironmentParameterResolver(EnvironmentParameterResolver parameterResolver)
    {
        this.parameterResolver = parameterResolver;
        if(certprofile != null)
        {
            certprofile.setEnvironmentParameterResolver(parameterResolver);
        }
    }

    public Date getNotBefore(Date notBefore)
    {
        return certprofile.getNotBefore(notBefore);
    }

    public CertValidity getValidity()
    {
        return certprofile.getValidity();
    }

    public boolean hasMidnightNotBefore()
    {
        return certprofile.hasMidnightNotBefore();
    }

    public TimeZone getTimezone()
    {
        return certprofile.getTimezone();
    }

    public SubjectInfo getSubject(X500Name requestedSubject)
    throws CertprofileException, BadCertTemplateException
    {
        return certprofile.getSubject(requestedSubject);
    }

    public ExtensionValues getExtensions(
            X500Name requestedSubject, Extensions requestExtensions,
            SubjectPublicKeyInfo publicKeyInfo,
            PublicCAInfo publicCaInfo, X509Certificate crlSignerCert)
    throws CertprofileException, BadCertTemplateException
    {
        ExtensionValues values = new ExtensionValues();

        Map<ASN1ObjectIdentifier, ExtensionControl> controls = new HashMap<>(certprofile.getExtensionControls());

        Set<ASN1ObjectIdentifier> neededExtensionTypes = new HashSet<>();
        Set<ASN1ObjectIdentifier> wantedExtensionTypes = new HashSet<>();
        if(requestExtensions != null)
        {
            Extension reqExtension = requestExtensions.getExtension(XipkiCmpConstants.id_ext_cmp_request_extensions);
            if(reqExtension != null)
            {
                ExtensionExistence ee = ExtensionExistence.getInstance(reqExtension.getParsedValue());
                neededExtensionTypes.addAll(ee.getNeedExtensions());
                wantedExtensionTypes.addAll(ee.getWantExtensions());
            }

            for(ASN1ObjectIdentifier oid : neededExtensionTypes)
            {
                if(wantedExtensionTypes.contains(oid))
                {
                    wantedExtensionTypes.remove(oid);
                }

                if(controls.containsKey(oid) == false)
                {
                    throw new BadCertTemplateException("could not add needed extension " + oid.getId());
                }
            }
        }

        // SubjectKeyIdentifier
        ASN1ObjectIdentifier extType = Extension.subjectKeyIdentifier;
        ExtensionControl extControl = controls.remove(extType);
        if(extControl != null)
        {
            boolean addMe = addMe(extType, extControl, neededExtensionTypes, wantedExtensionTypes);
            if(addMe)
            {
                MessageDigest sha1;
                try
                {
                    sha1 = MessageDigest.getInstance("SHA-1");
                } catch (NoSuchAlgorithmException e)
                {
                    throw new CertprofileException(e.getMessage(), e);
                }
                byte[] skiValue = sha1.digest(publicKeyInfo.getPublicKeyData().getBytes());

                SubjectKeyIdentifier value = new SubjectKeyIdentifier(skiValue);
                addExtension(values, extType, value, extControl,
                        neededExtensionTypes, wantedExtensionTypes);
            }
        }

        // Authority key identifier
        extType = Extension.authorityKeyIdentifier;
        extControl = controls.remove(extType);
        if(extControl != null)
        {
            boolean addMe = addMe(extType, extControl, neededExtensionTypes, wantedExtensionTypes);
            if(addMe)
            {
                byte[] ikiValue = publicCaInfo.getSubjectKeyIdentifer();
                AuthorityKeyIdentifier value = null;
                if(ikiValue != null)
                {
                    if(certprofile.includeIssuerAndSerialInAKI())
                    {
                        GeneralNames x509CaSubject = new GeneralNames(new GeneralName(publicCaInfo.getX500Subject()));
                        value = new AuthorityKeyIdentifier(ikiValue, x509CaSubject, publicCaInfo.getSerialNumber());
                    }
                    else
                    {
                        value = new AuthorityKeyIdentifier(ikiValue);
                    }
                }

                addExtension(values, extType, value, extControl,
                        neededExtensionTypes, wantedExtensionTypes);
            }
        }

        // IssuerAltName
        extType = Extension.issuerAlternativeName;
        extControl = controls.remove(extType);
        if(extControl != null)
        {
            boolean addMe = addMe(extType, extControl, neededExtensionTypes, wantedExtensionTypes);
            if(addMe)
            {
                GeneralNames value = publicCaInfo.getSubjectAltName();
                addExtension(values, extType, value, extControl,
                        neededExtensionTypes, wantedExtensionTypes);
            }
        }

        // AuthorityInfoAccess
        extType = Extension.authorityInfoAccess;
        extControl = controls.remove(extType);
        if(extControl != null)
        {
            boolean addMe = addMe(extType, extControl, neededExtensionTypes, wantedExtensionTypes);
            if(addMe)
            {
                AuthorityInformationAccess value = X509Util.createAuthorityInformationAccess(publicCaInfo.getOcspUris());
                addExtension(values, extType, value, extControl,
                        neededExtensionTypes, wantedExtensionTypes);
            }
        }

        if(controls.containsKey(Extension.cRLDistributionPoints) || controls.containsKey(Extension.freshestCRL))
        {
            X500Name crlSignerSubject = null;
            if(crlSignerCert != null)
            {
                crlSignerSubject = X500Name.getInstance(crlSignerCert.getSubjectX500Principal().getEncoded());
            }

            X500Name x500CaPrincipal = publicCaInfo.getX500Subject();

            // CRLDistributionPoints
            extType = Extension.cRLDistributionPoints;
            extControl = controls.remove(extType);
            if(extControl != null)
            {
                boolean addMe = addMe(extType, extControl, neededExtensionTypes, wantedExtensionTypes);
                if(addMe)
                {
                    CRLDistPoint value;
                    try
                    {
                        value = X509Util.createCRLDistributionPoints(publicCaInfo.getCrlUris(),
                                x500CaPrincipal, crlSignerSubject);
                    } catch (IOException e)
                    {
                        throw new CertprofileException(e.getMessage(), e);
                    }
                    addExtension(values, extType, value, extControl,
                            neededExtensionTypes, wantedExtensionTypes);
                }
            }

            // FreshestCRL
            extType = Extension.freshestCRL;
            extControl = controls.remove(extType);
            if(extControl != null)
            {
                boolean addMe = addMe(extType, extControl, neededExtensionTypes, wantedExtensionTypes);
                if(addMe)
                {
                    CRLDistPoint value;
                    try
                    {
                        value = X509Util.createCRLDistributionPoints(publicCaInfo.getDeltaCrlUris(),
                                x500CaPrincipal, crlSignerSubject);
                    } catch (IOException e)
                    {
                        throw new CertprofileException(e.getMessage(), e);
                    }
                    addExtension(values, extType, value, extControl,
                            neededExtensionTypes, wantedExtensionTypes);
                }
            }
        }

        // BasicConstraints
        extType = Extension.basicConstraints;
        extControl = controls.remove(extType);
        if(extControl != null)
        {
            boolean addMe = addMe(extType, extControl, neededExtensionTypes, wantedExtensionTypes);
            if(addMe)
            {
                BasicConstraints value = X509Util.createBasicConstraints(certprofile.isCA(),
                        certprofile.getPathLenBasicConstraint());
                addExtension(values, extType, value, extControl,
                        neededExtensionTypes, wantedExtensionTypes);
            }
        }

        // KeyUsage
        extType = Extension.keyUsage;
        extControl = controls.remove(extType);
        if(extControl != null)
        {
            boolean addMe = addMe(extType, extControl, neededExtensionTypes, wantedExtensionTypes);
            if(addMe)
            {
                Set<KeyUsage> usages = new HashSet<>();
                Set<KeyUsageControl> usageOccs = certprofile.getKeyUsage();
                for(KeyUsageControl k : usageOccs)
                {
                    if(k.isRequired())
                    {
                        usages.add(k.getKeyUsage());
                    }
                }

                // the optional KeyUsage will only be set if requested explicitly
                if(requestExtensions != null && extControl.isRequest())
                {
                    Extension extension = requestExtensions.getExtension(extType);
                    if(extension != null)
                    {
                        org.bouncycastle.asn1.x509.KeyUsage reqKeyUsage =
                                org.bouncycastle.asn1.x509.KeyUsage.getInstance(extension.getParsedValue());
                        for(KeyUsageControl k : usageOccs)
                        {
                            if(k.isRequired())
                            {
                                continue;
                            }

                            if(reqKeyUsage.hasUsages(k.getKeyUsage().getBcUsage()))
                            {
                                usages.add(k.getKeyUsage());
                            }
                        }
                    }
                }

                org.bouncycastle.asn1.x509.KeyUsage value = SecurityUtil.createKeyUsage(usages);
                addExtension(values, extType, value, extControl,
                        neededExtensionTypes, wantedExtensionTypes);
            }
        }

        // ExtendedKeyUsage
        extType = Extension.extendedKeyUsage;
        extControl = controls.remove(extType);
        if(extControl != null)
        {
            boolean addMe = addMe(extType, extControl, neededExtensionTypes, wantedExtensionTypes);
            if(addMe)
            {
                Set<ASN1ObjectIdentifier> usages = new HashSet<>();
                Set<ExtKeyUsageControl> usageOccs = certprofile.getExtendedKeyUsages();
                for(ExtKeyUsageControl k : usageOccs)
                {
                    if(k.isRequired())
                    {
                        usages.add(k.getExtKeyUsage());
                    }
                }

                // the optional ExtKeyUsage will only be set if requested explicitly
                if(requestExtensions != null && extControl.isRequest())
                {
                    Extension extension = requestExtensions.getExtension(extType);
                    if(extension != null)
                    {
                        ExtendedKeyUsage reqKeyUsage =
                                ExtendedKeyUsage.getInstance(extension.getParsedValue());
                        for(ExtKeyUsageControl k : usageOccs)
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

                if(extControl.isCritical() && usages.contains(ObjectIdentifiers.anyExtendedKeyUsage))
                {
                    extControl = new ExtensionControl(false, extControl.isRequired(), extControl.isRequest());
                }

                ExtendedKeyUsage value = SecurityUtil.createExtendedUsage(usages);
                addExtension(values, extType, value, extControl,
                        neededExtensionTypes, wantedExtensionTypes);
            }
        }

        // ocsp-nocheck
        extType = ObjectIdentifiers.id_extension_pkix_ocsp_nocheck;
        extControl = controls.remove(extType);
        if(extControl != null)
        {
            boolean addMe = addMe(extType, extControl, neededExtensionTypes, wantedExtensionTypes);
            if(addMe)
            {
                // the extension ocsp-nocheck will only be set if requested explicitly
                DERNull value = DERNull.INSTANCE;
                addExtension(values, extType, value, extControl,
                        neededExtensionTypes, wantedExtensionTypes);
            }
        }

        // SubjectAltName
        extType = Extension.subjectAlternativeName;
        extControl = controls.remove(extType);
        if(extControl != null)
        {
            boolean addMe = addMe(extType, extControl, neededExtensionTypes, wantedExtensionTypes);
            if(addMe)
            {
                GeneralNames value = null;
                if(requestExtensions != null && extControl.isRequest())
                {
                    ASN1Encodable extValue = requestExtensions.getExtensionParsedValue(extType);
                    if(extValue != null)
                    {
                        GeneralNames reqNames = GeneralNames.getInstance(extValue);

                        Set<GeneralNameMode> modes = certprofile.getSubjectAltNameModes();
                        if(modes != null)
                        {
                            GeneralName[] reqL = reqNames.getNames();
                            GeneralName[] l = new GeneralName[reqL.length];
                            for(int i = 0; i < reqL.length; i++)
                            {
                                l[i] = createGeneralName(reqL[i], modes);
                            }
                            value = new GeneralNames(l);
                        } else
                        {
                            value = reqNames;
                        }

                    }
                }

                addExtension(values, extType, value, extControl,
                        neededExtensionTypes, wantedExtensionTypes);
            }
        }

        // SubjectInfoAccess
        extType = Extension.subjectInfoAccess;
        extControl = controls.remove(extType);
        if(extControl != null)
        {
            boolean addMe = addMe(extType, extControl, neededExtensionTypes, wantedExtensionTypes);
            if(addMe)
            {
                ASN1Sequence value = null;
                if(requestExtensions != null && extControl.isRequest())
                {
                    ASN1Encodable extValue = requestExtensions.getExtensionParsedValue(extType);
                    if(extValue != null)
                    {
                        ASN1Sequence reqSeq = ASN1Sequence.getInstance(extValue);
                        int size = reqSeq.size();

                        Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> modes = certprofile.getSubjectInfoAccessModes();
                        if(modes == null)
                        {
                            value = reqSeq;
                        } else
                        {
                            ASN1EncodableVector v = new ASN1EncodableVector();
                            for(int i = 0; i < size; i++)
                            {
                                AccessDescription ad = AccessDescription.getInstance(reqSeq.getObjectAt(i));
                                ASN1ObjectIdentifier accessMethod = ad.getAccessMethod();
                                if(accessMethod == null)
                                {
                                    accessMethod = X509Certprofile.OID_ZERO;
                                }
                                Set<GeneralNameMode> generalNameModes = modes.get(accessMethod);

                                if(generalNameModes == null)
                                {
                                    throw new BadCertTemplateException("subjectInfoAccess.accessMethod " + accessMethod.getId()+
                                            " is not allowed");
                                }

                                GeneralName accessLocation = createGeneralName(ad.getAccessLocation(),generalNameModes);
                                v.add(new AccessDescription(accessMethod, accessLocation));
                            }

                            if(v.size() > 0)
                            {
                                value = new DERSequence(v);
                            }
                        }
                    }
                }
                addExtension(values, extType, value, extControl,
                        neededExtensionTypes, wantedExtensionTypes);
            }
        }

        ExtensionValues subvalues = certprofile.getExtensions(
                Collections.unmodifiableMap(controls), requestedSubject, requestExtensions);

        Set<ASN1ObjectIdentifier> extTypes = new HashSet<>(controls.keySet());
        for(ASN1ObjectIdentifier type : extTypes)
        {
            extControl = controls.remove(type);
            boolean addMe = addMe(type, extControl, neededExtensionTypes, wantedExtensionTypes);
            if(addMe)
            {
                ExtensionValue value = null;
                if(extControl.isRequest())
                {
                    Extension reqExt = requestExtensions.getExtension(type);
                    if(reqExt != null)
                    {
                        value = new ExtensionValue(reqExt.isCritical(), reqExt.getParsedValue());
                    }
                }

                if(value == null)
                {
                    value = subvalues.getExtensionValue(type);
                }

                addExtension(values, type, value, extControl,
                        neededExtensionTypes, wantedExtensionTypes);
            }
        }

        Set<ASN1ObjectIdentifier> unprocessedExtTypes = new HashSet<>();
        for(ASN1ObjectIdentifier type : controls.keySet())
        {
            if(controls.get(type).isRequired())
            {
                unprocessedExtTypes.add(type);
            }
        }

        if(CollectionUtil.isNotEmpty(unprocessedExtTypes))
        {
            throw new CertprofileException("Could not add required extensions " + toString(unprocessedExtTypes));
        }

        if(CollectionUtil.isNotEmpty(neededExtensionTypes))
        {
            throw new BadCertTemplateException("Could not add requested extensions " + toString(neededExtensionTypes));
        }

        return values;
    }

    private static void addExtension(ExtensionValues values, ASN1ObjectIdentifier extType,
            ExtensionValue extValue, ExtensionControl extControl,
            Set<ASN1ObjectIdentifier> neededExtensionTypes, Set<ASN1ObjectIdentifier> wantedExtensionTypes)
    throws CertprofileException
    {
        if(extValue == null)
        {
            if(extControl.isRequired())
            {
                String description = ObjectIdentifiers.getName(extType);
                if(description == null)
                {
                    description = extType.getId();
                }
                throw new CertprofileException("Could not add required extension " + description);
            }
        } else
        {
            values.addExtension(extType, extValue);
            neededExtensionTypes.remove(extType);
            wantedExtensionTypes.remove(extType);
        }
    }

    private static void addExtension(ExtensionValues values, ASN1ObjectIdentifier extType,
            ASN1Encodable extValue, ExtensionControl extControl,
            Set<ASN1ObjectIdentifier> neededExtensionTypes, Set<ASN1ObjectIdentifier> wantedExtensionTypes)
    throws CertprofileException
    {
        if(extValue == null)
        {
            if(extControl.isRequired())
            {
                String description = ObjectIdentifiers.getName(extType);
                if(description == null)
                {
                    description = extType.getId();
                }
                throw new CertprofileException("Could not add required extension " + description);
            }
        } else
        {
            values.addExtension(extType, extControl.isCritical(), extValue);
            neededExtensionTypes.remove(extType);
            wantedExtensionTypes.remove(extType);
        }
    }

    public boolean isCA()
    {
        return certprofile.isCA();
    }

    public boolean isOnlyForRA()
    {
        return certprofile.isOnlyForRA();
    }

    public boolean isOnlyForQA()
    {
        return certprofile.isOnlyForQA();
    }

    public SubjectPublicKeyInfo checkPublicKey(SubjectPublicKeyInfo publicKey)
    throws BadCertTemplateException
    {
        return certprofile.checkPublicKey(publicKey);
    }

    public boolean incSerialNumberIfSubjectExists()
    {
        return certprofile.incSerialNumberIfSubjectExists();
    }

    public void shutdown()
    {
        if(certprofile != null)
        {
            certprofile.shutdown();
        }
    }

    public boolean includeIssuerAndSerialInAKI()
    {
        return certprofile.includeIssuerAndSerialInAKI();
    }

    public String incSerialNumber(String currentSerialNumber)
    throws BadFormatException
    {
        return certprofile.incSerialNumber(currentSerialNumber);
    }

    public boolean isDuplicateKeyPermitted()
    {
        return certprofile.isDuplicateKeyPermitted();
    }

    public boolean isDuplicateSubjectPermitted()
    {
        return certprofile.isDuplicateSubjectPermitted();
    }

    public boolean isSerialNumberInReqPermitted()
    {
        return certprofile.isSerialNumberInReqPermitted();
    }

    public  String getParameter(String paramName)
    {
        return certprofile.getParameter(paramName);
    }

    public Map<ASN1ObjectIdentifier, ExtensionControl> getExtensionControls()
    {
        return certprofile.getExtensionControls();
    }

    public Set<KeyUsageControl> getKeyUsage()
    {
        return certprofile.getKeyUsage();
    }

    public Integer getPathLenBasicConstraint()
    {
        return certprofile.getPathLenBasicConstraint();
    }

    public Set<ExtKeyUsageControl> getExtendedKeyUsages()
    {
        return certprofile.getExtendedKeyUsages();
    }

    public void validate()
    throws CertprofileException
    {
        if(isOnlyForQA())
        {
            return;
        }

        StringBuilder msg = new StringBuilder();

        Map<ASN1ObjectIdentifier, ExtensionControl> controls = getExtensionControls();
        Set<ASN1ObjectIdentifier> set = new HashSet<>();
        for(ASN1ObjectIdentifier type : noneRequestExtensionTypes)
        {
            ExtensionControl control = controls.get(type);
            if(control != null && control.isRequest())
            {
                set.add(type);
            }
        }

        if(CollectionUtil.isNotEmpty(set))
        {
            msg.append("extensions ").append(toString(set)).append(" could not be contained in request, ");
        }

        boolean ca = isCA();

        set.clear();
        if(ca == false)
        {
            set.clear();
            for(ASN1ObjectIdentifier type : caOnlyExtensionTypes)
            {
                if(controls.containsKey(type))
                {
                    set.add(type);
                }
            }

            if(CollectionUtil.isNotEmpty(set))
            {
                msg.append("EE profile contains CA-only extensions ").append(toString(set)).append(", ");
            }
        }

        set.clear();
        for(ASN1ObjectIdentifier type : controls.keySet())
        {
            ExtensionControl control = controls.get(type);
            if(criticalOnlyExtensionTypes.contains(type))
            {
                if(control.isCritical() == false)
                {
                    set.add(type);
                }
            }
        }

        if(CollectionUtil.isNotEmpty(set))
        {
            msg.append("Critical only extensions are marked as non-critical ").append(toString(set)).append(", ");
        }

        set.clear();
        for(ASN1ObjectIdentifier type : controls.keySet())
        {
            ExtensionControl control = controls.get(type);
            if(noncriticalOnlyExtensionTypes.contains(type))
            {
                if(control.isCritical())
                {
                    set.add(type);
                }
            }
        }

        if(CollectionUtil.isNotEmpty(set))
        {
            msg.append("None-critical extensions are marked as critical ").append(toString(set)).append(", ");
        }

        Set<KeyUsageControl> usages = getKeyUsage();

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
                if(controls.containsKey(type) == false || controls.get(type).isRequired() == false)
                {
                    set.add(type);
                }
            }

            if(CollectionUtil.isNotEmpty(set))
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

            if(CollectionUtil.isNotEmpty(set))
            {
                msg.append("EE profile contains CA-only keyUsage ").append(setUsages).append(", ");
            }
        }

        int len = msg.length();
        if(len > 2)
        {
            msg.delete(len - 2, len);
            throw new CertprofileException(msg.toString());
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
        if(CollectionUtil.isNotEmpty(oids))
        {
            int len = sb.length();
            sb.delete(len - 2, len);
        }
        sb.append("]");

        return sb.toString();
    }

    private static boolean containsKeyusage(Set<KeyUsageControl> usageControls, KeyUsage usage)
    {
        for(KeyUsageControl entry : usageControls)
        {
            if(usage == entry.getKeyUsage())
            {
                return true;
            }
        }
        return false;
    }

    private static GeneralName createGeneralName(GeneralName reqName, Set<GeneralNameMode> modes)
    throws BadCertTemplateException
    {
        int tag = reqName.getTagNo();
        GeneralNameMode mode = null;
        for(GeneralNameMode m : modes)
        {
            if(m.getTag().getTag() == tag)
            {
                mode = m;
                break;
            }
        }

        if(mode == null)
        {
            throw new BadCertTemplateException("generalName tag " + tag + " is not allowed");
        }

        switch(tag)
        {
            case GeneralName.rfc822Name:
            case GeneralName.dNSName:
            case GeneralName.uniformResourceIdentifier:
            case GeneralName.iPAddress:
            case GeneralName.registeredID:
            case GeneralName.directoryName:
            {
                return new GeneralName(tag, reqName.getName());
            }
            case GeneralName.otherName:
            {
                ASN1Sequence reqSeq = ASN1Sequence.getInstance(reqName.getName());
                ASN1ObjectIdentifier type = ASN1ObjectIdentifier.getInstance(reqSeq.getObjectAt(0));
                if(mode.getAllowedTypes().contains(type) == false)
                {
                    throw new BadCertTemplateException("otherName.type " + type.getId() + " is not allowed");
                }

                ASN1Encodable value = ((ASN1TaggedObject) reqSeq.getObjectAt(1)).getObject();
                String text;
                if(value instanceof ASN1String == false)
                {
                    throw new BadCertTemplateException("otherName.value is not a String");
                } else
                {
                    text = ((ASN1String) value).getString();
                }

                ASN1EncodableVector vector = new ASN1EncodableVector();
                vector.add(type);
                vector.add(new DERTaggedObject(true, 0, new DERUTF8String(text)));
                DERSequence seq = new DERSequence(vector);

                return new GeneralName(GeneralName.otherName, seq);
            }
            case GeneralName.ediPartyName:
            {
                ASN1Sequence reqSeq = ASN1Sequence.getInstance(reqName.getName());

                int n = reqSeq.size();
                String nameAssigner = null;
                int idx = 0;
                if(n > 1)
                {
                    DirectoryString ds = DirectoryString.getInstance(
                            ((ASN1TaggedObject) reqSeq.getObjectAt(idx++)).getObject());
                    nameAssigner = ds.getString();
                }

                DirectoryString ds = DirectoryString.getInstance(
                        ((ASN1TaggedObject) reqSeq.getObjectAt(idx++)).getObject());
                String partyName = ds.getString();

                ASN1EncodableVector vector = new ASN1EncodableVector();
                if(nameAssigner != null)
                {
                    vector.add(new DERTaggedObject(false, 0, new DirectoryString(nameAssigner)));
                }
                vector.add(new DERTaggedObject(false, 1, new DirectoryString(partyName)));
                ASN1Sequence seq = new DERSequence(vector);
                return new GeneralName(GeneralName.ediPartyName, seq);
            }
            default:
            {
                throw new RuntimeException("should not reach here, unknown GeneralName tag "+ tag);
            }
        }
    }

    private static boolean addMe(ASN1ObjectIdentifier extType, ExtensionControl extControl,
            Set<ASN1ObjectIdentifier> neededExtensionTypes,
            Set<ASN1ObjectIdentifier> wantedExtensionTypes)
    {
        boolean addMe = extControl.isRequired();
        if(addMe == false)
        {
            if(neededExtensionTypes.contains(extType) || wantedExtensionTypes.contains(extType))
            {
                addMe = true;
            }
        }
        return addMe;
    }
}
