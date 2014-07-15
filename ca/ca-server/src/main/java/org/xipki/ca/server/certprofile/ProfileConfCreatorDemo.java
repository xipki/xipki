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

package org.xipki.ca.server.certprofile;

import java.io.File;
import java.io.FileOutputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.validation.SchemaFactory;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.ca.server.certprofile.jaxb.CertificatePolicyInformationType;
import org.xipki.ca.server.certprofile.jaxb.ConstantExtensionType;
import org.xipki.ca.server.certprofile.jaxb.ExtensionType;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.Admission;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.ConstantExtensions;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.ExtendedKeyUsage;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.InhibitAnyPolicy;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.NameConstraints;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.PolicyConstraints;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.PolicyMappings;
import org.xipki.ca.server.certprofile.jaxb.GeneralNameType.OtherName;
import org.xipki.ca.server.certprofile.jaxb.GeneralNameType;
import org.xipki.ca.server.certprofile.jaxb.GeneralSubtreeBaseType;
import org.xipki.ca.server.certprofile.jaxb.GeneralSubtreesType;
import org.xipki.ca.server.certprofile.jaxb.KeyUsageType;
import org.xipki.ca.server.certprofile.jaxb.ObjectFactory;
import org.xipki.ca.server.certprofile.jaxb.OidWithDescType;
import org.xipki.ca.server.certprofile.jaxb.PolicyIdMappingType;
import org.xipki.ca.server.certprofile.jaxb.ProfileType;
import org.xipki.ca.server.certprofile.jaxb.ProfileType.Subject;
import org.xipki.ca.server.certprofile.jaxb.RdnType;
import org.xipki.security.common.ObjectIdentifiers;

/**
 * @author Lijun Liao
 */

public class ProfileConfCreatorDemo
{
    private static final Map<ASN1ObjectIdentifier, String> oidDescMap;

    static
    {
        oidDescMap = new HashMap<>();
        oidDescMap.put(Extension.auditIdentity, "auditIdentity");
        oidDescMap.put(Extension.authorityInfoAccess, "authorityInfoAccess");
        oidDescMap.put(Extension.authorityKeyIdentifier, "authorityKeyIdentifier");
        oidDescMap.put(Extension.basicConstraints, "basicConstraints");
        oidDescMap.put(Extension.biometricInfo, "biometricInfo");
        oidDescMap.put(Extension.certificateIssuer, "certificateIssuer");
        oidDescMap.put(Extension.certificatePolicies, "certificatePolicies");
        oidDescMap.put(Extension.cRLDistributionPoints, "cRLDistributionPoints");
        oidDescMap.put(Extension.cRLNumber, "cRLNumber");
        oidDescMap.put(Extension.deltaCRLIndicator, "deltaCRLIndicator");
        oidDescMap.put(Extension.extendedKeyUsage, "extendedKeyUsage");
        oidDescMap.put(Extension.freshestCRL, "freshestCRL");
        oidDescMap.put(Extension.inhibitAnyPolicy, "inhibitAnyPolicy");
        oidDescMap.put(Extension.instructionCode, "instructionCode");
        oidDescMap.put(Extension.invalidityDate, "invalidityDate");
        oidDescMap.put(Extension.issuerAlternativeName, "issuerAlternativeName");
        oidDescMap.put(Extension.issuingDistributionPoint, "issuingDistributionPoint");
        oidDescMap.put(Extension.keyUsage, "keyUsage");
        oidDescMap.put(Extension.logoType, "logoType");
        oidDescMap.put(Extension.nameConstraints, "nameConstraints");
        oidDescMap.put(Extension.noRevAvail, "noRevAvail");
        oidDescMap.put(Extension.policyConstraints, "policyConstraints");
        oidDescMap.put(Extension.policyMappings, "policyMappings");
        oidDescMap.put(Extension.privateKeyUsagePeriod, "privateKeyUsagePeriod");
        oidDescMap.put(Extension.qCStatements, "qCStatements");
        oidDescMap.put(Extension.reasonCode, "reasonCode");
        oidDescMap.put(Extension.subjectAlternativeName, "subjectAlternativeName");
        oidDescMap.put(Extension.subjectDirectoryAttributes, "subjectDirectoryAttributes");
        oidDescMap.put(Extension.subjectInfoAccess, "subjectInfoAccess");
        oidDescMap.put(Extension.subjectKeyIdentifier, "subjectKeyIdentifier");
        oidDescMap.put(Extension.targetInformation, "targetInformation");
    }

    public static void main(String[] args)
    {
        try
        {
            Marshaller m = JAXBContext.newInstance(ObjectFactory.class).createMarshaller();
            final SchemaFactory schemaFact = SchemaFactory.newInstance(
                    javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
            URL url = DfltCertProfile.class.getResource("/xsd/certprofile.xsd");
            m.setSchema(schemaFact.newSchema(url));
            m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            m.setProperty("com.sun.xml.internal.bind.indentString", "  ");
            
            // RootCA
            ProfileType profile = CertProfile_RootCA();
            marshall(m, profile, "CertProfile_RootCA.xml");

            // SubCA
            profile = CertProfile_SubCA();
            marshall(m, profile, "CertProfile_SubCA.xml");

            profile = CertProfile_SubCA_Complex();
            marshall(m, profile, "CertProfile_SubCA_Complex.xml");

            // OCSP
            profile = CertProfile_OCSP();
            marshall(m, profile, "CertProfile_OCSP.xml");

            // TLS
            profile = CertProfile_TLS();
            marshall(m, profile, "CertProfile_TLS.xml");

            // TLS_C
            profile = CertProfile_TLS_C();
            marshall(m, profile, "CertProfile_TLS_C.xml");

            // TLSwithIncSN
            profile = CertProfile_TLSwithIncSN();
            marshall(m, profile, "CertProfile_TLSwithIncSN.xml");
        }catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    private static void marshall(Marshaller m, ProfileType profile, String filename)
    throws Exception
    {
        File file = new File("tmp", filename);
        file.getParentFile().mkdirs();
        JAXBElement<ProfileType> root = new ObjectFactory().createProfile(profile);
        FileOutputStream out = new FileOutputStream(file);
        try
        {
            m.marshal(root, out);
        }finally
        {
            out.close();
        }

    }

    private static ProfileType CertProfile_RootCA()
    throws Exception
    {
        ProfileType profile = new ProfileType();
        profile.setDescription("CertProfile RootCA");
        profile.setOnlyForRA(false);
        profile.setCa(true);
        profile.setValidity(1825);

        // Subject
        Subject subject = new Subject();
        profile.setSubject(subject);

        subject.setDnBackwards(false);
        subject.setIncSerialNrIfSubjectExists(false);

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1));

        // AllowedClientExtensions
        profile.setAllowedClientExtensions(null);

        // Extensions
        // Extensions - general
        ExtensionsType extensions = new ExtensionsType();
        profile.setExtensions(extensions);

        extensions.setIncludeIssuerAndSerialInAKI(false);

        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true));
        list.add(createExtension(Extension.authorityInfoAccess, false));
        list.add(createExtension(Extension.cRLDistributionPoints, false));
        list.add(createExtension(Extension.freshestCRL, false));
        list.add(createExtension(Extension.keyUsage, true));
        list.add(createExtension(Extension.basicConstraints, true));

        // Extensions - keyUsage
        extensions.setKeyUsage(createKeyUsages(KeyUsageType.KEYCERT_SIGN, KeyUsageType.CRL_SIGN));
        return profile;
    }

    private static ProfileType CertProfile_SubCA()
    throws Exception
    {
        ProfileType profile = new ProfileType();
        profile.setDescription("CertProfile SubCA");
        profile.setOnlyForRA(false);
        profile.setCa(true);
        profile.setValidity(1825);

        // Subject
        Subject subject = new Subject();
        profile.setSubject(subject);

        subject.setDnBackwards(false);
        subject.setIncSerialNrIfSubjectExists(false);

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1));

        // AllowedClientExtensions
        profile.setAllowedClientExtensions(null);

        // Extensions
        // Extensions - general
        ExtensionsType extensions = new ExtensionsType();
        profile.setExtensions(extensions);

        extensions.setPathLen(1);
        extensions.setIncludeIssuerAndSerialInAKI(false);

        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true));
        list.add(createExtension(Extension.authorityKeyIdentifier, true));
        list.add(createExtension(Extension.authorityInfoAccess, false));
        list.add(createExtension(Extension.cRLDistributionPoints, false));
        list.add(createExtension(Extension.freshestCRL, false));
        list.add(createExtension(Extension.keyUsage, true));
        list.add(createExtension(Extension.basicConstraints, true));

        // Extensions - keyUsage
        extensions.setKeyUsage(createKeyUsages(KeyUsageType.KEYCERT_SIGN, KeyUsageType.CRL_SIGN));
        return profile;
    }

    private static ProfileType CertProfile_SubCA_Complex()
    throws Exception
    {
        ProfileType profile = new ProfileType();
        profile.setDescription("CertProfile SubCA with most extensions");
        profile.setOnlyForRA(false);
        profile.setCa(true);
        profile.setValidity(1825);

        // Subject
        Subject subject = new Subject();
        profile.setSubject(subject);

        subject.setDnBackwards(false);
        subject.setIncSerialNrIfSubjectExists(false);

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1));

        // AllowedClientExtensions
        profile.setAllowedClientExtensions(null);

        // Extensions
        // Extensions - general
        ExtensionsType extensions = new ExtensionsType();
        profile.setExtensions(extensions);

        extensions.setPathLen(1);
        extensions.setIncludeIssuerAndSerialInAKI(false);

        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true));
        list.add(createExtension(Extension.authorityKeyIdentifier, true));
        list.add(createExtension(Extension.authorityInfoAccess, false));
        list.add(createExtension(Extension.cRLDistributionPoints, false));
        list.add(createExtension(Extension.freshestCRL, false));
        list.add(createExtension(Extension.keyUsage, true));
        list.add(createExtension(Extension.basicConstraints, true));
        list.add(createExtension(Extension.subjectAlternativeName, true));        
        list.add(createExtension(Extension.subjectInfoAccess, true));

        list.add(createExtension(Extension.policyMappings, true));
        list.add(createExtension(Extension.nameConstraints, true));
        list.add(createExtension(Extension.policyConstraints, true));
        list.add(createExtension(Extension.inhibitAnyPolicy, true));

        
        ASN1ObjectIdentifier customExtensionOid = new ASN1ObjectIdentifier("1.2.3.4");
        list.add(createExtension(customExtensionOid, true, "custom extension 1"));

        // Extensions - keyUsage
        extensions.setKeyUsage(createKeyUsages(KeyUsageType.KEYCERT_SIGN, KeyUsageType.CRL_SIGN));

        // Certificate Policies
        ExtensionsType.CertificateProfiles certificatePolicies = createCertificatePolicies(
                new ASN1ObjectIdentifier("1.2.3.4.5"), new ASN1ObjectIdentifier("2.4.3.2.1"));
        extensions.setCertificateProfiles(certificatePolicies);

        // Policy Mappings
        PolicyMappings policyMappings = new PolicyMappings();
        policyMappings.getMapping().add(createPolicyIdMapping(
                new ASN1ObjectIdentifier("1.1.1.1.1"),
                new ASN1ObjectIdentifier("2.1.1.1.1")));
        policyMappings.getMapping().add(createPolicyIdMapping(
                new ASN1ObjectIdentifier("1.1.1.1.2"),
                new ASN1ObjectIdentifier("2.1.1.1.2")));
        extensions.setPolicyMappings(policyMappings);

        // Policy Constraints
        PolicyConstraints policyConstraints = createPolicyConstraints(2, 2);
        extensions.setPolicyConstraints(policyConstraints);

        // Name Constrains
        NameConstraints nameConstraints = createNameConstraints();
        extensions.setNameConstraints(nameConstraints);

        // Inhibit anyPolicy
        InhibitAnyPolicy inhibitAnyPolicy = createInhibitAnyPolicy(1);
        extensions.setInhibitAnyPolicy(inhibitAnyPolicy);

        // SubjectAltName
        GeneralNameType subjectAltNameMode = new GeneralNameType();
        extensions.setSubjectAltName(subjectAltNameMode);
        
        OtherName otherName = new OtherName();
        otherName.setType(createOidType(ObjectIdentifiers.DN_O.getId(), "o"));
        subjectAltNameMode.setOtherName(otherName);
        
        // SubjectInfoAccess
        GeneralNameType subjectInfoAccessMode = new GeneralNameType();
        extensions.setSubjectInfoAccess(subjectInfoAccessMode);
        
        subjectInfoAccessMode.setIPAddress("");        
        
        // Custom Extension
        ConstantExtensions constantExts = new ConstantExtensions();
        extensions.setConstantExtensions(constantExts);

        ConstantExtensionType constantExt = new ConstantExtensionType();
        constantExts.getConstantExtension().add(constantExt);

        OidWithDescType type = createOidType(customExtensionOid.getId(), "custom extension 1");
        constantExt.setType(type);
        constantExt.setValue(DERNull.INSTANCE.getEncoded());

        return profile;
    }

    private static ProfileType CertProfile_OCSP()
    throws Exception
    {
        ProfileType profile = new ProfileType();
        profile.setDescription("CertProfile OCSP");
        profile.setOnlyForRA(false);
        profile.setCa(false);
        profile.setValidity(730);

        // Subject
        Subject subject = new Subject();
        profile.setSubject(subject);

        subject.setDnBackwards(false);
        subject.setIncSerialNrIfSubjectExists(false);

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1));

        // AllowedClientExtensions
        profile.setAllowedClientExtensions(null);

        // Extensions
        // Extensions - general
        ExtensionsType extensions = new ExtensionsType();
        profile.setExtensions(extensions);

        extensions.setIncludeIssuerAndSerialInAKI(false);

        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true));
        list.add(createExtension(Extension.authorityKeyIdentifier, true));
        list.add(createExtension(Extension.authorityInfoAccess, false));
        list.add(createExtension(Extension.cRLDistributionPoints, false));
        list.add(createExtension(Extension.freshestCRL, false));
        list.add(createExtension(Extension.keyUsage, true));
        list.add(createExtension(Extension.basicConstraints, true));
        list.add(createExtension(Extension.extendedKeyUsage, true));
        list.add(createExtension(ObjectIdentifiers.id_extension_pkix_ocsp_nocheck, false));

        // Extensions - keyUsage
        extensions.setKeyUsage(createKeyUsages(KeyUsageType.CONTENT_COMMITMENT));

        // Extensions - extenedKeyUsage
        extensions.setExtendedKeyUsage(createExtendedKeyUsage(
                ObjectIdentifiers.id_kp_OCSPSigning));

        return profile;
    }

    private static ProfileType CertProfile_TLS()
    throws Exception
    {
        ProfileType profile = new ProfileType();
        profile.setDescription("CertProfile TLS");
        profile.setOnlyForRA(false);
        profile.setCa(false);
        profile.setValidity(730);

        // Subject
        Subject subject = new Subject();
        profile.setSubject(subject);

        subject.setDnBackwards(false);
        subject.setIncSerialNrIfSubjectExists(false);

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1));

        // AllowedClientExtensions
        profile.setAllowedClientExtensions(null);

        // Extensions
        // Extensions - general
        ExtensionsType extensions = new ExtensionsType();
        profile.setExtensions(extensions);

        extensions.setIncludeIssuerAndSerialInAKI(false);

        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true));
        list.add(createExtension(Extension.authorityKeyIdentifier, true));
        list.add(createExtension(Extension.authorityInfoAccess, false));
        list.add(createExtension(Extension.cRLDistributionPoints, false));
        list.add(createExtension(Extension.freshestCRL, false));
        list.add(createExtension(Extension.keyUsage, true));
        list.add(createExtension(Extension.basicConstraints, true));
        list.add(createExtension(Extension.extendedKeyUsage, true));
        list.add(createExtension(ObjectIdentifiers.id_extension_admission, true));

        // Extensions - keyUsage
        extensions.setKeyUsage(createKeyUsages(KeyUsageType.DIGITAL_SIGNATURE,
                KeyUsageType.DATA_ENCIPHERMENT,  KeyUsageType.KEY_ENCIPHERMENT));

        // Extensions - extenedKeyUsage
        extensions.setExtendedKeyUsage(createExtendedKeyUsage(
                ObjectIdentifiers.id_kp_clientAuth, ObjectIdentifiers.id_kp_serverAuth));
        
        // Admission - just DEMO, does not belong to TLS certificate
        Admission admission = createAdmission(new ASN1ObjectIdentifier("1.1.1.2"), "demo item");
        extensions.setAdmission(admission);

        return profile;
    }

    private static ProfileType CertProfile_TLS_C()
    throws Exception
    {
        ProfileType profile = new ProfileType();
        profile.setDescription("CertProfile TLS_C");
        profile.setOnlyForRA(false);
        profile.setCa(false);
        profile.setValidity(730);

        // Subject
        Subject subject = new Subject();
        profile.setSubject(subject);

        subject.setDnBackwards(false);
        subject.setIncSerialNrIfSubjectExists(false);

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1));

        // AllowedClientExtensions
        profile.setAllowedClientExtensions(null);

        // Extensions
        // Extensions - general
        ExtensionsType extensions = new ExtensionsType();
        profile.setExtensions(extensions);

        extensions.setIncludeIssuerAndSerialInAKI(false);

        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true));
        list.add(createExtension(Extension.authorityKeyIdentifier, true));
        list.add(createExtension(Extension.authorityInfoAccess, false));
        list.add(createExtension(Extension.cRLDistributionPoints, false));
        list.add(createExtension(Extension.freshestCRL, false));
        list.add(createExtension(Extension.keyUsage, true));
        list.add(createExtension(Extension.basicConstraints, true));
        list.add(createExtension(Extension.extendedKeyUsage, true));

        // Extensions - keyUsage
        extensions.setKeyUsage(createKeyUsages(KeyUsageType.DIGITAL_SIGNATURE,
                KeyUsageType.DATA_ENCIPHERMENT,  KeyUsageType.KEY_ENCIPHERMENT));

        // Extensions - extenedKeyUsage
        extensions.setExtendedKeyUsage(createExtendedKeyUsage(
                ObjectIdentifiers.id_kp_clientAuth));
        return profile;
    }

    private static ProfileType CertProfile_TLSwithIncSN()
    throws Exception
    {
        ProfileType profile = new ProfileType();
        profile.setDescription("CertProfile TLSwithIncSN");
        profile.setCa(false);
        profile.setOnlyForRA(false);
        profile.setValidity(730);

        // Subject
        Subject subject = new Subject();
        profile.setSubject(subject);

        subject.setDnBackwards(false);
        subject.setIncSerialNrIfSubjectExists(true);

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1));

        // AllowedClientExtensions
        profile.setAllowedClientExtensions(null);

        // Extensions
        // Extensions - general
        ExtensionsType extensions = new ExtensionsType();
        profile.setExtensions(extensions);

        extensions.setIncludeIssuerAndSerialInAKI(false);

        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true));
        list.add(createExtension(Extension.authorityKeyIdentifier, true));
        list.add(createExtension(Extension.authorityInfoAccess, false));
        list.add(createExtension(Extension.cRLDistributionPoints, false));
        list.add(createExtension(Extension.freshestCRL, false));
        list.add(createExtension(Extension.keyUsage, true));
        list.add(createExtension(Extension.basicConstraints, true));
        list.add(createExtension(Extension.extendedKeyUsage, true));

        // Extensions - keyUsage
        extensions.setKeyUsage(createKeyUsages(KeyUsageType.DIGITAL_SIGNATURE,
                KeyUsageType.DATA_ENCIPHERMENT,  KeyUsageType.KEY_ENCIPHERMENT));

        // Extensions - extenedKeyUsage
        extensions.setExtendedKeyUsage(createExtendedKeyUsage(
                ObjectIdentifiers.id_kp_clientAuth, ObjectIdentifiers.id_kp_serverAuth));

        return profile;
    }
    private static RdnType createRDN(ASN1ObjectIdentifier type, int min, int max)
    {
        RdnType ret = new RdnType();
        ret.setValue(type.getId());
        ret.setMinOccurs(min);
        ret.setMaxOccurs(max);

        String description = getDescription(type);
        if(description != null)
        {
            ret.setDescription(description);
        }
        return ret;
    }

    private static ExtensionType createExtension(ASN1ObjectIdentifier type, boolean required)
    {
        return createExtension(type, required, null);
    }

    private static ExtensionType createExtension(ASN1ObjectIdentifier type, boolean required, String description)
    {
        ExtensionType ret = new ExtensionType();
        ret.setValue(type.getId());
        ret.setRequired(required);
        if(description == null)
        {
            description = getDescription(type);
        }

        if(description != null)
        {
            ret.setDescription(description);
        }
        return ret;
    }

    private static org.xipki.ca.server.certprofile.jaxb.ExtensionsType.KeyUsage createKeyUsages(
            KeyUsageType... keyUsages)
    {
        org.xipki.ca.server.certprofile.jaxb.ExtensionsType.KeyUsage ret =
                new org.xipki.ca.server.certprofile.jaxb.ExtensionsType.KeyUsage();
        for(KeyUsageType usage : keyUsages)
        {
            ret.getUsage().add(usage);
        }
        return ret;
    }

    private static Admission createAdmission(ASN1ObjectIdentifier oid, String item)
    {
    	Admission ret = new Admission();
    	ret.getProfessionItem().add(item);
    	ret.getProfessionOid().add(createOidType(oid.getId(), null));
    	return ret;
    }
    
    private static ExtensionsType.CertificateProfiles createCertificatePolicies(
            ASN1ObjectIdentifier... policyOids)
    {
        if(policyOids == null || policyOids.length == 0)
        {
            return null;
        }

        ExtensionsType.CertificateProfiles ret = new ExtensionsType.CertificateProfiles();
        List<CertificatePolicyInformationType> l = ret.getCertificatePolicyInformation();
        for(ASN1ObjectIdentifier oid : policyOids)
        {
            CertificatePolicyInformationType single = new CertificatePolicyInformationType();
            l.add(single);
            single.setPolicyIdentifier(createOidType(oid.getId(), null));
        }

        return ret;
    }

    private static ExtendedKeyUsage createExtendedKeyUsage(
            ASN1ObjectIdentifier... extKeyUsages)
    {
        ExtendedKeyUsage ret = new ExtendedKeyUsage();
        for(ASN1ObjectIdentifier usage : extKeyUsages)
        {
            String description = getDescription(usage);
            ret.getUsage().add(createOidType(usage.getId(), description));
        }
        return ret;
    }

    private static String getDescription(ASN1ObjectIdentifier oid)
    {
        String desc = ObjectIdentifiers.getName(oid);
        if(desc == null)
        {
            desc = oidDescMap.get(oid);
        }

        return desc;
    }

    private static PolicyIdMappingType createPolicyIdMapping(
        ASN1ObjectIdentifier issuerPolicyId,
        ASN1ObjectIdentifier subjectPolicyId)
    {
        PolicyIdMappingType ret = new PolicyIdMappingType();

        String desc = getDescription(issuerPolicyId);
        ret.setIssuerDomainPolicy(createOidType(issuerPolicyId.getId(), desc));

        desc = getDescription(subjectPolicyId);
        ret.setSubjectDomainPolicy(createOidType(subjectPolicyId.getId(), desc));

        return ret;
    }

    private static PolicyConstraints createPolicyConstraints(Integer inhibitPolicyMapping,
            Integer requireExplicitPolicy)
    {
        PolicyConstraints ret = new PolicyConstraints();
        if(inhibitPolicyMapping != null)
        {
            ret.setInhibitPolicyMapping(inhibitPolicyMapping);
        }

        if(requireExplicitPolicy != null)
        {
            ret.setRequireExplicitPolicy(requireExplicitPolicy);
        }
        return ret;
    }

    private static NameConstraints createNameConstraints()
    {
        NameConstraints ret = new NameConstraints();
        GeneralSubtreesType permitted = new GeneralSubtreesType();
        GeneralSubtreeBaseType single = new GeneralSubtreeBaseType();
        single.setDirectoryName("O=example organization, C=DE");
        permitted.getBase().add(single);
        ret.setPermittedSubtrees(permitted);

        GeneralSubtreesType excluded = new GeneralSubtreesType();
        single = new GeneralSubtreeBaseType();
        single.setDirectoryName("OU=bad OU, O=example organization, C=DE");
        excluded.getBase().add(single);
        ret.setExcludedSubtrees(excluded);

        return ret;
    }

    private static InhibitAnyPolicy createInhibitAnyPolicy(int skipCerts)
    {
        InhibitAnyPolicy ret = new InhibitAnyPolicy();
        ret.setSkipCerts(skipCerts);
        return ret;
    }
    
    private static OidWithDescType createOidType(String oid, String description)
    {
    	OidWithDescType ret = new OidWithDescType();
    	ret.setValue(oid);
    	if(description != null)
    	{
    		ret.setDescription(description);
    	}
    	return ret;
    }
}
