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
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xipki.ca.api.profile.SpecialCertProfileBehavior;
import org.xipki.ca.server.certprofile.jaxb.AddTextType;
import org.xipki.ca.server.certprofile.jaxb.AlgorithmType;
import org.xipki.ca.server.certprofile.jaxb.CertificatePolicyInformationType;
import org.xipki.ca.server.certprofile.jaxb.ConditionType;
import org.xipki.ca.server.certprofile.jaxb.ConstantExtensionType;
import org.xipki.ca.server.certprofile.jaxb.CurveType;
import org.xipki.ca.server.certprofile.jaxb.CurveType.Encodings;
import org.xipki.ca.server.certprofile.jaxb.ECParameterType;
import org.xipki.ca.server.certprofile.jaxb.EnvParamType;
import org.xipki.ca.server.certprofile.jaxb.ExtensionType;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.Admission;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.AuthorityKeyIdentifier;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.CertificatePolicies;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.ConstantExtensions;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.ExtendedKeyUsage;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.InhibitAnyPolicy;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.NameConstraints;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.PolicyConstraints;
import org.xipki.ca.server.certprofile.jaxb.ExtensionsType.PolicyMappings;
import org.xipki.ca.server.certprofile.jaxb.GeneralNameType;
import org.xipki.ca.server.certprofile.jaxb.GeneralNameType.OtherName;
import org.xipki.ca.server.certprofile.jaxb.GeneralSubtreeBaseType;
import org.xipki.ca.server.certprofile.jaxb.GeneralSubtreesType;
import org.xipki.ca.server.certprofile.jaxb.KeyUsageType;
import org.xipki.ca.server.certprofile.jaxb.NameValueType;
import org.xipki.ca.server.certprofile.jaxb.ObjectFactory;
import org.xipki.ca.server.certprofile.jaxb.OidWithDescType;
import org.xipki.ca.server.certprofile.jaxb.OperatorType;
import org.xipki.ca.server.certprofile.jaxb.ParameterType;
import org.xipki.ca.server.certprofile.jaxb.PolicyIdMappingType;
import org.xipki.ca.server.certprofile.jaxb.ProfileType;
import org.xipki.ca.server.certprofile.jaxb.ProfileType.KeyAlgorithms;
import org.xipki.ca.server.certprofile.jaxb.ProfileType.Parameters;
import org.xipki.ca.server.certprofile.jaxb.ProfileType.Subject;
import org.xipki.ca.server.certprofile.jaxb.RdnConstraintType;
import org.xipki.ca.server.certprofile.jaxb.RdnType;
import org.xipki.ca.server.certprofile.jaxb.SubjectInfoAccessType;
import org.xipki.ca.server.certprofile.jaxb.SubjectInfoAccessType.Access;
import org.xipki.common.IoCertUtil;
import org.xipki.common.ObjectIdentifiers;

/**
 * @author Lijun Liao
 */

public class ProfileConfCreatorDemo
{
    private static final ASN1ObjectIdentifier id_gematik = new ASN1ObjectIdentifier("1.2.276.0.76.4");

    private static final String REGEX_FQDN =
            "(?=^.{1,254}$)(^(?:(?!\\d+\\.|-)[a-zA-Z0-9_\\-]{1,63}(?<!-)\\.?)+(?:[a-zA-Z]{2,})$)";
    private static final String REGEX_SN = "[\\d]{1,}";

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
            URL url = DefaultCertProfile.class.getResource("/xsd/certprofile.xsd");
            m.setSchema(schemaFact.newSchema(url));
            m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            m.setProperty("com.sun.xml.internal.bind.indentString", "  ");

            // RootCA
            ProfileType profile = CertProfile_RootCA(false);
            marshall(m, profile, "CertProfile_RootCA.xml");

            // RootCA-Cross
            profile = CertProfile_RootCA(true);
            marshall(m, profile, "CertProfile_RootCA_Cross.xml");

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

            //gSMC-K
            profile = CertProfile_gSMC_K();
            marshall(m, profile, "CertProfile_gSMC_K.xml");
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

    private static ProfileType CertProfile_RootCA(boolean cross)
    throws Exception
    {
        ProfileType profile = getBaseProfile("CertProfile RootCA" + (cross ? " Cross" : ""), true, 10 * 365, false);

        // Subject
        Subject subject = profile.getSubject();
        subject.setIncSerialNrIfSubjectExists(false);

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1, "DE|FR"));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1, REGEX_SN));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1, null));

        // Extensions
        // Extensions - general
        ExtensionsType extensions = profile.getExtensions();

        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true));
        if(cross)
        {
            list.add(createExtension(Extension.authorityKeyIdentifier, true));
        }
        list.add(createExtension(Extension.authorityInfoAccess, false));
        list.add(createExtension(Extension.cRLDistributionPoints, false));
        list.add(createExtension(Extension.freshestCRL, false));
        list.add(createExtension(Extension.keyUsage, true));
        list.add(createExtension(Extension.basicConstraints, true));

        // Extensions - keyUsage
        extensions.getKeyUsage().add(createKeyUsages(KeyUsageType.KEYCERT_SIGN, KeyUsageType.CRL_SIGN));
        return profile;
    }

    private static ProfileType CertProfile_SubCA()
    throws Exception
    {
        ProfileType profile = getBaseProfile("CertProfile SubCA", true, 8 * 365, false);

        // Subject
        Subject subject = profile.getSubject();
        subject.setIncSerialNrIfSubjectExists(false);

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1, "DE|FR"));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1, REGEX_SN));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1, null));

        // Extensions
        // Extensions - general
        ExtensionsType extensions = profile.getExtensions();
        extensions.setPathLen(1);

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
        extensions.getKeyUsage().add(createKeyUsages(KeyUsageType.KEYCERT_SIGN, KeyUsageType.CRL_SIGN));
        return profile;
    }

    private static ProfileType CertProfile_SubCA_Complex()
    throws Exception
    {
        ProfileType profile = getBaseProfile("CertProfile SubCA with most extensions", true, 8 * 365, false);

        // Subject
        Subject subject = profile.getSubject();
        subject.setIncSerialNrIfSubjectExists(false);

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1, "DE|FR"));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1, REGEX_SN));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1, null, "PREFIX ", " SUFFIX"));

        // Extensions
        // Extensions - general
        ExtensionsType extensions = profile.getExtensions();
        extensions.setPathLen(1);

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
        extensions.getKeyUsage().add(createKeyUsages(KeyUsageType.KEYCERT_SIGN, KeyUsageType.CRL_SIGN));

        // Certificate Policies
        ExtensionsType.CertificatePolicies certificatePolicies = createCertificatePolicies(
                new ASN1ObjectIdentifier("1.2.3.4.5"), new ASN1ObjectIdentifier("2.4.3.2.1"));
        extensions.getCertificatePolicies().add(certificatePolicies);

        // Policy Mappings
        PolicyMappings policyMappings = new PolicyMappings();
        policyMappings.getMapping().add(createPolicyIdMapping(
                new ASN1ObjectIdentifier("1.1.1.1.1"),
                new ASN1ObjectIdentifier("2.1.1.1.1")));
        policyMappings.getMapping().add(createPolicyIdMapping(
                new ASN1ObjectIdentifier("1.1.1.1.2"),
                new ASN1ObjectIdentifier("2.1.1.1.2")));
        extensions.getPolicyMappings().add(policyMappings);

        // Policy Constraints
        PolicyConstraints policyConstraints = createPolicyConstraints(2, 2);
        extensions.getPolicyConstraints().add(policyConstraints);

        // Name Constrains
        NameConstraints nameConstraints = createNameConstraints();
        extensions.getNameConstraints().add(nameConstraints);

        // Inhibit anyPolicy
        InhibitAnyPolicy inhibitAnyPolicy = createInhibitAnyPolicy(1);
        extensions.getInhibitAnyPolicy().add(inhibitAnyPolicy);

        // SubjectAltName
        GeneralNameType subjectAltNameMode = new GeneralNameType();
        extensions.setSubjectAltName(subjectAltNameMode);

        OtherName otherName = new OtherName();
        otherName.getType().add(createOidType(ObjectIdentifiers.DN_O));
        subjectAltNameMode.setOtherName(otherName);
        subjectAltNameMode.setRfc822Name("");
        subjectAltNameMode.setDNSName("");
        subjectAltNameMode.setDirectoryName("");
        subjectAltNameMode.setEdiPartyName("");
        subjectAltNameMode.setUniformResourceIdentifier("");
        subjectAltNameMode.setIPAddress("");
        subjectAltNameMode.setRegisteredID("");

        // SubjectInfoAccess
        SubjectInfoAccessType subjectInfoAccessMode = new SubjectInfoAccessType();
        extensions.setSubjectInfoAccess(subjectInfoAccessMode);

        Access access = new Access();
        access.setAccessMethod(createOidType(ObjectIdentifiers.id_ad_caRepository));

        GeneralNameType accessLocation = new GeneralNameType();
        access.setAccessLocation(accessLocation);
        accessLocation.setDirectoryName("");
        accessLocation.setUniformResourceIdentifier("");

        subjectInfoAccessMode.getAccess().add(access);

        // Custom Extension
        ConstantExtensions constantExts = new ConstantExtensions();
        extensions.getConstantExtensions().add(constantExts);

        ConstantExtensionType constantExt = new ConstantExtensionType();
        constantExts.getConstantExtension().add(constantExt);

        OidWithDescType type = createOidType(customExtensionOid, "custom extension 1");
        constantExt.setType(type);
        constantExt.setValue(DERNull.INSTANCE.getEncoded());

        return profile;
    }

    private static ProfileType CertProfile_OCSP()
    throws Exception
    {
        ProfileType profile = getBaseProfile("CertProfile OCSP", false, 5 * 365, false);

        // Subject
        Subject subject = profile.getSubject();
        subject.setIncSerialNrIfSubjectExists(false);

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1, "DE|FR"));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1, REGEX_SN));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1, null));

        // Extensions
        // Extensions - general
        ExtensionsType extensions = profile.getExtensions();

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
        extensions.getKeyUsage().add(createKeyUsages(KeyUsageType.CONTENT_COMMITMENT));

        // Extensions - extenedKeyUsage
        extensions.getExtendedKeyUsage().add(createExtendedKeyUsage(
                ObjectIdentifiers.id_kp_OCSPSigning));

        return profile;
    }

    private static ProfileType CertProfile_TLS()
    throws Exception
    {
        ProfileType profile = getBaseProfile("CertProfile TLS", false, 5 * 365, true);

        // Subject
        Subject subject = profile.getSubject();
        subject.setIncSerialNrIfSubjectExists(false);

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1, "DE|FR"));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1, REGEX_SN));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1, REGEX_FQDN));

        // Extensions
        // Extensions - general
        ExtensionsType extensions = profile.getExtensions();

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
        extensions.getKeyUsage().add(createKeyUsages(KeyUsageType.DIGITAL_SIGNATURE,
                KeyUsageType.DATA_ENCIPHERMENT,  KeyUsageType.KEY_ENCIPHERMENT));

        // Extensions - extenedKeyUsage
        extensions.getExtendedKeyUsage().add(createExtendedKeyUsage(
                ObjectIdentifiers.id_kp_clientAuth, ObjectIdentifiers.id_kp_serverAuth));

        // Admission - just DEMO, does not belong to TLS certificate
        Admission admission = createAdmission(new ASN1ObjectIdentifier("1.1.1.2"), "demo item");
        extensions.getAdmission().add(admission);

        return profile;
    }

    private static ProfileType CertProfile_TLS_C()
    throws Exception
    {
        ProfileType profile = getBaseProfile("CertProfile TLS_C", false, 5 * 365, false);

        // Subject
        Subject subject = profile.getSubject();
        subject.setIncSerialNrIfSubjectExists(false);

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1, "DE|FR"));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1, REGEX_SN));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1, null));

        // Extensions
        // Extensions - general
        ExtensionsType extensions = profile.getExtensions();
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
        extensions.getKeyUsage().add(createKeyUsages(KeyUsageType.DIGITAL_SIGNATURE,
                KeyUsageType.DATA_ENCIPHERMENT,  KeyUsageType.KEY_ENCIPHERMENT));

        // Extensions - extenedKeyUsage
        extensions.getExtendedKeyUsage().add(createExtendedKeyUsage(
                ObjectIdentifiers.id_kp_clientAuth));
        return profile;
    }

    private static ProfileType CertProfile_TLSwithIncSN()
    throws Exception
    {
        ProfileType profile = getBaseProfile("CertProfile TLSwithIncSN", false, 5 * 365, false);

        // Subject
        Subject subject = profile.getSubject();
        subject.setIncSerialNrIfSubjectExists(true);

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1, "DE|FR"));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1, REGEX_SN));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1, REGEX_FQDN));

        // Extensions
        // Extensions - general
        ExtensionsType extensions = profile.getExtensions();

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
        extensions.getKeyUsage().add(createKeyUsages(KeyUsageType.DIGITAL_SIGNATURE,
                KeyUsageType.DATA_ENCIPHERMENT,  KeyUsageType.KEY_ENCIPHERMENT));

        // Extensions - extenedKeyUsage
        extensions.getExtendedKeyUsage().add(createExtendedKeyUsage(
                ObjectIdentifiers.id_kp_clientAuth, ObjectIdentifiers.id_kp_serverAuth));

        return profile;
    }

    private static RdnType createRDN(ASN1ObjectIdentifier type, int min, int max, String regex)
    {
        return createRDN(type, min, max, regex, null, null);
    }

    private static RdnType createRDN(ASN1ObjectIdentifier type, int min, int max, String regex,
            String prefix, String suffix)
    {
        RdnType ret = new RdnType();
        ret.setType(createOidType(type));
        ret.setMinOccurs(min);
        ret.setMaxOccurs(max);

        if(regex != null)
        {
            RdnConstraintType constraint = new RdnConstraintType();
            constraint.setRegex(regex);
            ret.setConstraint(constraint);
        }

        if(prefix != null && prefix.isEmpty() == false)
        {
            ret.getAddPrefix().add(createAddText(prefix, "add.prefix", "true", OperatorType.AND));
        }

        if(suffix != null && suffix.isEmpty() == false)
        {
            ret.getAddSuffix().add(createAddText(suffix, "add.suffix", "true", OperatorType.AND));
        }

        return ret;
    }

    private static AddTextType createAddText(String text, String envName, String envValue,
            OperatorType operator)
    {
        AddTextType ret = new AddTextType();
        ret.setText(text);

        ConditionType condition = new ConditionType();
        ret.setCondition(condition);

        condition.setOperator(operator);
        EnvParamType envParam = new EnvParamType();
        condition.getEnvParam().add(envParam);

        envParam.setName(envName);
        envParam.setValue(envValue);

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
        ret.getProfessionOid().add(createOidType(oid));
        return ret;
    }

    private static ExtensionsType.CertificatePolicies createCertificatePolicies(
            ASN1ObjectIdentifier... policyOids)
    {
        if(policyOids == null || policyOids.length == 0)
        {
            return null;
        }

        ExtensionsType.CertificatePolicies ret = new ExtensionsType.CertificatePolicies();
        List<CertificatePolicyInformationType> l = ret.getCertificatePolicyInformation();
        for(ASN1ObjectIdentifier oid : policyOids)
        {
            CertificatePolicyInformationType single = new CertificatePolicyInformationType();
            l.add(single);
            single.setPolicyIdentifier(createOidType(oid));
        }

        return ret;
    }

    private static ExtendedKeyUsage createExtendedKeyUsage(
            ASN1ObjectIdentifier... extKeyUsages)
    {
        ExtendedKeyUsage ret = new ExtendedKeyUsage();
        for(ASN1ObjectIdentifier usage : extKeyUsages)
        {
            ret.getUsage().add(createOidType(usage));
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
        ret.setIssuerDomainPolicy(createOidType(issuerPolicyId));
        ret.setSubjectDomainPolicy(createOidType(subjectPolicyId));

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

    private static OidWithDescType createOidType(ASN1ObjectIdentifier oid)
    {
        return createOidType(oid, null);
    }

    private static OidWithDescType createOidType(ASN1ObjectIdentifier oid, String description)
    {
        OidWithDescType ret = new OidWithDescType();
        ret.setValue(oid.getId());
        if(description == null)
        {
            description = getDescription(oid);
        }
        if(description != null)
        {
            ret.setDescription(description);
        }
        return ret;
    }

    private static ProfileType CertProfile_gSMC_K()
    throws Exception
    {
        ProfileType profile = getBaseProfile("CertProfile gSMC_K (C.AK.AUT)", false, 5 * 365, false);
        profile.setDuplicateSubjectPermitted(true);

        // SpecialBehavior
        profile.setSpecialBehavior(SpecialCertProfileBehavior.gematik_gSMC_K.name());

        // Maximal liftime
        Parameters profileParams = new Parameters();
        profile.setParameters(profileParams);
        NameValueType nv = new NameValueType();
        nv.setName(SpecialCertProfileBehavior.PARAMETER_MAXLIFTIME);
        nv.setValue(Integer.toString(20 * 365));
        profileParams.getParameter().add(nv);

        // Subject
        Subject subject = profile.getSubject();
        subject.setIncSerialNrIfSubjectExists(false);

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1, "DE"));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_ST, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_L, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_POSTAL_CODE, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_STREET, 0, 1, null));
        // regex: ICCSN-yyyyMMdd
        String regex = "80276[\\d]{15,15}-20\\d\\d(0[1-9]|1[012])(0[1-9]|[12][0-9]|3[01])";
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1, regex));

        // Extensions
        // Extensions - general
        ExtensionsType extensions = profile.getExtensions();

        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true));
        list.add(createExtension(Extension.authorityKeyIdentifier, true));
        list.add(createExtension(Extension.authorityInfoAccess, true));
        list.add(createExtension(Extension.cRLDistributionPoints, false));
        list.add(createExtension(Extension.keyUsage, true));
        list.add(createExtension(Extension.subjectAlternativeName, false));
        list.add(createExtension(Extension.basicConstraints, true));
        list.add(createExtension(Extension.certificatePolicies, true));
        list.add(createExtension(ObjectIdentifiers.id_extension_admission, true));
        list.add(createExtension(Extension.extendedKeyUsage, true));

        // Extensions - keyUsage
        extensions.getKeyUsage().add(createKeyUsages(KeyUsageType.DIGITAL_SIGNATURE,
                KeyUsageType.KEY_ENCIPHERMENT));

        // Extensions - extenedKeyUsage
        extensions.getExtendedKeyUsage().add(createExtendedKeyUsage(
                ObjectIdentifiers.id_kp_clientAuth, ObjectIdentifiers.id_kp_serverAuth));

        // Extensions - Policy
        CertificatePolicies policies = new CertificatePolicies();
        extensions.getCertificatePolicies().add(policies);

        ASN1ObjectIdentifier[] policyIds = new ASN1ObjectIdentifier[]
        {
                id_gematik.branch("79"), id_gematik.branch("163")};
        for(ASN1ObjectIdentifier id : policyIds)
        {
            CertificatePolicyInformationType policyInfo = new CertificatePolicyInformationType();
            policies.getCertificatePolicyInformation().add(policyInfo);
            policyInfo.setPolicyIdentifier(createOidType(id));
        }

        // Extension - Adminssion
        Admission admission = new Admission();
        extensions.getAdmission().add(admission);
        admission.getProfessionOid().add(createOidType(id_gematik.branch("103")));
        admission.getProfessionItem().add("Anwendungskonnektor");

        return profile;
    }

    private static ProfileType getBaseProfile(String description, boolean ca, int validity, boolean useMidnightNotBefore)
    {
        ProfileType profile = new ProfileType();
        profile.setDescription(description);
        profile.setOnlyForRA(false);
        profile.setCa(ca);
        profile.setValidity(validity);
        profile.setNotBeforeTime(useMidnightNotBefore ? "midnight" : "current");

        profile.setDuplicateKeyPermitted(false);
        profile.setDuplicateSubjectPermitted(false);
        profile.setSerialNumberInReqPermitted(false);

        // Subject
        Subject subject = new Subject();
        profile.setSubject(subject);

        subject.setDnBackwards(false);

        // Key
        profile.setKeyAlgorithms(createKeyAlgorithms());

        // AllowedClientExtensions
        profile.setAllowedClientExtensions(null);

        // Extensions
        // Extensions - general
        ExtensionsType extensions = new ExtensionsType();
        profile.setExtensions(extensions);

        AuthorityKeyIdentifier akiType = new AuthorityKeyIdentifier();
        akiType.setIncludeIssuerAndSerial(Boolean.FALSE);
        extensions.setAuthorityKeyIdentifier(akiType);

        return profile;
    }

    private static KeyAlgorithms createKeyAlgorithms()
    {
        KeyAlgorithms ret = new KeyAlgorithms();
        List<AlgorithmType> list = ret.getAlgorithm();

        // RSA
        {
            AlgorithmType rsa = new AlgorithmType();
            list.add(rsa);

            rsa.setAlgorithm(createOidType(PKCSObjectIdentifiers.rsaEncryption, "RSA"));
            List<ParameterType> params = rsa.getParameter();

            ParameterType param = new ParameterType();
            params.add(param);
            param.setName(DefaultCertProfile.MODULUS_LENGTH);
            param.setMin(2048);
            param.setMax(2048);

            param = new ParameterType();
            param.setName(DefaultCertProfile.MODULUS_LENGTH);
            params.add(param);
            param.setMin(3072);
            param.setMax(3072);
        }

        // DSA
        {
            AlgorithmType dsa = new AlgorithmType();
            list.add(dsa);

            dsa.setAlgorithm(createOidType(X9ObjectIdentifiers.id_dsa, "DSA"));
            List<ParameterType> params = dsa.getParameter();

            ParameterType param = new ParameterType();
            params.add(param);
            param.setName(DefaultCertProfile.P_LENGTH);
            param.setMin(1024);
            param.setMax(1024);

            param = new ParameterType();
            params.add(param);
            param.setName(DefaultCertProfile.P_LENGTH);
            param.setMin(2048);
            param.setMax(2048);

            param = new ParameterType();
            params.add(param);
            param.setName(DefaultCertProfile.Q_LENGTH);
            param.setMin(160);
            param.setMax(160);

            param = new ParameterType();
            params.add(param);
            param.setName(DefaultCertProfile.Q_LENGTH);
            param.setMin(224);
            param.setMax(224);

            param = new ParameterType();
            params.add(param);
            param.setName(DefaultCertProfile.Q_LENGTH);
            param.setMin(256);
            param.setMax(256);
        }

        // EC
        {
            AlgorithmType ec = new AlgorithmType();
            ec.setAlgorithm(createOidType(X9ObjectIdentifiers.id_ecPublicKey, "EC"));

            list.add(ec);

            ECParameterType params = new ECParameterType();
            ec.setEcParameter(params);

            ASN1ObjectIdentifier[] curveIds = new ASN1ObjectIdentifier[]
            {
                    SECObjectIdentifiers.secp256r1, TeleTrusTObjectIdentifiers.brainpoolP256r1};

            for(ASN1ObjectIdentifier curveId : curveIds)
            {
                String name = IoCertUtil.getCurveName(curveId);
                CurveType curve = new CurveType();
                curve.setOid(createOidType(curveId, name));

                Encodings encodings = new Encodings();
                encodings.getEncoding().add((byte) 4); // uncompressed
                curve.setEncodings(encodings);

                params.getCurve().add(curve);
            }
        }

        return ret;
    }

}
