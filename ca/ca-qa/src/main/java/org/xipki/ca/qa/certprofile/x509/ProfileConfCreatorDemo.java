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

package org.xipki.ca.qa.certprofile.x509;

import java.io.File;
import java.io.FileOutputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.validation.SchemaFactory;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xipki.ca.qa.certprofile.x509.jaxb.AlgorithmType;
import org.xipki.ca.qa.certprofile.x509.jaxb.CertificatePolicyInformationType;
import org.xipki.ca.qa.certprofile.x509.jaxb.ConstantExtensionType;
import org.xipki.ca.qa.certprofile.x509.jaxb.DSAParametersType;
import org.xipki.ca.qa.certprofile.x509.jaxb.ECParametersType;
import org.xipki.ca.qa.certprofile.x509.jaxb.ECParametersType.Curves;
import org.xipki.ca.qa.certprofile.x509.jaxb.ECParametersType.PointEncodings;
import org.xipki.ca.qa.certprofile.x509.jaxb.ExtensionType;
import org.xipki.ca.qa.certprofile.x509.jaxb.ExtensionsType;
import org.xipki.ca.qa.certprofile.x509.jaxb.ExtensionsType.Admission;
import org.xipki.ca.qa.certprofile.x509.jaxb.ExtensionsType.AuthorityKeyIdentifier;
import org.xipki.ca.qa.certprofile.x509.jaxb.ExtensionsType.CertificatePolicies;
import org.xipki.ca.qa.certprofile.x509.jaxb.ExtensionsType.ConstantExtensions;
import org.xipki.ca.qa.certprofile.x509.jaxb.ExtensionsType.ExtendedKeyUsage;
import org.xipki.ca.qa.certprofile.x509.jaxb.ExtensionsType.ExtendedKeyUsage.Usage;
import org.xipki.ca.qa.certprofile.x509.jaxb.ExtensionsType.InhibitAnyPolicy;
import org.xipki.ca.qa.certprofile.x509.jaxb.ExtensionsType.KeyUsage;
import org.xipki.ca.qa.certprofile.x509.jaxb.ExtensionsType.NameConstraints;
import org.xipki.ca.qa.certprofile.x509.jaxb.ExtensionsType.PolicyConstraints;
import org.xipki.ca.qa.certprofile.x509.jaxb.ExtensionsType.PolicyMappings;
import org.xipki.ca.qa.certprofile.x509.jaxb.GeneralNameType;
import org.xipki.ca.qa.certprofile.x509.jaxb.GeneralNameType.OtherName;
import org.xipki.ca.qa.certprofile.x509.jaxb.GeneralSubtreeBaseType;
import org.xipki.ca.qa.certprofile.x509.jaxb.GeneralSubtreesType;
import org.xipki.ca.qa.certprofile.x509.jaxb.KeyUsageEnum;
import org.xipki.ca.qa.certprofile.x509.jaxb.KeyUsageType;
import org.xipki.ca.qa.certprofile.x509.jaxb.ObjectFactory;
import org.xipki.ca.qa.certprofile.x509.jaxb.OidWithDescType;
import org.xipki.ca.qa.certprofile.x509.jaxb.PolicyIdMappingType;
import org.xipki.ca.qa.certprofile.x509.jaxb.RSAParametersType;
import org.xipki.ca.qa.certprofile.x509.jaxb.RangeType;
import org.xipki.ca.qa.certprofile.x509.jaxb.RangesType;
import org.xipki.ca.qa.certprofile.x509.jaxb.RdnType;
import org.xipki.ca.qa.certprofile.x509.jaxb.SubjectInfoAccessType;
import org.xipki.ca.qa.certprofile.x509.jaxb.SubjectInfoAccessType.Access;
import org.xipki.ca.qa.certprofile.x509.jaxb.X509ProfileType;
import org.xipki.ca.qa.certprofile.x509.jaxb.X509ProfileType.KeyAlgorithms;
import org.xipki.ca.qa.certprofile.x509.jaxb.X509ProfileType.Subject;
import org.xipki.common.ObjectIdentifiers;
import org.xipki.common.SecurityUtil;
import org.xipki.common.XMLUtil;

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
        oidDescMap.put(ObjectIdentifiers.id_extension_pkix_ocsp_nocheck, "pkixOcspNocheck");
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
            URL url = X509CertProfileQA.class.getResource("/xsd/qa-x509certprofile.xsd");
            m.setSchema(schemaFact.newSchema(url));
            m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            m.setProperty("com.sun.xml.internal.bind.indentString", "  ");

            // RootCA
            X509ProfileType profile = CertProfile_RootCA(false);
            marshall(m, profile, "QA-CertProfile_RootCA.xml");

            // RootCA-Cross
            profile = CertProfile_RootCA(true);
            marshall(m, profile, "QA-CertProfile_RootCA_Cross.xml");

            // SubCA
            profile = CertProfile_SubCA();
            marshall(m, profile, "QA-CertProfile_SubCA.xml");

            profile = CertProfile_SubCA_Complex();
            marshall(m, profile, "QA-CertProfile_SubCA_Complex.xml");

            // OCSP
            profile = CertProfile_OCSP();
            marshall(m, profile, "QA-CertProfile_OCSP.xml");

            // TLS
            profile = CertProfile_TLS();
            marshall(m, profile, "QA-CertProfile_TLS.xml");

            // TLS_C
            profile = CertProfile_TLS_C();
            marshall(m, profile, "QA-CertProfile_TLS_C.xml");

            // TLSwithIncSN
            profile = CertProfile_TLSwithIncSN();
            marshall(m, profile, "QA-CertProfile_TLSwithIncSN.xml");

            //gSMC-K
            profile = CertProfile_gSMC_K();
            marshall(m, profile, "QA-CertProfile_gSMC_K.xml");

            //multiple-OUs
            profile = CertProfile_MultipleOUs();
            marshall(m, profile, "QA-CertProfile_multipleOUs.xml");

        }catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    private static void marshall(Marshaller m, X509ProfileType profile, String filename)
    throws Exception
    {
        File file = new File("tmp", filename);
        file.getParentFile().mkdirs();
        JAXBElement<X509ProfileType> root = new ObjectFactory().createX509Profile(profile);
        FileOutputStream out = new FileOutputStream(file);
        try
        {
            m.marshal(root, out);
        } catch(JAXBException e)
        {
            throw XMLUtil.convert(e);
        }
        finally
        {
            out.close();
        }

    }

    private static X509ProfileType CertProfile_RootCA(boolean cross)
    throws Exception
    {
        X509ProfileType profile = getBaseProfile("CertProfile RootCA" + (cross ? " Cross" : ""),
                true, "10y", false);

        // Subject
        Subject subject = profile.getSubject();

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1, new String[]{"DE|FR"}));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1, new String[]{REGEX_SN}));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1, null));

        // Extensions
        // Extensions - general
        ExtensionsType extensions = profile.getExtensions();

        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true, false, false));
        if(cross)
        {
            list.add(createExtension(Extension.authorityKeyIdentifier, true, false, false));
        }
        list.add(createExtension(Extension.authorityInfoAccess, false, false, false));
        list.add(createExtension(Extension.cRLDistributionPoints, false, false, false));
        list.add(createExtension(Extension.freshestCRL, false, false, false));
        list.add(createExtension(Extension.keyUsage, true, true, true));
        list.add(createExtension(Extension.basicConstraints, true, true, false));

        // Extensions - keyUsage
        KeyUsage keyusage = createRequiredKeyUsages(KeyUsageEnum.KEY_CERT_SIGN);
        keyusage.getUsage().add(createOptionalKeyUsage(KeyUsageEnum.C_RL_SIGN));
        extensions.setKeyUsage(keyusage);
        return profile;
    }

    private static X509ProfileType CertProfile_SubCA()
    throws Exception
    {
        X509ProfileType profile = getBaseProfile("CertProfile SubCA", true, "8y", false);

        // Subject
        Subject subject = profile.getSubject();

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1, new String[]{"DE|FR"}));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1, new String[]{REGEX_SN}));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1, null));

        // Extensions
        // Extensions - general
        ExtensionsType extensions = profile.getExtensions();
        extensions.setPathLen(1);

        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true, false, false));
        list.add(createExtension(Extension.authorityKeyIdentifier, true, false, false));
        list.add(createExtension(Extension.authorityInfoAccess, false, false, false));
        list.add(createExtension(Extension.cRLDistributionPoints, false, false, false));
        list.add(createExtension(Extension.freshestCRL, false, false, false));
        list.add(createExtension(Extension.keyUsage, true, true, true));
        list.add(createExtension(Extension.basicConstraints, true, true, false));

        // Extensions - keyUsage
        KeyUsage keyusage = createRequiredKeyUsages(KeyUsageEnum.KEY_CERT_SIGN);
        keyusage.getUsage().add(createOptionalKeyUsage(KeyUsageEnum.C_RL_SIGN));
        extensions.setKeyUsage(keyusage);

        return profile;
    }

    private static X509ProfileType CertProfile_SubCA_Complex()
    throws Exception
    {
        X509ProfileType profile = getBaseProfile("CertProfile SubCA with most extensions", true, "8y", false);

        // Subject
        Subject subject = profile.getSubject();

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1, new String[]{"DE|FR"}));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1, new String[]{REGEX_SN}));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1, null, "PREFIX ", " SUFFIX"));

        // Extensions
        // Extensions - general
        ExtensionsType extensions = profile.getExtensions();
        extensions.setPathLen(1);

        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true, false, false));
        list.add(createExtension(Extension.authorityKeyIdentifier, true, false, false));
        list.add(createExtension(Extension.authorityInfoAccess, false, false, false));
        list.add(createExtension(Extension.cRLDistributionPoints, false, false, false));
        list.add(createExtension(Extension.freshestCRL, false, false, false));
        list.add(createExtension(Extension.keyUsage, true, true, true));
        list.add(createExtension(Extension.basicConstraints, true, true, false));
        list.add(createExtension(Extension.subjectAlternativeName, true, false, true));
        list.add(createExtension(Extension.subjectInfoAccess, true, false, true));

        list.add(createExtension(Extension.policyMappings, true, true, false));
        list.add(createExtension(Extension.nameConstraints, true, true, false));
        list.add(createExtension(Extension.policyConstraints, true, true, false));
        list.add(createExtension(Extension.inhibitAnyPolicy, true, true, false));

        ASN1ObjectIdentifier customExtensionOid = new ASN1ObjectIdentifier("1.2.3.4");
        list.add(createExtension(customExtensionOid, true, false, false, "custom extension 1"));

        // Extensions - keyUsage
        KeyUsage keyusage = createRequiredKeyUsages(KeyUsageEnum.KEY_CERT_SIGN);
        keyusage.getUsage().add(createOptionalKeyUsage(KeyUsageEnum.C_RL_SIGN));
        extensions.setKeyUsage(keyusage);

        // Certificate Policies
        ExtensionsType.CertificatePolicies certificatePolicies = createCertificatePolicies(
                new ASN1ObjectIdentifier("1.2.3.4.5"), new ASN1ObjectIdentifier("2.4.3.2.1"));
        extensions.setCertificatePolicies(certificatePolicies);

        // Policy Mappings
        PolicyMappings policyMappings = new PolicyMappings();
        extensions.setPolicyMappings(policyMappings);
        policyMappings.getMapping().add(createPolicyIdMapping(
                new ASN1ObjectIdentifier("1.1.1.1.1"),
                new ASN1ObjectIdentifier("2.1.1.1.1")));
        policyMappings.getMapping().add(createPolicyIdMapping(
                new ASN1ObjectIdentifier("1.1.1.1.2"),
                new ASN1ObjectIdentifier("2.1.1.1.2")));

        // Policy Constraints
        extensions.setPolicyConstraints(createPolicyConstraints(2, 2));

        // Name Constrains
        extensions.setNameConstraints(createNameConstraints());

        // Inhibit anyPolicy
        extensions.setInhibitAnyPolicy(createInhibitAnyPolicy(1));

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
        extensions.setConstantExtensions(constantExts);

        ConstantExtensionType constantExt = new ConstantExtensionType();
        constantExts.getConstantExtension().add(constantExt);

        OidWithDescType type = createOidType(customExtensionOid, "custom extension 1");
        constantExt.setType(type);
        constantExt.setValue(DERNull.INSTANCE.getEncoded());

        return profile;
    }

    private static X509ProfileType CertProfile_OCSP()
    throws Exception
    {
        X509ProfileType profile = getBaseProfile("CertProfile OCSP", false, "5y", false);

        // Subject
        Subject subject = profile.getSubject();

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1, new String[]{"DE|FR"}));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1, new String[]{REGEX_SN}));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1, null));

        // Extensions
        // Extensions - general
        ExtensionsType extensions = profile.getExtensions();

        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true, false, false));
        list.add(createExtension(Extension.authorityKeyIdentifier, true, false, false));
        list.add(createExtension(Extension.authorityInfoAccess, false, false, false));
        list.add(createExtension(Extension.cRLDistributionPoints, false, false, false));
        list.add(createExtension(Extension.freshestCRL, false, false, false));
        list.add(createExtension(Extension.keyUsage, true, true, true));
        list.add(createExtension(Extension.basicConstraints, true, true, false));
        list.add(createExtension(Extension.extendedKeyUsage, true, false, true));
        list.add(createExtension(ObjectIdentifiers.id_extension_pkix_ocsp_nocheck, false,false, false));

        // Extensions - keyUsage
        extensions.setKeyUsage(createRequiredKeyUsages(KeyUsageEnum.CONTENT_COMMITMENT));

        // Extensions - extenedKeyUsage

        extensions.setExtendedKeyUsage(createRequiredExtendedKeyUsage(
                ObjectIdentifiers.id_kp_OCSPSigning));

        return profile;
    }

    private static X509ProfileType CertProfile_TLS()
    throws Exception
    {
        X509ProfileType profile = getBaseProfile("CertProfile TLS", false, "5y", true);

        // Subject
        Subject subject = profile.getSubject();

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1, new String[]{"DE|FR"}));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1, new String[]{REGEX_SN}));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1, new String[]{REGEX_FQDN}));

        // Extensions
        // Extensions - general
        ExtensionsType extensions = profile.getExtensions();

        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true, false, false));
        list.add(createExtension(Extension.authorityKeyIdentifier, true, false, false));
        list.add(createExtension(Extension.authorityInfoAccess, false, false, false));
        list.add(createExtension(Extension.cRLDistributionPoints, false, false, false));
        list.add(createExtension(Extension.freshestCRL, false, false, false));
        list.add(createExtension(Extension.keyUsage, true, true, true));
        list.add(createExtension(Extension.basicConstraints, true, true, false));
        list.add(createExtension(Extension.extendedKeyUsage, true, false, true));
        list.add(createExtension(ObjectIdentifiers.id_extension_admission, true, false, false));

        // Extensions - keyUsage
        KeyUsage keyusage = createRequiredKeyUsages(KeyUsageEnum.DIGITAL_SIGNATURE,
                KeyUsageEnum.DATA_ENCIPHERMENT,  KeyUsageEnum.KEY_ENCIPHERMENT);
        extensions.setKeyUsage(keyusage);

        // Extensions - extenedKeyUsage
        ExtendedKeyUsage extKeyUsage = createRequiredExtendedKeyUsage(ObjectIdentifiers.id_kp_serverAuth);
        extKeyUsage.getUsage().add(createExtKeyUsage(ObjectIdentifiers.id_kp_clientAuth, false));
        extensions.setExtendedKeyUsage(extKeyUsage);

        // Admission - just DEMO, does not belong to TLS certificate
        Admission admission = createAdmission(new ASN1ObjectIdentifier("1.1.1.2"), "demo item");
        extensions.setAdmission(admission);

        return profile;
    }

    private static X509ProfileType CertProfile_TLS_C()
    throws Exception
    {
        X509ProfileType profile = getBaseProfile("CertProfile TLS_C", false, "5y", false);

        // Subject
        Subject subject = profile.getSubject();

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1, new String[]{"DE|FR"}));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1, new String[]{REGEX_SN}));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1, null));

        // Extensions
        // Extensions - general
        ExtensionsType extensions = profile.getExtensions();
        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true, false, false));
        list.add(createExtension(Extension.authorityKeyIdentifier, true, false, false));
        list.add(createExtension(Extension.authorityInfoAccess, false, false, false));
        list.add(createExtension(Extension.cRLDistributionPoints, false, false, false));
        list.add(createExtension(Extension.freshestCRL, false, false, false));
        list.add(createExtension(Extension.keyUsage, true, true, true));
        list.add(createExtension(Extension.basicConstraints, true, true, false));
        list.add(createExtension(Extension.extendedKeyUsage, true, false, true));

        // Extensions - keyUsage
        KeyUsage keyusage = createRequiredKeyUsages(KeyUsageEnum.DIGITAL_SIGNATURE,
                KeyUsageEnum.DATA_ENCIPHERMENT,  KeyUsageEnum.KEY_ENCIPHERMENT);
        extensions.setKeyUsage(keyusage);

        // Extensions - extenedKeyUsage
        ExtendedKeyUsage extKeyUsage = createRequiredExtendedKeyUsage(ObjectIdentifiers.id_kp_clientAuth);
        extensions.setExtendedKeyUsage(extKeyUsage);

        return profile;
    }

    private static X509ProfileType CertProfile_TLSwithIncSN()
    throws Exception
    {
        X509ProfileType profile = getBaseProfile("CertProfile TLSwithIncSN", false, "5y", false);

        // Subject
        Subject subject = profile.getSubject();

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1, new String[]{"DE|FR"}));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1, null));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1, new String[]{REGEX_SN}));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1, new String[]{REGEX_FQDN}));

        // Extensions
        // Extensions - general
        ExtensionsType extensions = profile.getExtensions();

        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true, false, false));
        list.add(createExtension(Extension.authorityKeyIdentifier, true, false, false));
        list.add(createExtension(Extension.authorityInfoAccess, false, false, false));
        list.add(createExtension(Extension.cRLDistributionPoints, false, false, false));
        list.add(createExtension(Extension.freshestCRL, false, false, false));
        list.add(createExtension(Extension.keyUsage, true, true, true));
        list.add(createExtension(Extension.basicConstraints, true, true, false));
        list.add(createExtension(Extension.extendedKeyUsage, true, false, true));

        // Extensions - keyUsage
        KeyUsage keyusage = createRequiredKeyUsages(KeyUsageEnum.DIGITAL_SIGNATURE,
                KeyUsageEnum.DATA_ENCIPHERMENT,  KeyUsageEnum.KEY_ENCIPHERMENT);
        extensions.setKeyUsage(keyusage);

        // Extensions - extenedKeyUsage
        ExtendedKeyUsage extKeyUsage = createRequiredExtendedKeyUsage(ObjectIdentifiers.id_kp_serverAuth);
        extKeyUsage.getUsage().add(createExtKeyUsage(ObjectIdentifiers.id_kp_clientAuth, false));
        extensions.setExtendedKeyUsage(extKeyUsage);

        return profile;
    }

    private static RdnType createRDN(ASN1ObjectIdentifier type, int min, int max, String[] regexArrays)
    {
        return createRDN(type, min, max, regexArrays, null, null);
    }

    private static RdnType createRDN(ASN1ObjectIdentifier type, int min, int max, String[] regexArrays,
            String prefix, String suffix)
    {
        RdnType ret = new RdnType();
        ret.setType(createOidType(type));
        ret.setMinOccurs(min);
        ret.setMaxOccurs(max);
        ret.setPrefix(prefix);
        ret.setSuffix(suffix);
        if(regexArrays != null)
        {
            if(regexArrays.length != max)
            {
                throw new IllegalArgumentException("regexArrays.length " + regexArrays.length + " != max " + max);
            }
            for(String regex : regexArrays)
            {
                ret.getRegex().add(regex);
            }
        }
        return ret;
    }

    private static ExtensionType createExtension(ASN1ObjectIdentifier type, boolean required,
            boolean critical, boolean permittedInRequest)
    {
        return createExtension(type, required, critical, permittedInRequest, null);
    }

    private static ExtensionType createExtension(ASN1ObjectIdentifier type, boolean required, boolean critical,
            boolean permittedInRequest, String description)
    {
        ExtensionType ret = new ExtensionType();
        ret.setValue(type.getId());
        ret.setRequired(required);
        ret.setCritical(critical);
        ret.setPermittedInRequest(permittedInRequest);
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

    private static X509ProfileType CertProfile_gSMC_K()
    throws Exception
    {
        X509ProfileType profile = getBaseProfile("CertProfile gSMC_K", false, "5y", false);

        profile.setSpecialBehavior("gematik_gSMC_K");

        // Subject
        Subject subject = profile.getSubject();

        List<RdnType> rdns = subject.getRdn();
        rdns.add(createRDN(ObjectIdentifiers.DN_C, 1, 1, new String[]{"DE"}));
        rdns.add(createRDN(ObjectIdentifiers.DN_O, 1, 1, null));
        rdns.add(createRDN(ObjectIdentifiers.DN_OU, 0, 1, null));
        rdns.add(createRDN(ObjectIdentifiers.DN_ST, 0, 1, null));
        rdns.add(createRDN(ObjectIdentifiers.DN_L, 0, 1, null));
        rdns.add(createRDN(ObjectIdentifiers.DN_POSTAL_CODE, 0, 1, null));
        rdns.add(createRDN(ObjectIdentifiers.DN_STREET, 0, 1, null));
        // regex: ICCSN-yyyyMMdd
        String regex = "80276[\\d]{15,15}-20\\d\\d(0[1-9]|1[012])(0[1-9]|[12][0-9]|3[01])";
        rdns.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1, new String[]{regex}));

        // Extensions
        // Extensions - general
        ExtensionsType extensions = profile.getExtensions();

        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true, false, false));
        list.add(createExtension(Extension.authorityKeyIdentifier, true, false, false));
        list.add(createExtension(Extension.authorityInfoAccess, true, false, false));
        list.add(createExtension(Extension.cRLDistributionPoints, false, false, false));
        list.add(createExtension(Extension.keyUsage, true, true, true));
        list.add(createExtension(Extension.subjectAlternativeName, false, false, true));
        list.add(createExtension(Extension.basicConstraints, true, true, false));
        list.add(createExtension(Extension.certificatePolicies, true, false, false));
        list.add(createExtension(ObjectIdentifiers.id_extension_admission, true, false, false));
        list.add(createExtension(Extension.extendedKeyUsage, true, false, true));

        // Extensions - keyUsage
        extensions.setKeyUsage(createRequiredKeyUsages(KeyUsageEnum.DIGITAL_SIGNATURE, KeyUsageEnum.KEY_ENCIPHERMENT));

        // Extensions - extenedKeyUsage
        ExtendedKeyUsage extKeyUsage = createRequiredExtendedKeyUsage(ObjectIdentifiers.id_kp_serverAuth);
        extKeyUsage.getUsage().add(createExtKeyUsage(ObjectIdentifiers.id_kp_clientAuth, false));
        extensions.setExtendedKeyUsage(extKeyUsage);

        // Extensions - Policy
        CertificatePolicies policies = new CertificatePolicies();
        extensions.setCertificatePolicies(policies);

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
        extensions.setAdmission(admission);
        admission.getProfessionOid().add(createOidType(id_gematik.branch("103")));
        admission.getProfessionItem().add("Anwendungskonnektor");

        return profile;
    }

    private static X509ProfileType CertProfile_MultipleOUs()
    throws Exception
    {
        X509ProfileType profile = getBaseProfile("CertProfile Multiple OUs DEMO", false, "5y", false);

        // Subject
        Subject subject = profile.getSubject();

        List<RdnType> occurrences = subject.getRdn();
        occurrences.add(createRDN(ObjectIdentifiers.DN_C, 1, 1, new String[]{"DE|FR"}));
        occurrences.add(createRDN(ObjectIdentifiers.DN_O, 1, 1, null));

        final String regex_ou1 = "[A-Z]{1,1}[\\d]{5,5}";
        final String regex_ou2 = "[\\d]{5,5}";
        occurrences.add(createRDN(ObjectIdentifiers.DN_OU, 2, 2, new String[]{regex_ou1,regex_ou2}));
        occurrences.add(createRDN(ObjectIdentifiers.DN_SN, 0, 1, new String[]{REGEX_SN}));
        occurrences.add(createRDN(ObjectIdentifiers.DN_CN, 1, 1, null));

        // Extensions
        // Extensions - general
        ExtensionsType extensions = profile.getExtensions();

        // Extensions - occurrences
        List<ExtensionType> list = extensions.getExtension();
        list.add(createExtension(Extension.subjectKeyIdentifier, true, false, false));
        list.add(createExtension(Extension.authorityKeyIdentifier, true, false, false));
        list.add(createExtension(Extension.authorityInfoAccess, false, false, false));
        list.add(createExtension(Extension.cRLDistributionPoints, false, false, false));
        list.add(createExtension(Extension.freshestCRL, false, false, false));
        list.add(createExtension(Extension.keyUsage, true, true, true));
        list.add(createExtension(Extension.basicConstraints, true, true, false));

        // Extensions - keyUsage
        extensions.setKeyUsage(createRequiredKeyUsages(KeyUsageEnum.CONTENT_COMMITMENT));

        return profile;
    }

    private static X509ProfileType getBaseProfile(String description, boolean ca,
            String validity, boolean useMidnightNotBefore)
    {
        X509ProfileType profile = new X509ProfileType();
        profile.setDescription(description);
        profile.setCa(ca);
        profile.setVersion(3);
        profile.setValidity(validity);
        profile.setNotBeforeTime(useMidnightNotBefore ? "midnight" : "current");

        // Subject
        Subject subject = new Subject();
        profile.setSubject(subject);

        // Key
        profile.setKeyAlgorithms(createKeyAlgorithms());

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

            rsa.getAlgorithm().add(createOidType(PKCSObjectIdentifiers.rsaEncryption, "RSA"));
            rsa.setRSAParameters(new RSAParametersType());
            RangesType ranges = new RangesType();
            rsa.getRSAParameters().setModulusLength(ranges);

            List<RangeType> modulusLengths = ranges.getRange();
            modulusLengths.add(createRange(2048));
            modulusLengths.add(createRange(3072));
        }

        // DSA
        {
            AlgorithmType dsa = new AlgorithmType();
            list.add(dsa);

            dsa.getAlgorithm().add(createOidType(X9ObjectIdentifiers.id_dsa, "DSA"));
            dsa.setDSAParameters(new DSAParametersType());

            RangesType ranges = new RangesType();
            dsa.getDSAParameters().setPLength(ranges);

            List<RangeType> pLengths = ranges.getRange();
            pLengths.add(createRange(1024));
            pLengths.add(createRange(2048));

            ranges = new RangesType();
            dsa.getDSAParameters().setQLength(ranges);
            List<RangeType> qLengths = ranges.getRange();
            qLengths.add(createRange(160));
            qLengths.add(createRange(224));
            qLengths.add(createRange(256));
        }

        // EC
        {
            AlgorithmType ec = new AlgorithmType();
            ec.getAlgorithm().add(createOidType(X9ObjectIdentifiers.id_ecPublicKey, "EC"));

            list.add(ec);

            ec.setECParameters(new ECParametersType());
            Curves curves = new Curves();
            ec.getECParameters().setCurves(curves);

            ASN1ObjectIdentifier[] curveIds = new ASN1ObjectIdentifier[]
            {
                SECObjectIdentifiers.secp256r1, TeleTrusTObjectIdentifiers.brainpoolP256r1
            };

            for(ASN1ObjectIdentifier curveId : curveIds)
            {
                String name = SecurityUtil.getCurveName(curveId);
                curves.getCurve().add(createOidType(curveId, name));
            }

            ec.getECParameters().setPointEncodings(new PointEncodings());
            final Byte unpressed = 4;
            ec.getECParameters().getPointEncodings().getPointEncoding().add(unpressed);
        }

        return ret;
    }

    private static RangeType createRange(Integer size)
    {
        return createRange(size, size);
    }

    private static RangeType createRange(Integer min, Integer max)
    {
        RangeType range = new RangeType();
        if(min != null)
        {
            range.setMin(min);
        }
        if(max != null)
        {
            range.setMax(max);
        }
        return range;
    }

    private static KeyUsage createRequiredKeyUsages(KeyUsageEnum... keyUsage)
    {
        KeyUsage ret = new KeyUsage();
        for(KeyUsageEnum usage : keyUsage)
        {
            org.xipki.ca.qa.certprofile.x509.jaxb.KeyUsageType type =
                    new org.xipki.ca.qa.certprofile.x509.jaxb.KeyUsageType();
            type.setRequired(true);
            type.setValue(usage);
            ret.getUsage().add(type);
        }

        return ret;
    }

    private static KeyUsageType createOptionalKeyUsage(KeyUsageEnum usage)
    {
        KeyUsageType type = new KeyUsageType();
        type.setValue(usage);
        type.setRequired(false);
        return type;
    }

    private static ExtendedKeyUsage createRequiredExtendedKeyUsage(
            ASN1ObjectIdentifier... extKeyUsages)
    {
        ExtendedKeyUsage ret = new ExtendedKeyUsage();
        for(ASN1ObjectIdentifier usage : extKeyUsages)
        {
            ret.getUsage().add(createExtKeyUsage(usage, true));
        }
        return ret;
    }

    private static Usage createExtKeyUsage(ASN1ObjectIdentifier usage, boolean required)
    {
        Usage type = new Usage();
        type.setValue(usage.getId());
        type.setRequired(required);
        String desc = getDescription(usage);
        if(desc != null)
        {
            type.setDescription(desc);
        }
        return type;
    }

}
