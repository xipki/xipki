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

package org.xipki.ca.qa;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.CertprofileException;
import org.xipki.ca.api.EnvironmentParameterResolver;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.api.profile.DirectoryStringType;
import org.xipki.ca.api.profile.ExtensionControl;
import org.xipki.ca.api.profile.GeneralNameMode;
import org.xipki.ca.api.profile.KeyParametersOption;
import org.xipki.ca.api.profile.KeyParametersOption.AllowAllParametersOption;
import org.xipki.ca.api.profile.KeyParametersOption.DSAParametersOption;
import org.xipki.ca.api.profile.KeyParametersOption.ECParamatersOption;
import org.xipki.ca.api.profile.KeyParametersOption.RSAParametersOption;
import org.xipki.ca.api.profile.KeyParametersOption.Range;
import org.xipki.ca.api.profile.RDNControl;
import org.xipki.ca.api.profile.x509.ExtKeyUsageControl;
import org.xipki.ca.api.profile.x509.KeyUsageControl;
import org.xipki.ca.api.profile.x509.X509Certprofile;
import org.xipki.ca.api.profile.x509.X509CertVersion;
import org.xipki.ca.certprofile.internal.AddText;
import org.xipki.ca.certprofile.internal.AuthorityKeyIdentifierOption;
import org.xipki.ca.certprofile.internal.ExtKeyUsageOptions;
import org.xipki.ca.certprofile.internal.KeyUsageOptions;
import org.xipki.ca.certprofile.internal.SubjectDNOption;
import org.xipki.ca.certprofile.internal.XmlX509CertprofileUtil;
import org.xipki.ca.certprofile.internal.x509.jaxb.ConstantExtensionType;
import org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType;
import org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.Admission;
import org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.CertificatePolicies;
import org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.ConstantExtensions;
import org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.ExtendedKeyUsage;
import org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.InhibitAnyPolicy;
import org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.NameConstraints;
import org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.PolicyConstraints;
import org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.PolicyMappings;
import org.xipki.ca.certprofile.internal.x509.jaxb.RangeType;
import org.xipki.ca.certprofile.internal.x509.jaxb.RangesType;
import org.xipki.ca.certprofile.internal.x509.jaxb.RdnType;
import org.xipki.ca.certprofile.internal.x509.jaxb.SubjectInfoAccessType.Access;
import org.xipki.ca.certprofile.internal.x509.jaxb.X509ProfileType;
import org.xipki.ca.certprofile.internal.x509.jaxb.X509ProfileType.Subject;
import org.xipki.ca.qa.internal.QaAdmissionOption;
import org.xipki.ca.qa.internal.QaCertificatePoliciesOption;
import org.xipki.ca.qa.internal.QaCertificatePoliciesOption.QaCertificatePolicyInformation;
import org.xipki.ca.qa.internal.QaConstantExtensionOption;
import org.xipki.ca.qa.internal.QaExtensionOption;
import org.xipki.ca.qa.internal.QaExtensionOptions;
import org.xipki.ca.qa.internal.QaExtensionValue;
import org.xipki.ca.qa.internal.QaGeneralSubtree;
import org.xipki.ca.qa.internal.QaInhibitAnyPolicyOption;
import org.xipki.ca.qa.internal.QaNameConstraintsOption;
import org.xipki.ca.qa.internal.QaPolicyConstraintsOption;
import org.xipki.ca.qa.internal.QaPolicyMappingsOption;
import org.xipki.ca.qa.internal.QaPolicyQualifierInfo;
import org.xipki.ca.qa.internal.QaPolicyQualifierInfo.QaCPSUriPolicyQualifier;
import org.xipki.ca.qa.internal.QaPolicyQualifierInfo.QaUserNoticePolicyQualifierInfo;
import org.xipki.ca.qa.internal.QaPolicyQualifiersOption;
import org.xipki.common.CustomObjectIdentifiers;
import org.xipki.common.HashAlgoType;
import org.xipki.common.HashCalculator;
import org.xipki.common.KeyUsage;
import org.xipki.common.LogUtil;
import org.xipki.common.LruCache;
import org.xipki.common.ObjectIdentifiers;
import org.xipki.common.ParamChecker;
import org.xipki.common.SecurityUtil;
import org.xipki.security.api.ExtensionExistence;

/**
 * @author Lijun Liao
 */

public class X509CertprofileQA
{
    private static final byte[] DERNull = new byte[]{5, 0};
    private static final Logger LOG = LoggerFactory.getLogger(X509CertprofileQA.class);
    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");
    private static final long SECOND = 1000L;

    private static final List<String> allUsages = Arrays.asList(
            KeyUsage.digitalSignature.getName(), // 0
            KeyUsage.contentCommitment.getName(), // 1
            KeyUsage.keyEncipherment.getName(), // 2
            KeyUsage.dataEncipherment.getName(), // 3
            KeyUsage.keyAgreement.getName(), // 4
            KeyUsage.keyCertSign.getName(), // 5
            KeyUsage.cRLSign.getName(), // 6
            KeyUsage.encipherOnly.getName(), // 7
            KeyUsage.decipherOnly.getName() // 8
        );

    private String specialBehavior;

    private Map<ASN1ObjectIdentifier, KeyParametersOption> keyAlgorithms;

    private Map<ASN1ObjectIdentifier, SubjectDNOption> subjectDNOptions;
    private Set<RDNControl> subjectDNControls;
    private Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls;

    private CertValidity validity;
    private X509CertVersion version;
    private Set<ASN1ObjectIdentifier> signatureAlgorithms;
    private boolean ca;
    private boolean notBeforeMidnight;
    private Integer pathLen;
    private KeyUsageOptions keyusages;
    private ExtKeyUsageOptions extendedKeyusages;
    private Set<GeneralNameMode> allowedSubjectAltNameModes;
    private Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> allowedSubjectInfoAccessModes;

    private AuthorityKeyIdentifierOption akiOption;
    private QaExtensionOptions certificatePolicies;
    private QaExtensionOptions policyMappings;
    private QaExtensionOptions nameConstraints;
    private QaExtensionOptions policyConstraints;
    private QaExtensionOptions inhibitAnyPolicy;
    private QaExtensionOptions admission;

    private Map<ASN1ObjectIdentifier, QaExtensionOptions> constantExtensions;

    private static LruCache<ASN1ObjectIdentifier, Integer> ecCurveFieldSizes = new LruCache<>(100);

    public X509CertprofileQA(String data)
    throws CertprofileException
    {
        this(data.getBytes());
    }

    public X509CertprofileQA(byte[] dataBytes)
    throws CertprofileException
    {
        try
        {
            X509ProfileType conf = XmlX509CertprofileUtil.parse(new ByteArrayInputStream(dataBytes));

            this.version = X509CertVersion.getInstance(conf.getVersion());
            if(this.version == null)
            {
                throw new CertprofileException("invalid version " + conf.getVersion());
            }

            if(conf.getSignatureAlgorithms() != null)
            {
                this.signatureAlgorithms = XmlX509CertprofileUtil.toOIDSet(
                        conf.getSignatureAlgorithms().getAlgorithm());
            }

            this.validity = CertValidity.getInstance(conf.getValidity());
            this.ca = conf.isCa();
            this.notBeforeMidnight = "midnight".equalsIgnoreCase(conf.getNotBeforeTime());
            this.specialBehavior = conf.getSpecialBehavior();
            if(this.specialBehavior != null && "gematik_gSMC_K".equalsIgnoreCase(this.specialBehavior) == false)
            {
                throw new CertprofileException("unknown special bahavior " + this.specialBehavior);
            }

            // KeyAlgorithms
            if(conf.getKeyAlgorithms() != null)
            {
                this.keyAlgorithms = XmlX509CertprofileUtil.buildKeyAlgorithms(conf.getKeyAlgorithms());
            }

            // Subject
            if(conf.getSubject() != null)
            {
                Subject subject = conf.getSubject();

                this.subjectDNControls = new HashSet<RDNControl>();
                this.subjectDNOptions = new HashMap<>();

                for(RdnType t : subject.getRdn())
                {
                    DirectoryStringType directoryStringEnum = null;
                    if(t.getDirectoryStringType() != null)
                    {
                        switch(t.getDirectoryStringType())
                        {
                            case BMP_STRING:
                                directoryStringEnum = DirectoryStringType.bmpString;
                                break;
                            case PRINTABLE_STRING:
                                directoryStringEnum = DirectoryStringType.printableString;
                                break;
                            case TELETEX_STRING:
                                directoryStringEnum = DirectoryStringType.teletexString;
                                break;
                            case UTF_8_STRING:
                                directoryStringEnum = DirectoryStringType.utf8String;
                                break;
                            default:
                                throw new RuntimeException("should not reach here");
                        }
                    }
                    ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(t.getType().getValue());
                    RDNControl occ = new RDNControl(type,
                            getInt(t.getMinOccurs(), 1), getInt(t.getMaxOccurs(), 1), directoryStringEnum);
                    this.subjectDNControls.add(occ);

                    List<Pattern> patterns = null;
                    if(t.getRegex().isEmpty() == false)
                    {
                        patterns = new LinkedList<>();
                        for(String regex : t.getRegex())
                        {
                            Pattern pattern = Pattern.compile(regex);
                            patterns.add(pattern);
                        }
                    }

                    List<AddText> addprefixes = XmlX509CertprofileUtil.buildAddText(t.getAddPrefix());
                    List<AddText> addsuffixes = XmlX509CertprofileUtil.buildAddText(t.getAddSuffix());
                    SubjectDNOption option = new SubjectDNOption(addprefixes, addsuffixes, patterns,
                            t.getMinLen(), t.getMaxLen());
                    this.subjectDNOptions.put(type, option);
                }
            }

            // Extensions
            ExtensionsType extensionsType = conf.getExtensions();
            this.pathLen = extensionsType.getPathLen();

            // Extension controls
            this.extensionControls = XmlX509CertprofileUtil.buildExtensionControls(extensionsType);

            // Extension KeyUsage
            if(extensionControls.containsKey(Extension.keyUsage))
            {
                List<org.xipki.ca.certprofile.internal.x509.jaxb.ExtensionsType.KeyUsage> keyUsageTypeList =
                        extensionsType.getKeyUsage();
                if(keyUsageTypeList.isEmpty() == false)
                {
                    this.keyusages = XmlX509CertprofileUtil.buildKeyUsageOptions(keyUsageTypeList);
                }
            }

            // ExtendedKeyUsage
            if(extensionControls.containsKey(Extension.extendedKeyUsage))
            {
                List<ExtendedKeyUsage> extKeyUsageTypeList = extensionsType.getExtendedKeyUsage();
                if(extKeyUsageTypeList.isEmpty() == false)
                {
                    this.extendedKeyusages = XmlX509CertprofileUtil.buildExtKeyUsageOptions(
                            extKeyUsageTypeList);
                }
            }

            // AuthorityKeyIdentifier
            {
                ExtensionControl extensionControl = extensionControls.get(Extension.authorityKeyIdentifier);
                if(extensionControl != null)
                {
                    this.akiOption = XmlX509CertprofileUtil.buildAuthorityKeyIdentifier(
                            extensionsType.getAuthorityKeyIdentifier(),
                            extensionControl);
                }
            }

            // Certificate Policies
            {
                ExtensionControl extensionControl = extensionControls.get(Extension.certificatePolicies);
                List<CertificatePolicies> l1 = extensionsType.getCertificatePolicies();
                if(extensionControl != null && l1.isEmpty() == false)
                {
                    List<QaCertificatePoliciesOption> l2 = new ArrayList<>(l1.size());
                    for(CertificatePolicies m : l1)
                    {
                        l2.add(new QaCertificatePoliciesOption(m));
                    }
                    this.certificatePolicies = new QaExtensionOptions(l2);
                }
            }

            // Policy Mappings
            {
                ExtensionControl extensionControl = extensionControls.get(Extension.policyMappings);
                List<PolicyMappings> l1 = extensionsType.getPolicyMappings();
                if(extensionControl != null && l1.isEmpty() == false)
                {
                    List<QaPolicyMappingsOption> l2 = new ArrayList<>(l1.size());
                    for(PolicyMappings m : l1)
                    {
                        l2.add(new QaPolicyMappingsOption(m));
                    }
                    this.policyMappings = new QaExtensionOptions(l2);
                }
            }

            // Name Constrains
            {
                ExtensionControl extensionControl = extensionControls.get(Extension.nameConstraints);
                List<NameConstraints> l1 = extensionsType.getNameConstraints();
                if(extensionControl != null && l1.isEmpty() == false)
                {
                    List<QaNameConstraintsOption> l2 = new ArrayList<>(l1.size());
                    for(NameConstraints m : l1)
                    {
                        l2.add(new QaNameConstraintsOption(m));
                    }
                    this.nameConstraints = new QaExtensionOptions(l2);
                }
            }

            // Policy Constraints
            {
                ExtensionControl extensionControl = extensionControls.get(Extension.policyConstraints);
                List<PolicyConstraints> l1 = extensionsType.getPolicyConstraints();
                if(extensionControl != null && l1.isEmpty() == false)
                {
                    List<QaPolicyConstraintsOption> l2 = new ArrayList<>(l1.size());
                    for(PolicyConstraints m : l1)
                    {
                        l2.add(new QaPolicyConstraintsOption(m));
                    }
                    this.policyConstraints = new QaExtensionOptions(l2);
                }
            }

            // Inhibit anyPolicy
            {
                ExtensionControl extensionControl = extensionControls.get(Extension.inhibitAnyPolicy);
                List<InhibitAnyPolicy> l1 = extensionsType.getInhibitAnyPolicy();
                if(extensionControl != null && l1.isEmpty() == false)
                {
                    List<QaInhibitAnyPolicyOption> l2 = new ArrayList<>(l1.size());
                    for(InhibitAnyPolicy m : l1)
                    {
                        l2.add(new QaInhibitAnyPolicyOption(m));
                    }
                    this.inhibitAnyPolicy = new QaExtensionOptions(l2);
                }
            }

            // admission
            {
                ExtensionControl extensionControl = extensionControls.get(ObjectIdentifiers.id_extension_admission);
                List<Admission> l1 = extensionsType.getAdmission();
                if(extensionControl != null && l1.isEmpty() == false)
                {
                    List<QaAdmissionOption> l2 = new ArrayList<>(l1.size());
                    for(Admission m : l1)
                    {
                        l2.add(new QaAdmissionOption(m));
                    }
                    this.admission = new QaExtensionOptions(l2);
                }
            }

            // SubjectAltNameMode
            if(extensionsType.getSubjectAltName() != null)
            {
                this.allowedSubjectAltNameModes = XmlX509CertprofileUtil.buildGeneralNameMode(
                        extensionsType.getSubjectAltName());
            }

            // SubjectInfoAccess
            if(extensionsType.getSubjectInfoAccess() != null)
            {
                List<Access> list = extensionsType.getSubjectInfoAccess().getAccess();
                this.allowedSubjectInfoAccessModes = new HashMap<>();
                for(Access entry : list)
                {
                    this.allowedSubjectInfoAccessModes.put(
                            new ASN1ObjectIdentifier(entry.getAccessMethod().getValue()),
                            XmlX509CertprofileUtil.buildGeneralNameMode(entry.getAccessLocation()));
                }
            }
            // constant extensions
            List<ConstantExtensions> cess = extensionsType.getConstantExtensions();
            if(cess != null && cess.isEmpty() == false)
            {
                Map<ASN1ObjectIdentifier, List<QaConstantExtensionOption>> map = new HashMap<>();
                for(ConstantExtensions ces : cess)
                {
                    for(ConstantExtensionType ce :ces.getConstantExtension())
                    {
                        ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(ce.getType().getValue());
                        ExtensionControl control = extensionControls.get(type);
                        if(control != null)
                        {
                            byte[] encodedValue = ce.getValue();
                            QaExtensionValue extension = new QaExtensionValue(control.isCritical(), encodedValue);
                            QaConstantExtensionOption option = new QaConstantExtensionOption(
                                    ce.getCondition(), extension);

                            List<QaConstantExtensionOption> options = map.get(type);
                            if(options == null)
                            {
                                options = new LinkedList<>();
                                map.put(type, options);
                            }
                            options.add(option);
                        }
                    }
                }

                if(map.isEmpty() == false)
                {
                    Map<ASN1ObjectIdentifier, QaExtensionOptions> constantExtensions = new HashMap<>(map.size());
                    for(ASN1ObjectIdentifier type : map.keySet())
                    {
                        List<QaConstantExtensionOption> options = map.get(type);
                        constantExtensions.put(type, new QaExtensionOptions(options));
                    }

                    this.constantExtensions = Collections.unmodifiableMap(constantExtensions);
                }
            }
        }catch(RuntimeException e)
        {
            final String message = "RuntimeException";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            throw new CertprofileException("RuntimeException thrown while initializing certprofile: " + e.getMessage());
        }
    }

    public ValidationResult checkCert(byte[] certBytes, X509IssuerInfo issuerInfo,
            X500Name requestedSubject, SubjectPublicKeyInfo requestedPublicKey,
            Extensions requestedExtensions, EnvironmentParameterResolver pr)
    {
        ParamChecker.assertNotNull("certBytes", certBytes);
        ParamChecker.assertNotNull("issuerInfo", issuerInfo);
        ParamChecker.assertNotNull("requestedSubject", requestedSubject);
        ParamChecker.assertNotNull("requestedPublicKey", requestedPublicKey);

        List<ValidationIssue> resultIssues = new LinkedList<ValidationIssue>();

        Certificate bcCert;
        X509Certificate cert;

        // certificate encoding
        {
            ValidationIssue issue = new ValidationIssue("X509.ENCODING", "certificate encoding");
            resultIssues.add(issue);
            try
            {
                bcCert = Certificate.getInstance(certBytes);
                cert = SecurityUtil.parseCert(certBytes);
            } catch (CertificateException | IOException e)
            {
                issue.setFailureMessage("certificate is not corrected encoded");
                return new ValidationResult(resultIssues);
            }
        }

        // syntax version
        {
            ValidationIssue issue = new ValidationIssue("X509.VERSION", "certificate version");
            resultIssues.add(issue);
            int versionNumber = cert.getVersion();
            if(versionNumber != version.getVersion())
            {
                issue.setFailureMessage("is '" + versionNumber + "' but expected '" + version.getVersion() + "'");
            }
        }

        // signatureAlgorithm
        if(signatureAlgorithms != null && signatureAlgorithms.isEmpty() == false)
        {
            ValidationIssue issue = new ValidationIssue("X509.SIGALG", "signature algorithm");
            resultIssues.add(issue);

            AlgorithmIdentifier sigAlgId = bcCert.getSignatureAlgorithm();
            AlgorithmIdentifier tbsSigAlgId = bcCert.getTBSCertificate().getSignature();
            if(tbsSigAlgId.equals(sigAlgId) == false)
            {
                issue.setFailureMessage("Certificate.tbsCertificate.signature != Certificate.signatureAlgorithm");
            } else
            {
                String sigAlgo = sigAlgId.getAlgorithm().getId();
                if(signatureAlgorithms.contains(sigAlgo) == false)
                {
                    issue.setFailureMessage("signatureAlgorithm '" + sigAlgo + "' is not allowed");
                }
            }
        }

        // notBefore
        if(notBeforeMidnight)
        {
            ValidationIssue issue = new ValidationIssue("X509.NOTBEFORE", "not before midnight");
            resultIssues.add(issue);
            Calendar c = Calendar.getInstance(UTC);
            c.setTime(cert.getNotBefore());
            int hourOfDay = c.get(Calendar.HOUR_OF_DAY);
            int minute = c.get(Calendar.MINUTE);
            int second = c.get(Calendar.SECOND);

            if(hourOfDay != 0 || minute != 0 || second != 0)
            {
                issue.setFailureMessage(" '" + cert.getNotBefore() + "' is not midnight time (UTC)");
            }
        }

        // validity
        {
            ValidationIssue issue = new ValidationIssue("X509.VALIDITY", "cert validity");
            resultIssues.add(issue);

            Date expectedNotAfter = validity.add(cert.getNotBefore());
            if(Math.abs(expectedNotAfter.getTime() - cert.getNotAfter().getTime()) > 60 * SECOND)
            {
                issue.setFailureMessage("cert validity is not within " + validity.toString());
            }
        }

        // public key
        {
            SubjectPublicKeyInfo publicKey = bcCert.getSubjectPublicKeyInfo();
            if(keyAlgorithms != null)
            {
                ValidationIssue issue = new ValidationIssue("X509.PUBKEY.SYN", "whether public key is permitted");
                resultIssues.add(issue);
                try
                {
                    checkPublicKey(publicKey);
                }catch(BadCertTemplateException e)
                {
                    issue.setFailureMessage(e.getMessage());
                }
            }

            ValidationIssue issue = new ValidationIssue("X509.PUBKEY.REQ", "whether public key matches the request one");
            resultIssues.add(issue);
            SubjectPublicKeyInfo c14nRequestedPublicKey;
            try
            {
                c14nRequestedPublicKey = SecurityUtil.toRfc3279Style(requestedPublicKey);
                if(c14nRequestedPublicKey.equals(publicKey) == false)
                {
                    issue.setFailureMessage("public key in the certificate does not equal the requested one");
                }
            } catch (InvalidKeySpecException e)
            {
                issue.setFailureMessage("public key in request is invalid");
            }
        }

        // Signature
        {
            ValidationIssue issue = new ValidationIssue("X509.SIG", "whether certificate is signed by CA");
            resultIssues.add(issue);
            try
            {
                cert.verify(issuerInfo.getCert().getPublicKey(), "BC");
            }catch(Exception e)
            {
                issue.setFailureMessage("invalid signature");
            }
        }

        // issuer
        {
            ValidationIssue issue = new ValidationIssue("X509.ISSUER", "certificate issuer");
            resultIssues.add(issue);
            if(cert.getIssuerX500Principal().equals(issuerInfo.getCert().getSubjectX500Principal()) == false)
            {
                issue.setFailureMessage("issue in certificate does not equal the subject of CA certificate");
            }
        }

        // subject
        X500Name subject = bcCert.getTBSCertificate().getSubject();
        resultIssues.addAll(checkSubject(subject, requestedSubject, pr));

        // extensions
        resultIssues.addAll(checkExtensions(bcCert, cert, issuerInfo, requestedExtensions, pr));

        return new ValidationResult(resultIssues);
    }

    private List<ValidationIssue> checkExtensions(Certificate bcCert, X509Certificate cert,
            X509IssuerInfo issuerInfo, Extensions requestExtensions, EnvironmentParameterResolver pr)
    {
        List<ValidationIssue> result = new LinkedList<>();

        // detect the list of extension types in certificate
        Set<ASN1ObjectIdentifier> presentExtenionTypes = getExensionTypes(bcCert, issuerInfo, requestExtensions,
                pr);

        Extensions extensions = bcCert.getTBSCertificate().getExtensions();
        ASN1ObjectIdentifier[] oids = extensions.getExtensionOIDs();

        if(oids == null)
        {
            ValidationIssue issue = new ValidationIssue("X509.EXT.GEN", "extension general");
            result.add(issue);
            issue.setFailureMessage("no extension is present");
            return result;
        }

        List<ASN1ObjectIdentifier> certExtTypes = Arrays.asList(oids);

        for(ASN1ObjectIdentifier extType : presentExtenionTypes)
        {
            if(certExtTypes.contains(extType) == false)
            {
                ValidationIssue issue = createExtensionIssue(extType);
                result.add(issue);
                issue.setFailureMessage("extension is absent but is required");
            }
        }

        for(ASN1ObjectIdentifier oid : certExtTypes)
        {
            ValidationIssue issue = createExtensionIssue(oid);
            result.add(issue);
            if(presentExtenionTypes.contains(oid) == false)
            {
                issue.setFailureMessage("extension is present but is not permitted");
                continue;
            }

            Extension ext = extensions.getExtension(oid);
            StringBuilder failureMsg = new StringBuilder();
            ExtensionControl extControl = extensionControls.get(oid);

            if(extControl.isCritical() != ext.isCritical())
            {
                failureMsg.append("critical is '" + ext.isCritical() +
                        "' but expected '" + extControl.isCritical() + "'");
                failureMsg.append("; ");
            }

            byte[] extensionValue = ext.getExtnValue().getOctets();

            try
            {
                if(Extension.authorityKeyIdentifier.equals(oid))
                {
                    // AuthorityKeyIdentifier
                    checkExtensionIssuerKeyIdentifier(failureMsg, extensionValue, issuerInfo);
                } else if(Extension.subjectKeyIdentifier.equals(oid))
                {
                    // SubjectKeyIdentifier
                    checkExtensionSubjectKeyIdentifier(failureMsg, extensionValue, bcCert.getSubjectPublicKeyInfo());
                } else if(Extension.keyUsage.equals(oid))
                {
                    // KeyUsage
                    checkExtensionKeyUsage(failureMsg, extensionValue, cert.getKeyUsage(), requestExtensions, extControl, pr);
                } else if(Extension.certificatePolicies.equals(oid))
                {
                    // CertificatePolicies
                    checkExtensionCertificatePolicies(failureMsg, extensionValue, requestExtensions, extControl, pr);
                } else if(Extension.policyMappings.equals(oid))
                {
                    // Policy Mappings
                    checkExtensionPolicyMappings(failureMsg, extensionValue, requestExtensions, extControl, pr);
                } else if(Extension.subjectAlternativeName.equals(oid))
                {
                    // SubjectAltName
                    checkExtensionSubjectAltName(failureMsg, extensionValue, requestExtensions, extControl, pr);
                } else if(Extension.issuerAlternativeName.equals(oid))
                {
                    // IssuerAltName
                    checkExtensionIssuerAltNames(failureMsg,extensionValue, issuerInfo);
                    continue;
                } else if(Extension.basicConstraints.equals(oid))
                {
                    // Basic Constraints
                    checkExtensionBasicConstraints(failureMsg, extensionValue);
                    continue;
                } else if(Extension.nameConstraints.equals(oid))
                {
                    // Name Constraints
                    checkExtensionNameConstraints(failureMsg, extensionValue, extensions, extControl, pr);
                } else if(Extension.policyConstraints.equals(oid))
                {
                    // PolicyConstrains
                    checkExtensionPolicyConstraints(failureMsg, extensionValue, requestExtensions, extControl, pr);
                } else if(Extension.extendedKeyUsage.equals(oid))
                {
                    // ExtendedKeyUsage
                    checkExtensionExtendedKeyUsage(failureMsg, extensionValue, requestExtensions, extControl, pr);
                } else if(Extension.cRLDistributionPoints.equals(oid))
                {
                    // CRL Distribution Points
                    checkExtensionCrlDistributionPoints(failureMsg, extensionValue, issuerInfo);
                    continue;
                } else if(Extension.inhibitAnyPolicy.equals(oid))
                {
                    // Inhibit anyPolicy
                    checkExtensionInhibitAnyPolicy(failureMsg, extensionValue,extensions, extControl, pr);
                } else if(Extension.freshestCRL.equals(oid))
                {
                    // Freshest CRL
                    checkExtensionDeltaCrlDistributionPoints(failureMsg, extensionValue, issuerInfo);
                    continue;
                } else if(Extension.authorityInfoAccess.equals(oid))
                {
                    // Authority Information Access
                    checkExtensionAuthorityInfoAccess(failureMsg, extensionValue, issuerInfo);
                    continue;
                } else if(Extension.subjectInfoAccess.equals(oid))
                {
                    // SubjectInfoAccess
                    checkExtensionSubjectInfoAccess(failureMsg, extensionValue, requestExtensions, extControl, pr);
                } else if(ObjectIdentifiers.id_extension_admission.equals(oid))
                {
                    // Admission
                    checkExtensionAdmission(failureMsg, extensionValue, requestExtensions, extControl, pr);
                } else if(ObjectIdentifiers.id_extension_pkix_ocsp_nocheck.equals(oid))
                {
                    // ocsp-nocheck
                    checkExtensionOcspNocheck(extensionValue, failureMsg);
                    continue;
                } else
                {
                    byte[] expected = getExpectedExtValue(oid, requestExtensions, extControl, pr);
                    if(Arrays.equals(expected, extensionValue) == false)
                    {
                        failureMsg.append("extension valus is '" + hex(extensionValue) +
                                "' but expected '" + (expected == null ? "not present" : hex(expected)) + "'");
                        failureMsg.append("; ");
                    }
                }

                if(failureMsg.length() > 0)
                {
                    issue.setFailureMessage(failureMsg.toString());
                }

            }catch(IllegalArgumentException | ClassCastException | ArrayIndexOutOfBoundsException e)
            {
                LOG.debug("extension value does not have correct syntax", e);
                issue.setFailureMessage("extension value does not have correct syntax");
            }
        }

        return result;
    }

    private byte[] getExpectedExtValue(ASN1ObjectIdentifier type, Extensions requestExtensions,
            ExtensionControl extControl, EnvironmentParameterResolver pr)
    {
        if(extControl.isRequest() && requestExtensions != null)
        {
            Extension reqExt = requestExtensions.getExtension(type);
            if(reqExt != null)
            {
                return reqExt.getExtnValue().getOctets();
            }
        } else if(constantExtensions != null && constantExtensions.containsKey(type))
        {
            QaExtensionOption conf = constantExtensions.get(type).getExtensionConf(pr);
            return ((QaConstantExtensionOption) conf).getExtensionValue().getValue();
        }

        return null;
    }

    private Set<ASN1ObjectIdentifier> getExensionTypes(Certificate cert,
            X509IssuerInfo issuerInfo, Extensions requestedExtensions,
            EnvironmentParameterResolver pr)
    {
        Set<ASN1ObjectIdentifier> types = new HashSet<>();
        // profile required extension types
        for(ASN1ObjectIdentifier oid : extensionControls.keySet())
        {
            if(extensionControls.get(oid).isRequired())
            {
                types.add(oid);
            }
        }

        Set<ASN1ObjectIdentifier> wantedExtensionTypes = new HashSet<>();

        if(requestedExtensions != null)
        {
            Extension reqExtension = requestedExtensions.getExtension(
                    CustomObjectIdentifiers.id_cmp_request_extensions);
            if(reqExtension != null)
            {
                ExtensionExistence ee = ExtensionExistence.getInstance(reqExtension.getParsedValue());
                types.addAll(ee.getNeedExtensions());
                wantedExtensionTypes.addAll(ee.getWantExtensions());
            }
        }

        if(wantedExtensionTypes.isEmpty())
        {
            return types;
        }

        // wanted extension types
        // Authority key identifier
        ASN1ObjectIdentifier type = Extension.authorityKeyIdentifier;
        if(wantedExtensionTypes.contains(type))
        {
            types.add(type);
        }

        // Subject key identifier
        type = Extension.subjectKeyIdentifier;
        if(wantedExtensionTypes.contains(type))
        {
            types.add(type);
        }

        // KeyUsage
        type = Extension.keyUsage;
        if(wantedExtensionTypes.contains(type))
        {
            boolean required = false;
            if(requestedExtensions.getExtension(type) != null)
            {
                required = true;
            }

            if(required == false)
            {
                Set<KeyUsageControl> requiredKeyusage = getKeyusage(true, pr);
                if(requiredKeyusage.isEmpty() == false)
                {
                    required = true;
                }
            }

            if(required)
            {
                types.add(type);
            }
        }

        // CertificatePolicies
        type = Extension.certificatePolicies;
        if(wantedExtensionTypes.contains(type))
        {
            if(certificatePolicies != null &&
                    certificatePolicies.getExtensionConf(pr) != null)
            {
                types.add(type);
            }
        }

        // Policy Mappings
        type = Extension.policyMappings;
        if(wantedExtensionTypes.contains(type))
        {
            if(policyMappings != null &&
                    policyMappings.getExtensionConf(pr) != null)
            {
                types.add(type);
            }
        }

        // SubjectAltNames
        type = Extension.subjectAlternativeName;
        if(wantedExtensionTypes.contains(type))
        {
            if(requestedExtensions.getExtension(type) != null)
            {
                types.add(type);
            }
        }

        // IssuerAltName
        type = Extension.issuerAlternativeName;
        if(wantedExtensionTypes.contains(type))
        {
            if(cert.getTBSCertificate().getExtensions().getExtension(Extension.subjectAlternativeName) != null)
            {
                types.add(type);
            }
        }

        // BasicConstraints
        type = Extension.basicConstraints;
        if(wantedExtensionTypes.contains(type))
        {
            types.add(type);
        }

        // Name Constraints
        type = Extension.nameConstraints;
        if(wantedExtensionTypes.contains(type))
        {
            if(nameConstraints != null &&
                    nameConstraints.getExtensionConf(pr) != null)
            {
                types.add(type);
            }
        }

        // PolicyConstrains
        type = Extension.policyConstraints;
        if(wantedExtensionTypes.contains(type))
        {
            if(policyConstraints != null &&
                    policyConstraints.getExtensionConf(pr) != null)
            {
                types.add(type);
            }
        }

        // ExtendedKeyUsage
        type = Extension.extendedKeyUsage;
        if(wantedExtensionTypes.contains(type))
        {
            boolean required = false;
            if(requestedExtensions.getExtension(type) != null)
            {
                required = true;
            }

            if(required == false)
            {
                Set<ExtKeyUsageControl> requiredExtKeyusage = getExtKeyusage(true, pr);
                if(requiredExtKeyusage.isEmpty() == false)
                {
                    required = true;
                }
            }

            if(required)
            {
                types.add(type);
            }
        }

        // CRLDistributionPoints
        type = Extension.cRLDistributionPoints;
        if(wantedExtensionTypes.contains(type))
        {
            if(issuerInfo.getCrlURLs() != null)
            {
                types.add(type);
            }
        }

        // Inhibit anyPolicy
        type = Extension.inhibitAnyPolicy;
        if(wantedExtensionTypes.contains(type))
        {
            if(inhibitAnyPolicy != null &&
                    inhibitAnyPolicy.getExtensionConf(pr) != null)
            {
                types.add(type);
            }
        }

        // FreshestCRL
        type = Extension.freshestCRL;
        if(wantedExtensionTypes.contains(type))
        {
            if(issuerInfo.getDeltaCrlURLs() != null)
            {
                types.add(type);
            }
        }

        // AuthorityInfoAccess
        type = Extension.authorityInfoAccess;
        if(wantedExtensionTypes.contains(type))
        {
            if(issuerInfo.getOcspURLs() != null)
            {
                types.add(type);
            }
        }

        // SubjectInfoAccess
        type = Extension.subjectInfoAccess;
        if(wantedExtensionTypes.contains(type))
        {
            if(requestedExtensions.getExtension(type) != null)
            {
                types.add(type);
            }
        }

        // Admission
        type = ObjectIdentifiers.id_extension_admission;
        if(wantedExtensionTypes.contains(type))
        {
            if(admission != null &&
                    admission.getExtensionConf(pr) != null)
            {
                types.add(type);
            }
        }

        // ocsp-nocheck
        type = ObjectIdentifiers.id_extension_pkix_ocsp_nocheck;
        if(wantedExtensionTypes.contains(type))
        {
            types.add(type);
        }

        wantedExtensionTypes.removeAll(types);

        for(ASN1ObjectIdentifier oid : wantedExtensionTypes)
        {
            if(requestedExtensions.getExtension(oid) != null)
            {
                QaExtensionOptions options = constantExtensions.get(oid);
                if(options != null &&
                        options.getExtensionConf(pr) != null)
                {
                    types.add(oid);
                }
            }
        }

        return types;
    }

    private void checkPublicKey(SubjectPublicKeyInfo publicKey)
    throws BadCertTemplateException
    {
        if(keyAlgorithms == null || keyAlgorithms.isEmpty())
        {
            return;
        }

        ASN1ObjectIdentifier keyType = publicKey.getAlgorithm().getAlgorithm();
        if(keyAlgorithms.containsKey(keyType) == false)
        {
            throw new BadCertTemplateException("key type " + keyType.getId() + " is not permitted");
        }

        KeyParametersOption keyParamsOption = keyAlgorithms.get(keyType);
        if(keyParamsOption instanceof AllowAllParametersOption)
        {
            return;
        } else if(keyParamsOption instanceof ECParamatersOption)
        {
            ECParamatersOption ecOption = (ECParamatersOption) keyParamsOption;
            // parameters
            ASN1Encodable algParam = publicKey.getAlgorithm().getParameters();
            ASN1ObjectIdentifier curveOid;

            if(algParam instanceof ASN1ObjectIdentifier)
            {
                curveOid = (ASN1ObjectIdentifier) algParam;
                if(ecOption.allowsCurve(curveOid) == false)
                {
                    throw new BadCertTemplateException("EC curve " + SecurityUtil.getCurveName(curveOid) +
                            " (OID: " + curveOid.getId() + ") is not allowed");
                }
            } else
            {
                throw new BadCertTemplateException("Only namedCurve or implictCA EC public key is supported");
            }

            // point encoding
            if(ecOption.getPointEncodings() != null)
            {
                byte[] keyData = publicKey.getPublicKeyData().getBytes();
                if(keyData.length < 1)
                {
                    throw new BadCertTemplateException("invalid publicKeyData");
                }
                byte pointEncoding = keyData[0];
                if(ecOption.getPointEncodings().contains(pointEncoding) == false)
                {
                    throw new BadCertTemplateException("Unaccepted EC point encoding " + pointEncoding);
                }
            }

            try
            {
                checkECSubjectPublicKeyInfo(curveOid, publicKey.getPublicKeyData().getBytes());
            }catch(BadCertTemplateException e)
            {
                throw e;
            }catch(Exception e)
            {
                LOG.debug("populateFromPubKeyInfo", e);
                throw new BadCertTemplateException("Invalid public key: " + e.getMessage());
            }

            return;
        } else if(keyParamsOption instanceof RSAParametersOption)
        {
            RSAParametersOption rsaOption = (RSAParametersOption) keyParamsOption;

            ASN1Integer modulus;
            try
            {
                ASN1Sequence seq = ASN1Sequence.getInstance(publicKey.getPublicKeyData().getBytes());
                modulus = ASN1Integer.getInstance(seq.getObjectAt(0));
            }catch(IllegalArgumentException e)
            {
                throw new BadCertTemplateException("invalid publicKeyData");
            }

            int modulusLength = modulus.getPositiveValue().bitLength();
            if((rsaOption.allowsModulusLength(modulusLength)))
            {
                return;
            }
        } else if(keyParamsOption instanceof DSAParametersOption)
        {
            DSAParametersOption dsaOption = (DSAParametersOption) keyParamsOption;
            ASN1Encodable params = publicKey.getAlgorithm().getParameters();
            if(params == null)
            {
                throw new BadCertTemplateException("null Dss-Parms is not permitted");
            }

            int pLength;
            int qLength;

            try
            {
                ASN1Sequence seq = ASN1Sequence.getInstance(params);
                ASN1Integer p = ASN1Integer.getInstance(seq.getObjectAt(0));
                ASN1Integer q = ASN1Integer.getInstance(seq.getObjectAt(1));
                pLength = p.getPositiveValue().bitLength();
                qLength = q.getPositiveValue().bitLength();
            } catch(IllegalArgumentException | ArrayIndexOutOfBoundsException e)
            {
                throw new BadCertTemplateException("illegal Dss-Parms");
            }

            boolean match = dsaOption.allowsPLength(pLength);
            if(match)
            {
                match = dsaOption.allowsQLength(qLength);
            }

            if(match)
            {
                return;
            }
        } else
        {
            throw new RuntimeException("should not reach here");
        }

        throw new BadCertTemplateException("the given publicKey is not permitted");
    }

    private static void checkECSubjectPublicKeyInfo(ASN1ObjectIdentifier curveOid, byte[] encoded)
    throws BadCertTemplateException
    {
        Integer expectedLength = ecCurveFieldSizes.get(curveOid);
        if(expectedLength == null)
        {
            X9ECParameters ecP = ECUtil.getNamedCurveByOid(curveOid);
            ECCurve curve = ecP.getCurve();
            expectedLength = (curve.getFieldSize() + 7) / 8;
            ecCurveFieldSizes.put(curveOid, expectedLength);
        }

        switch (encoded[0])
        {
            case 0x02: // compressed
            case 0x03: // compressed
            {
                if (encoded.length != (expectedLength + 1))
                {
                    throw new BadCertTemplateException("Incorrect length for compressed encoding");
                }
                break;
            }
            case 0x04: // uncompressed
            case 0x06: // hybrid
            case 0x07: // hybrid
            {
                if (encoded.length != (2 * expectedLength + 1))
                {
                    throw new BadCertTemplateException("Incorrect length for uncompressed/hybrid encoding");
                }
                break;
            }
            default:
                throw new BadCertTemplateException("Invalid point encoding 0x" + Integer.toString(encoded[0], 16));
        }
    }

    private List<ValidationIssue> checkSubject(X500Name subject, X500Name requestedSubject,
            EnvironmentParameterResolver pr)
    {
        // collect subject attribute types to check
        Set<ASN1ObjectIdentifier> oids = new HashSet<>();

        for(ASN1ObjectIdentifier oid : subjectDNOptions.keySet())
        {
            oids.add(oid);
        }

        for(ASN1ObjectIdentifier oid : subject.getAttributeTypes())
        {
            oids.add(oid);
        }

        List<ValidationIssue> result = new LinkedList<>();
        for(ASN1ObjectIdentifier type : oids)
        {
            ValidationIssue issue = checkSubjectAttribute(type, subject, requestedSubject, pr);
            result.add(issue);
        }

        return result;
    }

    private ValidationIssue checkSubjectAttribute(ASN1ObjectIdentifier type,
            X500Name subject, X500Name requestedSubject, EnvironmentParameterResolver pr)
    {
        ValidationIssue issue = createSubjectIssue(type);

        // control
        int minOccurs;
        int maxOccurs;
        RDNControl rdnControl = getSubjectDNControl(type);
        if(rdnControl == null)
        {
            minOccurs = 0;
            maxOccurs = 0;
        } else
        {
            minOccurs = rdnControl.getMinOccurs();
            maxOccurs = rdnControl.getMaxOccurs();
        }
        RDN[] rdns = subject.getRDNs(type);
        int rdnsSize = rdns == null ? 0 : rdns.length;

        if(rdnsSize < minOccurs || rdnsSize > maxOccurs)
        {
            issue.setFailureMessage("number of RDNs '" + rdnsSize +
                    "' is not within [" + minOccurs + ", " + maxOccurs + "]");
            return issue;
        }

        RDN[] requestedRdns = requestedSubject.getRDNs(type);

        if(rdnsSize == 0)
        {
            // check optional attribute but is present in requestedSubject
            if(maxOccurs > 0 && requestedRdns != null && requestedRdns.length > 0)
            {
                issue.setFailureMessage("is absent but expected present");
            }
            return issue;
        }

        SubjectDNOption rdnOption = subjectDNOptions.get(type);

        // check the encoding
        DirectoryStringType stringType = rdnControl.getDirectoryStringEnum();
        if(stringType == null)
        {
            if(ObjectIdentifiers.DN_C.equals(type) || ObjectIdentifiers.DN_SERIALNUMBER.equals(type))
            {
                stringType = DirectoryStringType.printableString;
            } else
            {
                stringType = DirectoryStringType.utf8String;
            }
        }

        StringBuilder failureMsg = new StringBuilder();
        List<String> requestedCoreAtvTextValues = new LinkedList<>();
        if(requestedRdns != null)
        {
            for(RDN requestedRdn : requestedRdns)
            {
                String textValue = SecurityUtil.rdnValueToString(requestedRdn.getFirst().getValue());
                requestedCoreAtvTextValues.add(textValue);
            }

            // sort the requestedRDNs
            if(rdnOption != null && rdnOption.getPatterns() != null)
            {
                List<String> sorted = new ArrayList<>(requestedCoreAtvTextValues.size());
                for(Pattern p : rdnOption.getPatterns())
                {
                    for(String value : requestedCoreAtvTextValues)
                    {
                        if(sorted.contains(value) == false && p.matcher(value).matches())
                        {
                            sorted.add(value);
                        }
                    }
                }
                for(String value : requestedCoreAtvTextValues)
                {
                    if(sorted.contains(value) == false)
                    {
                        sorted.add(value);
                    }
                }
                requestedCoreAtvTextValues = sorted;
            }
        }

        for(int i = 0; i < rdns.length; i++)
        {
            RDN rdn = rdns[i];
            AttributeTypeAndValue[] atvs = rdn.getTypesAndValues();
            if(atvs.length > 1)
            {
                failureMsg.append("Size of RDN + [" + i + "] is '" + atvs.length + "' but expected '1'");
                failureMsg.append("; ");
                continue;
            }

            ASN1Encodable atvValue = atvs[0].getValue();
            boolean correctStringType = true;
            switch(stringType)
            {
                case bmpString:
                    correctStringType = (atvValue instanceof DERBMPString);
                    break;
                case printableString:
                    correctStringType = (atvValue instanceof DERPrintableString);
                    break;
                case teletexString:
                    correctStringType = (atvValue instanceof DERT61String);
                    break;
                case utf8String:
                    correctStringType = (atvValue instanceof DERUTF8String);
                    break;
                default:
                    throw new RuntimeException("should not reach here");
            }

            if(correctStringType == false)
            {
                failureMsg.append("RDN + [" + i + "] is not of type DirectoryString." + stringType.name());
                failureMsg.append("; ");
                continue;
            }

            String atvTextValue = SecurityUtil.rdnValueToString(atvValue);
            String coreAtvTextValue = atvTextValue;

            if(rdnOption != null)
            {
                AddText addText = rdnOption.getAddprefix(pr);
                String prefix = addText == null ? null : addText.getText();

                if(prefix != null)
                {
                    if(coreAtvTextValue.startsWith(prefix) == false)
                    {
                        failureMsg.append("RDN + [" + i + "] '" + atvTextValue+
                                "' does not start with prefix '" + prefix + "'");
                        failureMsg.append("; ");
                        continue;
                    } else
                    {
                        coreAtvTextValue = coreAtvTextValue.substring(prefix.length());
                    }
                }

                addText = rdnOption.getAddsufix(pr);
                String suffix = addText == null ? null : addText.getText();
                if(suffix != null)
                {
                    if(coreAtvTextValue.endsWith(suffix) == false)
                    {
                        failureMsg.append("RDN + [" + i + "] '" + atvTextValue+
                                "' does not end with suffx '" + suffix + "'");
                        failureMsg.append("; ");
                        continue;
                    } else
                    {
                        coreAtvTextValue = coreAtvTextValue.substring(0, coreAtvTextValue.length() - suffix.length());
                    }
                }

                List<Pattern> patterns = rdnOption.getPatterns();
                if(patterns != null)
                {
                    Pattern pattern = patterns.get(i);
                    boolean matches = pattern.matcher(coreAtvTextValue).matches();
                    if(matches == false)
                    {
                        failureMsg.append("RDN + [" + i + "] '" + coreAtvTextValue+
                                "' is not valid against regex '" + pattern.pattern() + "'");
                        failureMsg.append("; ");
                        continue;
                    }
                }
            }

            if(requestedCoreAtvTextValues.isEmpty())
            {
                if(type.equals(ObjectIdentifiers.DN_SERIALNUMBER) == false)
                {
                    failureMsg.append("is present but not contained in the request");
                    failureMsg.append("; ");
                }
            } else
            {
                String requestedCoreAtvTextValue = requestedCoreAtvTextValues.get(i);
                if(ObjectIdentifiers.DN_CN.equals(type) &&
                        specialBehavior != null && "gematik_gSMC_K".equals(specialBehavior))
                {
                    if(coreAtvTextValue.startsWith(requestedCoreAtvTextValue + "-") == false)
                    {
                        failureMsg.append("content '" + coreAtvTextValue + "' does not start with '" +
                                requestedCoreAtvTextValue + "-'");
                        failureMsg.append("; ");
                    }
                } else if(type.equals(ObjectIdentifiers.DN_SERIALNUMBER))
                {
                } else
                {
                    if(coreAtvTextValue.equals(requestedCoreAtvTextValue) == false)
                    {
                        failureMsg.append("content '" + coreAtvTextValue + "' but expected '" +
                                requestedCoreAtvTextValue + "'");
                        failureMsg.append("; ");
                    }
                }
            }
        }

        int n = failureMsg.length();
        if(n > 2)
        {
            failureMsg.delete(n - 2, n);
            issue.setFailureMessage(failureMsg.toString());
        }

        return issue;
    }

    public boolean includeIssuerAndSerialInAKI()
    {
        return akiOption == null ? false : akiOption.isIncludeIssuerAndSerial();
    }

    private static int getInt(Integer i, int dfltValue)
    {
        return i == null ? dfltValue : i.intValue();
    }

    private ValidationIssue createSubjectIssue(ASN1ObjectIdentifier subjectAttrType)
    {
        ValidationIssue issue;
        String attrName = ObjectIdentifiers.getName(subjectAttrType);
        if(attrName == null)
        {
            attrName = subjectAttrType.getId().replace('.', '_');
            issue = new ValidationIssue("X509.SUBJECT." + attrName, "attribute " + subjectAttrType.getId());
        }
        else
        {
            issue = new ValidationIssue("X509.SUBJECT." + attrName, "extension " + attrName +
                    " (" + subjectAttrType.getId() + ")");
        }
        return issue;
    }

    private ValidationIssue createExtensionIssue(ASN1ObjectIdentifier extId)
    {
        ValidationIssue issue;
        String extName = ObjectIdentifiers.getName(extId);
        if(extName == null)
        {
            extName = extId.getId().replace('.', '_');
            issue = new ValidationIssue("X509.EXT." + extName, "extension " + extId.getId());
        }
        else
        {
            issue = new ValidationIssue("X509.EXT." + extName, "extension " + extName + " (" + extId.getId() + ")");
        }
        return issue;
    }

    private void checkExtensionBasicConstraints(StringBuilder failureMsg, byte[] extensionValue)
    {
        BasicConstraints bc =  BasicConstraints.getInstance(extensionValue);
        if(ca != bc.isCA())
        {
            failureMsg.append("ca is '" + bc.isCA() + "' but expected '" + ca + "'");
            failureMsg.append("; ");
        }

        if(bc.isCA())
        {
            BigInteger _pathLen = bc.getPathLenConstraint();
            if(pathLen == null)
            {
                if(_pathLen != null)
                {
                    failureMsg.append("pathLen is '" + _pathLen + "' but expected 'absent'");
                    failureMsg.append("; ");
                }
            }
            else
            {
                if(_pathLen == null)
                {
                    failureMsg.append("pathLen is 'null' but expected '" +  pathLen + "'");
                    failureMsg.append("; ");
                }
                else if(BigInteger.valueOf(pathLen).equals(_pathLen)== false)
                {
                    failureMsg.append("pathLen is '" + _pathLen + "' but expected '" +  pathLen + "'");
                    failureMsg.append("; ");
                }
            }
        }
    }

    private void checkExtensionSubjectKeyIdentifier(StringBuilder failureMsg,
            byte[] extensionValue, SubjectPublicKeyInfo subjectPublicKeyInfo)
    {
        // subjectKeyIdentifier
        SubjectKeyIdentifier asn1 = SubjectKeyIdentifier.getInstance(extensionValue);
        byte[] ski = asn1.getKeyIdentifier();
        byte[] pkData = subjectPublicKeyInfo.getPublicKeyData().getBytes();
        byte[] expectedSki = HashCalculator.hash(HashAlgoType.SHA1, pkData);
        if(Arrays.equals(expectedSki, ski) == false)
        {
            failureMsg.append("SKI is '" + hex(ski) + "' but expected is '" + hex(expectedSki) + "'");
            failureMsg.append("; ");
        }
    }

    private void checkExtensionIssuerKeyIdentifier(StringBuilder failureMsg,
            byte[] extensionValue, X509IssuerInfo issuerInfo)
    {
        AuthorityKeyIdentifier asn1 = AuthorityKeyIdentifier.getInstance(extensionValue);
        byte[] keyIdentifier = asn1.getKeyIdentifier();
        if(keyIdentifier == null)
        {
            failureMsg.append("keyIdentifier is 'absent' but expected 'present'");
            failureMsg.append("; ");
        }
        else if(Arrays.equals(issuerInfo.getSubjectKeyIdentifier(), keyIdentifier) == false)
        {
            failureMsg.append("keyIdentifier is '" + hex(keyIdentifier) + "' but expected '" +
                    hex(issuerInfo.getSubjectKeyIdentifier()) + "'");
            failureMsg.append("; ");
        }

        BigInteger serialNumber = asn1.getAuthorityCertSerialNumber();
        GeneralNames names = asn1.getAuthorityCertIssuer();
        if(serialNumber != null)
        {
            if(names == null)
            {
                failureMsg.append("authorityCertIssuer is 'absent' but expected 'present'");
                failureMsg.append("; ");
            }
            if(issuerInfo.getCert().getSerialNumber().equals(serialNumber) == false)
            {
                failureMsg.append("authorityCertSerialNumber is '" + serialNumber + "' but expected '" +
                        issuerInfo.getCert().getSerialNumber() + "'");
                failureMsg.append("; ");
            }
        }

        if(names != null)
        {
            if(serialNumber == null)
            {
                failureMsg.append("authorityCertSerialNumber is 'absent' but expected 'present'");
                failureMsg.append("; ");
            }
            GeneralName[] genNames = names.getNames();
            X500Name x500GenName = null;
            for(GeneralName genName : genNames)
            {
                if(genName.getTagNo() == GeneralName.directoryName)
                {
                    if(x500GenName != null)
                    {
                        failureMsg.append("authorityCertIssuer contains at least two directoryName "
                                + "but expected one");
                        failureMsg.append("; ");
                        break;
                    }
                    else
                    {
                        x500GenName = (X500Name) genName.getName();
                    }
                }
            }

            if(x500GenName == null)
            {
                failureMsg.append("authorityCertIssuer does not contain directoryName but expected one");
                failureMsg.append("; ");
            }
            else
            {
                X500Name caSubject = issuerInfo.getBcCert().getTBSCertificate().getSubject();
                if(caSubject.equals(x500GenName) == false)
                {
                    failureMsg.append("authorityCertIssuer is '" + x500GenName.toString()
                            + "' but expected '" + caSubject.toString() + "'");
                    failureMsg.append("; ");
                }
            }
        }
    }

    private void checkExtensionNameConstraints(StringBuilder failureMsg,
            byte[] extensionValue, Extensions requestExtensions, ExtensionControl extControl,
            EnvironmentParameterResolver pr)
    {
        QaNameConstraintsOption conf = (nameConstraints == null) ?
                null : (QaNameConstraintsOption) nameConstraints.getExtensionConf(pr);

        if(conf == null)
        {
            byte[] expected = getExpectedExtValue(Extension.nameConstraints, requestExtensions, extControl, pr);
            if(Arrays.equals(expected, extensionValue) == false)
            {
                failureMsg.append("extension valus is '" + hex(extensionValue) +
                        "' but expected '" + (expected == null ? "not present" : hex(expected)) + "'");
                failureMsg.append("; ");
            }
            return;
        }

        org.bouncycastle.asn1.x509.NameConstraints iNameConstraints =
                org.bouncycastle.asn1.x509.NameConstraints.getInstance(extensionValue);

        checkExtensionNameConstraintsSubtrees(failureMsg, "PermittedSubtrees", iNameConstraints.getPermittedSubtrees(),
                conf.getPermittedSubtrees());
        checkExtensionNameConstraintsSubtrees(failureMsg, "ExcludedSubtrees", iNameConstraints.getExcludedSubtrees(),
                conf.getExcludedSubtrees());
    }

    private void checkExtensionNameConstraintsSubtrees(StringBuilder failureMsg,
            String description, GeneralSubtree[] subtrees, List<QaGeneralSubtree> expectedSubtrees)
    {
        int iSize = subtrees == null ? 0 : subtrees.length;
        int eSize = expectedSubtrees == null ? 0 : expectedSubtrees.size();
        if(iSize != eSize)
        {
            failureMsg.append("Size of " + description + " is '" + iSize + "' but expected '" + eSize + "'");
            failureMsg.append("; ");
        } else
        {
            for(int i = 0; i < iSize; i++)
            {
                GeneralSubtree iSubtree = subtrees[i];
                QaGeneralSubtree eSubtree = expectedSubtrees.get(i);
                BigInteger bigInt = iSubtree.getMinimum();
                int iMinimum = bigInt == null ? 0 : bigInt.intValue();
                Integer _int = eSubtree.getMinimum();
                int eMinimum = _int == null ? 0 : _int.intValue();
                String desc = description + " [" + i + "]";
                if(iMinimum != eMinimum)
                {
                    failureMsg.append("minimum of " + desc + " is '" + iMinimum + "' but expected '" + eMinimum + "'");
                    failureMsg.append("; ");
                }

                bigInt = iSubtree.getMaximum();
                Integer iMaximum = bigInt == null ? null : bigInt.intValue();
                Integer eMaximum = eSubtree.getMaximum();
                if(iMaximum != eMaximum)
                {
                    failureMsg.append("maxmum of " + desc + " is '" + iMaximum + "' but expected '" + eMaximum + "'");
                    failureMsg.append("; ");
                }

                GeneralName iBase = iSubtree.getBase();

                GeneralName eBase;
                if(eSubtree.getDirectoryName() != null)
                {
                    eBase = new GeneralName(SecurityUtil.reverse(
                            new X500Name(eSubtree.getDirectoryName())));
                }
                else if(eSubtree.getDNSName() != null)
                {
                    eBase = new GeneralName(GeneralName.dNSName, eSubtree.getDNSName());
                }
                else if(eSubtree.getIpAddress() != null)
                {
                    eBase = new GeneralName(GeneralName.iPAddress, eSubtree.getIpAddress());
                }
                else if(eSubtree.getRfc822Name() != null)
                {
                    eBase = new GeneralName(GeneralName.rfc822Name, eSubtree.getRfc822Name());
                }
                else if(eSubtree.getUri() != null)
                {
                    eBase = new GeneralName(GeneralName.uniformResourceIdentifier, eSubtree.getUri());
                }
                else
                {
                    throw new RuntimeException("should not reach here");
                }

                if(iBase.equals(eBase) == false)
                {
                    failureMsg.append("base of " + desc + " is '" + iBase + "' but expected '" + eBase + "'");
                    failureMsg.append("; ");
                }
            }
        }
    }

    private void checkExtensionPolicyConstraints(StringBuilder failureMsg,
            byte[] extensionValue, Extensions requestExtensions, ExtensionControl extControl,
            EnvironmentParameterResolver pr)
    {
        QaPolicyConstraintsOption conf = (QaPolicyConstraintsOption) ((policyConstraints == null) ?
                null : policyConstraints.getExtensionConf(pr));
        if(conf == null)
        {
            byte[] expected = getExpectedExtValue(Extension.policyConstraints, requestExtensions, extControl, pr);
            if(Arrays.equals(expected, extensionValue) == false)
            {
                failureMsg.append("extension valus is '" + hex(extensionValue) +
                        "' but expected '" + (expected == null ? "not present" : hex(expected)) + "'");
                failureMsg.append("; ");
            }
            return;
        }

        org.bouncycastle.asn1.x509.PolicyConstraints iPolicyConstraints =
                org.bouncycastle.asn1.x509.PolicyConstraints.getInstance(extensionValue);
        Integer eRequireExplicitPolicy = conf.getRequireExplicitPolicy();
        BigInteger bigInt = iPolicyConstraints.getRequireExplicitPolicyMapping();
        Integer iRequreExplicitPolicy = bigInt == null ? null : bigInt.intValue();

        boolean match = true;
        if(eRequireExplicitPolicy == null)
        {
            if(iRequreExplicitPolicy != null)
            {
                match = false;
            }
        } else if(eRequireExplicitPolicy.equals(iRequreExplicitPolicy) == false)
        {
            match = false;
        }

        if(match == false)
        {
            failureMsg.append("requreExplicitPolicy is '" + iRequreExplicitPolicy + "' but expected '" +
                    eRequireExplicitPolicy + "'");
            failureMsg.append("; ");
        }

        Integer eInhibitPolicyMapping = conf.getInhibitPolicyMapping();
        bigInt = iPolicyConstraints.getInhibitPolicyMapping();
        Integer iInhibitPolicyMapping = bigInt == null ? null : bigInt.intValue();

        match = true;
        if(eInhibitPolicyMapping == null)
        {
            if(iInhibitPolicyMapping != null)
            {
                match = false;
            }
        } else if(eInhibitPolicyMapping.equals(iInhibitPolicyMapping) == false)
        {
            match = false;
        }

        if(match == false)
        {
            failureMsg.append("inhibitPolicyMapping is '" + iInhibitPolicyMapping + "' but expected '" +
                    eInhibitPolicyMapping + "'");
            failureMsg.append("; ");
        }
    }

    private void checkExtensionKeyUsage(StringBuilder failureMsg,
            byte[] extensionValue, boolean[] usages, Extensions requestExtensions, ExtensionControl extControl,
            EnvironmentParameterResolver pr)
    {
        int n = usages.length;

        if(n > 9)
        {
            failureMsg.append("invalid syntax: size of valid bits is larger than 9: " + n);
            failureMsg.append("; ");
        }

        Set<String> isUsages = new HashSet<>();
        for(int i = 0; i < n; i++)
        {
            if(usages[i])
            {
                isUsages.add(allUsages.get(i));
            }
        }

        Set<String> expectedUsages = new HashSet<>();
        Set<KeyUsageControl> requiredKeyusage = getKeyusage(true, pr);
        for(KeyUsageControl usage : requiredKeyusage)
        {
            expectedUsages.add(usage.getKeyUsage().getName());
        }

        Set<KeyUsageControl> optionalKeyusage = getKeyusage(false, pr);
        if(extControl.isRequest() && requestExtensions != null &&
                optionalKeyusage.isEmpty() == false)
        {
            Extension extension = requestExtensions.getExtension(Extension.keyUsage);
            if(extension != null)
            {
                org.bouncycastle.asn1.x509.KeyUsage reqKeyUsage =
                        org.bouncycastle.asn1.x509.KeyUsage.getInstance(extension.getParsedValue());
                for(KeyUsageControl k : optionalKeyusage)
                {
                    if(reqKeyUsage.hasUsages(k.getKeyUsage().getBcUsage()))
                    {
                        expectedUsages.add(k.getKeyUsage().getName());
                    }
                }
            }
        }

        if(expectedUsages.isEmpty())
        {
            byte[] constantExtValue = getConstantExtensionValue(Extension.keyUsage, pr);
            if(constantExtValue != null)
            {
                expectedUsages = getKeyUsage(constantExtValue);
            }
        }

        Set<String> diffs = str_in_b_not_in_a(expectedUsages, isUsages);
        if(diffs.isEmpty() == false)
        {
            failureMsg.append("Usages " + diffs.toString() + " are present but not expected");
            failureMsg.append("; ");
        }

        diffs = str_in_b_not_in_a(isUsages, expectedUsages);
        if(diffs.isEmpty() == false)
        {
            failureMsg.append("Usages " + diffs.toString() + " are absent but are required");
            failureMsg.append("; ");
        }
    }

    private void checkExtensionExtendedKeyUsage(StringBuilder failureMsg,
            byte[] extensionValue, Extensions requestExtensions, ExtensionControl extControl,
            EnvironmentParameterResolver pr)
    {
        Set<String> isUsages = new HashSet<>();
        {
            org.bouncycastle.asn1.x509.ExtendedKeyUsage keyusage =
                    org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(extensionValue);
            KeyPurposeId[] usages = keyusage.getUsages();
            if(usages != null)
            {
                for(KeyPurposeId usage : usages)
                {
                    isUsages.add(usage.getId());
                }
            }
        }

        Set<String> expectedUsages = new HashSet<>();
        Set<ExtKeyUsageControl> requiredExtKeyusage = getExtKeyusage(true, pr);
        if(requiredExtKeyusage != null)
        {
            for(ExtKeyUsageControl usage : requiredExtKeyusage)
            {
                expectedUsages.add(usage.getExtKeyUsage().getId());
            }
        }

        Set<ExtKeyUsageControl> optionalExtKeyusage = getExtKeyusage(false, pr);
        if(extControl.isRequest() && requestExtensions != null &&
                optionalExtKeyusage != null && optionalExtKeyusage.isEmpty() == false)
        {
            Extension extension = requestExtensions.getExtension(Extension.extendedKeyUsage);
            if(extension != null)
            {
                org.bouncycastle.asn1.x509.ExtendedKeyUsage reqKeyUsage =
                        org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(extension.getParsedValue());
                for(ExtKeyUsageControl k : optionalExtKeyusage)
                {
                    if(reqKeyUsage.hasKeyPurposeId(KeyPurposeId.getInstance(k.getExtKeyUsage())))
                    {
                        expectedUsages.add(k.getExtKeyUsage().getId());
                    }
                }
            }
        }

        if(expectedUsages.isEmpty())
        {
            byte[] constantExtValue = getConstantExtensionValue(Extension.keyUsage, pr);
            if(constantExtValue != null)
            {
                expectedUsages = getExtKeyUsage(constantExtValue);
            }
        }

        Set<String> diffs = str_in_b_not_in_a(expectedUsages, isUsages);
        if(diffs.isEmpty() == false)
        {
            failureMsg.append("Usages " + diffs.toString() + " are present but not expected");
            failureMsg.append("; ");
        }

        diffs = str_in_b_not_in_a(isUsages, expectedUsages);
        if(diffs.isEmpty() == false)
        {
            failureMsg.append("Usages " + diffs.toString() + " are absent but are required");
            failureMsg.append("; ");
        }
    }

    private void checkExtensionCertificatePolicies(StringBuilder failureMsg,
            byte[] extensionValue, Extensions requestExtensions, ExtensionControl extControl,
            EnvironmentParameterResolver pr)
    {
        QaCertificatePoliciesOption conf = (QaCertificatePoliciesOption) ((certificatePolicies == null) ?
                null : certificatePolicies.getExtensionConf(pr));
        if(certificatePolicies == null)
        {
            byte[] expected = getExpectedExtValue(Extension.certificatePolicies, requestExtensions, extControl, pr);
            if(Arrays.equals(expected, extensionValue) == false)
            {
                failureMsg.append("extension valus is '" + hex(extensionValue) +
                        "' but expected '" + (expected == null ? "not present" : hex(expected)) + "'");
                failureMsg.append("; ");
            }
            return;
        }

        org.bouncycastle.asn1.x509.CertificatePolicies asn1 =
                org.bouncycastle.asn1.x509.CertificatePolicies.getInstance(extensionValue);
        PolicyInformation[] iPolicyInformations = asn1.getPolicyInformation();

        for(PolicyInformation iPolicyInformation : iPolicyInformations)
        {
            ASN1ObjectIdentifier iPolicyId = iPolicyInformation.getPolicyIdentifier();
            QaCertificatePolicyInformation eCp = conf.getPolicyInformation(iPolicyId.getId());
            if(eCp == null)
            {
                failureMsg.append("certificate policy '" + iPolicyId + "' is not expected");
                failureMsg.append("; ");
            } else
            {
                QaPolicyQualifiersOption eCpPq = eCp.getPolicyQualifiers();
                if(eCpPq != null)
                {
                    ASN1Sequence iPolicyQualifiers = iPolicyInformation.getPolicyQualifiers();
                    List<String> iCpsUris = new LinkedList<>();
                    List<String> iUserNotices = new LinkedList<>();

                    int n = iPolicyQualifiers.size();
                    for(int i = 0; i < n; i++)
                    {
                        PolicyQualifierInfo iPolicyQualifierInfo =
                                (PolicyQualifierInfo) iPolicyQualifiers.getObjectAt(i);
                        ASN1ObjectIdentifier iPolicyQualifierId = iPolicyQualifierInfo.getPolicyQualifierId();
                        ASN1Encodable iQualifier = iPolicyQualifierInfo.getQualifier();
                        if(PolicyQualifierId.id_qt_cps.equals(iPolicyQualifierId))
                        {
                            String iCpsUri = ((DERIA5String) iQualifier).getString();
                            iCpsUris.add(iCpsUri);
                        } else if (PolicyQualifierId.id_qt_unotice.equals(iPolicyQualifierId))
                        {
                            UserNotice iUserNotice = UserNotice.getInstance(iQualifier);
                            if(iUserNotice.getExplicitText() != null)
                            {
                                iUserNotices.add(iUserNotice.getExplicitText().getString());
                            }
                        }
                    }

                    List<QaPolicyQualifierInfo> qualifierInfos = eCpPq.getPolicyQualifiers();
                    for(QaPolicyQualifierInfo qualifierInfo : qualifierInfos)
                    {
                        if(qualifierInfo instanceof QaCPSUriPolicyQualifier)
                        {
                            String value = ((QaCPSUriPolicyQualifier) qualifierInfo).getCPSUri();
                            if(iCpsUris.contains(value) == false)
                            {
                                failureMsg.append("CPSUri '" + value + "' is absent but is required");
                                failureMsg.append("; ");
                            }
                        }else if(qualifierInfo instanceof QaUserNoticePolicyQualifierInfo)
                        {
                            String value = ((QaUserNoticePolicyQualifierInfo) qualifierInfo).getUserNotice();
                            if(iUserNotices.contains(value) == false)
                            {
                                failureMsg.append("userNotice '" + value + "' is absent but is required");
                                failureMsg.append("; ");
                            }
                        }else
                        {
                            throw new RuntimeException("should not reach here");
                        }
                    }
                }
            }
        }

        for(QaCertificatePolicyInformation cp : conf.getPolicyInformations())
        {
            boolean present = false;
            for(PolicyInformation iPolicyInformation : iPolicyInformations)
            {
                if(iPolicyInformation.getPolicyIdentifier().getId().equals(cp.getPolicyId()))
                {
                    present = true;
                    break;
                }
            }

            if(present == false)
            {
                failureMsg.append("certificate policy '" + cp.getPolicyId() + "' is "
                        + "absent but is required");
                failureMsg.append("; ");
            }
        }
    }

    private void checkExtensionPolicyMappings(StringBuilder failureMsg, byte[] extensionValue,
            Extensions requestExtensions, ExtensionControl extControl,
            EnvironmentParameterResolver pr)
    {
        QaPolicyMappingsOption conf = (QaPolicyMappingsOption) ((policyMappings == null) ?
                null : policyMappings.getExtensionConf(pr));
        if(conf == null)
        {
            byte[] expected = getExpectedExtValue(Extension.policyMappings, requestExtensions, extControl, pr);
            if(Arrays.equals(expected, extensionValue) == false)
            {
                failureMsg.append("extension valus is '" + hex(extensionValue) +
                        "' but expected '" + (expected == null ? "not present" : hex(expected)) + "'");
                failureMsg.append("; ");
            }
            return;
        }

        ASN1Sequence iPolicyMappings = DERSequence.getInstance(extensionValue);
        Map<String, String> iMap = new HashMap<>();
        int size = iPolicyMappings.size();
        for(int i = 0; i < size; i++)
        {
            ASN1Sequence seq = (ASN1Sequence) iPolicyMappings.getObjectAt(i);

            CertPolicyId issuerDomainPolicy = CertPolicyId.getInstance(seq.getObjectAt(0));
            CertPolicyId subjectDomainPolicy = CertPolicyId.getInstance(seq.getObjectAt(1));
            iMap.put(issuerDomainPolicy.getId(), subjectDomainPolicy.getId());
        }

        Set<String> eIssuerDomainPolicies = conf.getIssuerDomainPolicies();
        for(String eIssuerDomainPolicy : eIssuerDomainPolicies)
        {
            String eSubjectDomainPolicy = conf.getSubjectDomainPolicy(eIssuerDomainPolicy);

            String iSubjectDomainPolicy = iMap.remove(eIssuerDomainPolicy);
            if(iSubjectDomainPolicy == null)
            {
                failureMsg.append("issuerDomainPolicy '").append(eIssuerDomainPolicy).append("' is absent but is required");
                failureMsg.append("; ");
            } else if(iSubjectDomainPolicy.equals(eSubjectDomainPolicy) == false)
            {
                failureMsg.append("subjectDomainPolicy for issuerDomainPolicy is '" + iSubjectDomainPolicy +
                        "' but expected '" + eSubjectDomainPolicy + "'");
                failureMsg.append("; ");
            }
        }

        if(iMap.isEmpty() == false)
        {
            failureMsg.append("issuerDomainPolicies '" + iMap.keySet() + "' are present but not expected");
            failureMsg.append("; ");
        }
    }

    private void checkExtensionInhibitAnyPolicy(StringBuilder failureMsg,
            byte[] extensionValue, Extensions requestExtensions, ExtensionControl extControl,
            EnvironmentParameterResolver pr)
    {
        QaInhibitAnyPolicyOption conf = (QaInhibitAnyPolicyOption) ((inhibitAnyPolicy == null) ?
                null : inhibitAnyPolicy.getExtensionConf(pr));
        if(conf == null)
        {
            byte[] expected = getExpectedExtValue(Extension.inhibitAnyPolicy, requestExtensions, extControl, pr);
            if(Arrays.equals(expected, extensionValue) == false)
            {
                failureMsg.append("extension valus is '").append(hex(extensionValue));
                failureMsg.append("' but expected '").append(expected == null ? "not present" : hex(expected)).append("'");
                failureMsg.append("; ");
            }
            return;
        }

        ASN1Integer asn1Int = ASN1Integer.getInstance(extensionValue);
        int iSkipCerts = asn1Int.getPositiveValue().intValue();
        if(iSkipCerts != conf.getSkipCerts())
        {
            failureMsg.append("skipCerts is '" + iSkipCerts + "' but expected '" +
                    conf.getSkipCerts() + "'");
            failureMsg.append("; ");
        }
    }

    private void checkExtensionSubjectAltName(StringBuilder failureMsg,
            byte[] extensionValue, Extensions requestExtensions, ExtensionControl extControl,
            EnvironmentParameterResolver pr)
    {
        if(allowedSubjectAltNameModes == null)
        {
            byte[] expected = getExpectedExtValue(Extension.subjectAlternativeName, requestExtensions, extControl, pr);
            if(Arrays.equals(expected, extensionValue) == false)
            {
                failureMsg.append("extension valus is '").append(hex(extensionValue));
                failureMsg.append("' but expected '").append(expected == null ? "not present" : hex(expected)).append("'");
                failureMsg.append("; ");
            }
            return;
        }

        ASN1Encodable extInRequest = null;
        if(requestExtensions != null)
        {
            extInRequest = requestExtensions.getExtensionParsedValue(Extension.subjectAlternativeName);
        }

        if(extInRequest == null)
        {
            failureMsg.append("extension is present but not expected");
            failureMsg.append("; ");
            return;
        }

        GeneralName[] requested = GeneralNames.getInstance(extInRequest).getNames();

        GeneralName[] is = GeneralNames.getInstance(extensionValue).getNames();

        GeneralName[] expected = new GeneralName[requested.length];
        for(int i = 0; i < is.length; i++)
        {
            try
            {
                expected[i] = createGeneralName(is[i], allowedSubjectAltNameModes);
            } catch (BadCertTemplateException e)
            {
                failureMsg.append("error while processing ").append(i+1).append("-th name: ").append(e.getMessage());
                failureMsg.append("; ");
                return;
            }
        }

        if(is.length != expected.length)
        {
            failureMsg.append("size of GeneralNames is '").append(is.length);
            failureMsg.append("' but expected '").append(expected.length).append("'");
            failureMsg.append("; ");
            return;
        }

        for(int i = 0; i < is.length; i++)
        {
            if(is[i].equals(expected[i]) == false)
            {
                failureMsg.append(i+1).append("-th name does not match the requested one");
                failureMsg.append("; ");
            }
        }
    }

    private void checkExtensionSubjectInfoAccess(StringBuilder failureMsg,
            byte[] extensionValue, Extensions requestExtensions, ExtensionControl extControl,
            EnvironmentParameterResolver pr)
    {
        if(allowedSubjectInfoAccessModes == null)
        {
            byte[] expected = getExpectedExtValue(Extension.subjectAlternativeName, requestExtensions, extControl, pr);
            if(Arrays.equals(expected, extensionValue) == false)
            {
                failureMsg.append("extension valus is '").append(hex(extensionValue));
                failureMsg.append("' but expected '").append(expected == null ? "not present" : hex(expected)).append("'");
                failureMsg.append("; ");
            }
            return;
        }

        ASN1Encodable requestExtValue = null;
        if(requestExtensions != null)
        {
            requestExtValue = requestExtensions.getExtensionParsedValue(Extension.subjectInfoAccess);
        }
        if(requestExtValue == null)
        {
            failureMsg.append("extension is present but not expected");
            failureMsg.append("; ");
            return;
        }

        ASN1Sequence requestSeq = ASN1Sequence.getInstance(requestExtValue);
        ASN1Sequence certSeq = ASN1Sequence.getInstance(extensionValue);

        int n = requestSeq.size();

        if(certSeq.size() != n)
        {
            failureMsg.append("size of GeneralNames is '").append(certSeq.size());
            failureMsg.append("' but expected '").append(n).append("'");
            failureMsg.append("; ");
            return;
        }

        for(int i = 0; i < n; i++)
        {
            AccessDescription ad = AccessDescription.getInstance(requestSeq.getObjectAt(i));
            ASN1ObjectIdentifier accessMethod = ad.getAccessMethod();

            Set<GeneralNameMode> generalNameModes;
            if(accessMethod == null)
            {
                generalNameModes = allowedSubjectInfoAccessModes.get(X509Certprofile.OID_ZERO);
            } else
            {
                generalNameModes = allowedSubjectInfoAccessModes.get(accessMethod);
            }

            if(generalNameModes == null)
            {
                failureMsg.append("accessMethod in requestExtension ");
                failureMsg.append(accessMethod == null ? "NULL" : accessMethod.getId());
                failureMsg.append(" is not allowed");
                failureMsg.append("; ");
                continue;
            }

            AccessDescription certAccessDesc = AccessDescription.getInstance(certSeq.getObjectAt(i));
            ASN1ObjectIdentifier certAccessMethod = certAccessDesc.getAccessMethod();

            boolean b;
            if(accessMethod == null)
            {
                b = certAccessDesc == null;
            } else
            {
                b = accessMethod.equals(certAccessMethod);
            }

            if(b == false)
            {
                failureMsg.append("accessMethod is '").append(certAccessMethod == null ? "null" : certAccessMethod.getId());
                failureMsg.append("' but expected '").append(accessMethod == null ? "null" : accessMethod.getId());
                failureMsg.append("; ");
                continue;
            }

            GeneralName accessLocation;
            try
            {
                accessLocation = createGeneralName(ad.getAccessLocation(), generalNameModes);
            } catch (BadCertTemplateException e)
            {
                failureMsg.append("invalid requestExtension: " + e.getMessage());
                failureMsg.append("; ");
                continue;
            }

            GeneralName certAccessLocation = certAccessDesc.getAccessLocation();
            if(certAccessLocation.equals(accessLocation) == false)
            {
                failureMsg.append("accessLocation does not match the requested one");
                failureMsg.append("; ");
            }
        }
    }

    private void checkExtensionIssuerAltNames(StringBuilder failureMsg,
            byte[] extensionValue, X509IssuerInfo issuerInfo)
    {
        Extension caSubjectAltExtension = issuerInfo.getBcCert().getTBSCertificate().getExtensions().getExtension(
                Extension.subjectAlternativeName);
        if(caSubjectAltExtension == null)
        {
            failureMsg.append("issuerAlternativeName is present but expected 'none'");
            failureMsg.append("; ");
        }
        else
        {
            byte[] caSubjectAltExtensionValue = caSubjectAltExtension.getExtnValue().getOctets();
            if(Arrays.equals(caSubjectAltExtensionValue, extensionValue) == false)
            {
                failureMsg.append("is '" + hex(extensionValue) + "' but expected '" +
                        hex(caSubjectAltExtensionValue) + "'");
                failureMsg.append("; ");
            }
        }
    }

    private void checkExtensionAuthorityInfoAccess(StringBuilder failureMsg,
            byte[] extensionValue, X509IssuerInfo issuerInfo)
    {
        Set<String> eOCSPUris = issuerInfo.getOcspURLs();
        if(eOCSPUris == null)
        {
            failureMsg.append("AIA is present but expected is 'none'");
            failureMsg.append("; ");
        }
        else
        {
            AuthorityInformationAccess iAIA = AuthorityInformationAccess.getInstance(extensionValue);
            AccessDescription[] iAccessDescriptions = iAIA.getAccessDescriptions();
            List<AccessDescription> iOCSPAccessDescriptions = new LinkedList<>();
            for(AccessDescription iAccessDescription : iAccessDescriptions)
            {
                if(iAccessDescription.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_ocsp))
                {
                    iOCSPAccessDescriptions.add(iAccessDescription);
                }
            }

            int n = iOCSPAccessDescriptions.size();
            if(n != eOCSPUris.size())
            {
                failureMsg.append("Number of AIA OCSP URIs is '").append(n);
                failureMsg.append("' but expected is '").append(eOCSPUris.size()).append("'");
                failureMsg.append("; ");
            }
            else
            {
                Set<String> iOCSPUris = new HashSet<>();
                for(int i = 0; i < n; i++)
                {
                    GeneralName iAccessLocation = iOCSPAccessDescriptions.get(i).getAccessLocation();
                    if(iAccessLocation.getTagNo() != GeneralName.uniformResourceIdentifier)
                    {
                        failureMsg.append("Tag of accessLocation of AIA OCSP is '").append(iAccessLocation.getTagNo());
                        failureMsg.append("' but expected is '").append(GeneralName.uniformResourceIdentifier).append("'");
                        failureMsg.append("; ");
                    }
                    else
                    {
                        String iOCSPUri = ((ASN1String) iAccessLocation.getName()).getString();
                        iOCSPUris.add(iOCSPUri);
                    }
                }

                Set<String> diffs = str_in_b_not_in_a(eOCSPUris, iOCSPUris);
                if(diffs.isEmpty() == false)
                {
                    failureMsg.append("OCSP URLs ").append(diffs.toString()).append(" are present but not expected");
                    failureMsg.append("; ");
                }

                diffs = str_in_b_not_in_a(iOCSPUris, eOCSPUris);
                if(diffs.isEmpty() == false)
                {
                    failureMsg.append("OCSP URLs ").append(diffs.toString()).append(" are absent but are required");
                    failureMsg.append("; ");
                }
            }
        }
    }

    private void checkExtensionCrlDistributionPoints(StringBuilder failureMsg,
            byte[] extensionValue, X509IssuerInfo issuerInfo)
    {
        CRLDistPoint iCRLDistPoints = CRLDistPoint.getInstance(extensionValue);
        DistributionPoint[] iDistributionPoints = iCRLDistPoints.getDistributionPoints();
        int n = iDistributionPoints == null ? 0 : iDistributionPoints.length;
        if(n != 1)
        {
            failureMsg.append("Size of CRLDistributionPoints is '").append(n).append("' but expected is '1'");
            failureMsg.append("; ");
        }
        else
        {
            Set<String> iCrlURLs = new HashSet<>();
            for(DistributionPoint entry : iDistributionPoints)
            {
                int asn1Type = entry.getDistributionPoint().getType();
                if(asn1Type != DistributionPointName.FULL_NAME)
                {
                    failureMsg.append("Tag of DistributionPointName of CRLDistibutionPoints is '").append(asn1Type);
                    failureMsg.append("' but expected is '").append(DistributionPointName.FULL_NAME).append("'");
                    failureMsg.append("; ");
                } else
                {
                    GeneralNames iDistributionPointNames = (GeneralNames) entry.getDistributionPoint().getName();
                    GeneralName[] names = iDistributionPointNames.getNames();

                    for(int i = 0; i < names.length; i++)
                    {
                        GeneralName name = names[i];
                        if(name.getTagNo() != GeneralName.uniformResourceIdentifier)
                        {
                            failureMsg.append("Tag of CRL URL is '").append(name.getTagNo());
                            failureMsg.append("' but expected is '").append(GeneralName.uniformResourceIdentifier).append("'");
                            failureMsg.append("; ");
                        }
                        else
                        {
                            String uri = ((ASN1String) name.getName()).getString();
                            iCrlURLs.add(uri);
                        }
                    }

                    Set<String> eCRLUrls = issuerInfo.getCrlURLs();
                    Set<String> diffs = str_in_b_not_in_a(eCRLUrls, iCrlURLs);
                    if(diffs.isEmpty() == false)
                    {
                        failureMsg.append("CRL URLs ").append(diffs.toString()).append(" are present but not expected");
                        failureMsg.append("; ");
                    }

                    diffs = str_in_b_not_in_a(iCrlURLs, eCRLUrls);
                    if(diffs.isEmpty() == false)
                    {
                        failureMsg.append("CRL URLs ").append(diffs.toString()).append(" are absent but are required");
                        failureMsg.append("; ");
                    }
                }
            }
        }
    }

    private void checkExtensionDeltaCrlDistributionPoints(StringBuilder failureMsg,
            byte[] extensionValue, X509IssuerInfo issuerInfo)
    {
        CRLDistPoint iCRLDistPoints = CRLDistPoint.getInstance(extensionValue);
        DistributionPoint[] iDistributionPoints = iCRLDistPoints.getDistributionPoints();
        int n = iDistributionPoints == null ? 0 : iDistributionPoints.length;
        if(n != 1)
        {
            failureMsg.append("Size of CRLDistributionPoints (deltaCRL) is '").append(n).append("' but expected is '1'");
            failureMsg.append("; ");
        }
        else
        {
            Set<String> iCrlURLs = new HashSet<>();
            for(DistributionPoint entry : iDistributionPoints)
            {
                int asn1Type = entry.getDistributionPoint().getType();
                if(asn1Type != DistributionPointName.FULL_NAME)
                {
                    failureMsg.append("Tag of DistributionPointName of CRLDistibutionPoints (deltaCRL) is '").append(asn1Type);
                    failureMsg.append("' but expected is '").append(DistributionPointName.FULL_NAME).append("'");
                    failureMsg.append("; ");
                } else
                {
                    GeneralNames iDistributionPointNames = (GeneralNames) entry.getDistributionPoint().getName();
                    GeneralName[] names = iDistributionPointNames.getNames();

                    for(int i = 0; i < names.length; i++)
                    {
                        GeneralName name = names[i];
                        if(name.getTagNo() != GeneralName.uniformResourceIdentifier)
                        {
                            failureMsg.append("Tag of deltaCRL URL is '").append(name.getTagNo());
                            failureMsg.append("' but expected is '").append(GeneralName.uniformResourceIdentifier).append("'");
                            failureMsg.append("; ");
                        }
                        else
                        {
                            String uri = ((ASN1String) name.getName()).getString();
                            iCrlURLs.add(uri);
                        }
                    }

                    Set<String> eCRLUrls = issuerInfo.getCrlURLs();
                    Set<String> diffs = str_in_b_not_in_a(eCRLUrls, iCrlURLs);
                    if(diffs.isEmpty() == false)
                    {
                        failureMsg.append("deltaCRL URLs ").append(diffs.toString()).append(" are present but not expected");
                        failureMsg.append("; ");
                    }

                    diffs = str_in_b_not_in_a(iCrlURLs, eCRLUrls);
                    if(diffs.isEmpty() == false)
                    {
                        failureMsg.append("deltaCRL URLs ").append(diffs.toString()).append(" are absent but are required");
                        failureMsg.append("; ");
                    }
                }
            }
        }
    }

    private void checkExtensionAdmission(StringBuilder failureMsg,
            byte[] extensionValue, Extensions requestExtensions, ExtensionControl extControl,
            EnvironmentParameterResolver pr)
    {
        QaAdmissionOption conf = (admission == null) ?
                null : (QaAdmissionOption) admission.getExtensionConf(pr);
        if(conf == null)
        {
            byte[] expected = getExpectedExtValue(ObjectIdentifiers.id_extension_admission, requestExtensions, extControl, pr);
            if(Arrays.equals(expected, extensionValue) == false)
            {
                failureMsg.append("extension valus is '").append(hex(extensionValue));
                failureMsg.append("' but expected '").append(expected == null ? "not present" : hex(expected)).append("'");
                failureMsg.append("; ");
            }
            return;
        }

        ASN1Sequence seq = ASN1Sequence.getInstance(extensionValue);
        AdmissionSyntax iAdmissionSyntax = AdmissionSyntax.getInstance(seq);
        Admissions[] iAdmissions = iAdmissionSyntax.getContentsOfAdmissions();
        int n = iAdmissions == null ? 0 : iAdmissions.length;
        if(n != 1)
        {
            failureMsg.append("Size of Admissions is '").append(n).append("' but expected is '1'");
            failureMsg.append("; ");
        }
        else
        {
            Admissions iAdmission = iAdmissions[0];
            ProfessionInfo[] iProfessionInfos = iAdmission.getProfessionInfos();
            n = iProfessionInfos == null ? 0 : iProfessionInfos.length;
            if(n != 1)
            {
                failureMsg.append("Size of ProfessionInfo is '").append(n).append("' but expected is '1'");
                failureMsg.append("; ");
            } else
            {
                ProfessionInfo iProfessionInfo = iProfessionInfos[0];
                String iRegistrationNumber = iProfessionInfo.getRegistrationNumber();
                String eRegistrationNumber = conf.getRegistrationNumber();
                if(eRegistrationNumber == null)
                {
                    if(iRegistrationNumber != null)
                    {
                        failureMsg.append("RegistrationNumber is '").append(iRegistrationNumber);
                        failureMsg.append("' but expected is 'null'");
                        failureMsg.append("; ");
                    }
                } else if(eRegistrationNumber.equals(iRegistrationNumber) == false)
                {
                    failureMsg.append("RegistrationNumber is '").append(iRegistrationNumber);
                    failureMsg.append("' but expected is '").append(eRegistrationNumber).append("'");
                    failureMsg.append("; ");
                }

                byte[] iAddProfessionInfo = null;
                if(iProfessionInfo.getAddProfessionInfo() != null)
                {
                    iAddProfessionInfo = iProfessionInfo.getAddProfessionInfo().getOctets();
                }
                byte[] eAddProfessionInfo = conf.getAddProfessionInfo();
                if(eAddProfessionInfo == null)
                {
                    if(iAddProfessionInfo != null)
                    {
                        failureMsg.append("AddProfessionInfo is '").append(hex(iAddProfessionInfo));
                        failureMsg.append("' but expected is 'null'");
                        failureMsg.append("; ");
                    }
                } else
                {
                    if(iAddProfessionInfo == null)
                    {
                        failureMsg.append("AddProfessionInfo is 'null' but expected is '").append(hex(eAddProfessionInfo));
                        failureMsg.append("'");
                        failureMsg.append("; ");
                    } else if(Arrays.equals(eAddProfessionInfo, iAddProfessionInfo) == false)
                    {
                        failureMsg.append("AddProfessionInfo is '").append(hex(iAddProfessionInfo));
                        failureMsg.append("' but expected is '").append(hex(eAddProfessionInfo)).append("'");
                        failureMsg.append("; ");
                    }
                }

                List<String> eProfessionOids = conf.getProfessionOIDs();
                ASN1ObjectIdentifier[] _iProfessionOids = iProfessionInfo.getProfessionOIDs();
                List<String> iProfessionOids = new LinkedList<>();
                if(_iProfessionOids != null)
                {
                    for(ASN1ObjectIdentifier entry : _iProfessionOids)
                    {
                        iProfessionOids.add(entry.getId());
                    }
                }

                Set<String> diffs = str_in_b_not_in_a(eProfessionOids, iProfessionOids);
                if(diffs.isEmpty() == false)
                {
                    failureMsg.append("ProfessionOIDs ").append(diffs.toString()).append(" are present but not expected");
                    failureMsg.append("; ");
                }

                diffs = str_in_b_not_in_a(iProfessionOids, eProfessionOids);
                if(diffs.isEmpty() == false)
                {
                    failureMsg.append("ProfessionOIDs ").append(diffs.toString()).append(" are absent but are required");
                    failureMsg.append("; ");
                }

                List<String> eProfessionItems = conf.getProfessionItems();
                DirectoryString[] items = iProfessionInfo.getProfessionItems();
                List<String> iProfessionItems = new LinkedList<>();
                if(items != null)
                {
                    for(DirectoryString item : items)
                    {
                        iProfessionItems.add(item.getString());
                    }
                }

                diffs = str_in_b_not_in_a(eProfessionItems, iProfessionItems);
                if(diffs.isEmpty() == false)
                {
                    failureMsg.append("ProfessionItems ").append(diffs.toString()).append(" are present but not expected");
                    failureMsg.append("; ");
                }

                diffs = str_in_b_not_in_a(iProfessionItems, eProfessionItems);
                if(diffs.isEmpty() == false)
                {
                    failureMsg.append("ProfessionItems ").append(diffs.toString()).append(" are absent but are required");
                    failureMsg.append("; ");
                }
            }
        }
    }

    private boolean checkExtensionOcspNocheck(byte[] extensionValue, StringBuilder failureMsg)
    {
        if(Arrays.equals(DERNull, extensionValue) == false)
        {
            failureMsg.append("value is not DER NULL");
            failureMsg.append("; ");
        }
        return true;
    }

    private static String hex(byte[] bytes)
    {
        return Hex.toHexString(bytes);
    }

    private static Set<String> str_in_b_not_in_a(Collection<String> a, Collection<String> b)
    {
        if(b == null)
        {
            return Collections.emptySet();
        }

        Set<String> result = new HashSet<>();
        for(String entry : b)
        {
            if(a == null || a.contains(entry) == false)
            {
                result.add(entry);
            }
        }
        return result;
    }

    static Set<Range> buildParametersMap(RangesType ranges)
    {
        if(ranges == null)
        {
            return null;
        }

        Set<Range> ret = new HashSet<>();
        for(RangeType range : ranges.getRange())
        {
            if(range.getMin() != null || range.getMax() != null)
            {
                ret.add(new Range(range.getMin(), range.getMax()));
            }
        }
        return ret;
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
                throw new RuntimeException("should not reach here");
            }
        }
    }

    private static Set<String> getKeyUsage(byte[] extensionValue)
    {
        Set<String> usages = new HashSet<>();
        org.bouncycastle.asn1.x509.KeyUsage reqKeyUsage =
                org.bouncycastle.asn1.x509.KeyUsage.getInstance(extensionValue);
        for(KeyUsage k : KeyUsage.values())
        {
            if(reqKeyUsage.hasUsages(k.getBcUsage()))
            {
                usages.add(k.getName());
            }
        }

        return usages;
    }

    private static Set<String> getExtKeyUsage(byte[] extensionValue)
    {
        Set<String> usages = new HashSet<>();
        org.bouncycastle.asn1.x509.ExtendedKeyUsage reqKeyUsage =
                org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(extensionValue);
        for(KeyPurposeId usage : reqKeyUsage.getUsages())
        {
            usages.add(usage.getId());
        }
        return usages;
    }

    private Set<KeyUsageControl> getKeyusage(boolean required, EnvironmentParameterResolver pr)
    {
        Set<KeyUsageControl> ret = new HashSet<>();

        Set<KeyUsageControl> controls = keyusages == null ?
                null : keyusages.getKeyusage(pr);
        if(controls != null)
        {
            for(KeyUsageControl control : controls)
            {
                if(control.isRequired() == required)
                {
                    ret.add(control);
                }
            }
        }
        return ret;
    }

    private Set<ExtKeyUsageControl> getExtKeyusage(boolean required, EnvironmentParameterResolver pr)
    {
        Set<ExtKeyUsageControl> ret = new HashSet<>();

        Set<ExtKeyUsageControl> controls = extendedKeyusages == null ?
                null :
                extendedKeyusages.getExtKeyusage(pr);
        if(controls != null)
        {
            for(ExtKeyUsageControl control : controls)
            {
                if(control.isRequired() == required)
                {
                    ret.add(control);
                }
            }
        }
        return ret;
    }

    private RDNControl getSubjectDNControl(ASN1ObjectIdentifier type)
    {
        for(RDNControl control : subjectDNControls)
        {
            if(control.getType().equals(type))
            {
                return control;
            }
        }

        return null;
    }

    private byte[] getConstantExtensionValue(ASN1ObjectIdentifier type, EnvironmentParameterResolver pr)
    {
        QaExtensionOptions c = constantExtensions.get(type);
        if(c != null)
        {
            QaConstantExtensionOption d = (QaConstantExtensionOption) c.getExtensionConf(pr);
            if(d != null)
            {
                return d.getExtensionValue().getValue();
            }
        }
        return null;
    }

}
