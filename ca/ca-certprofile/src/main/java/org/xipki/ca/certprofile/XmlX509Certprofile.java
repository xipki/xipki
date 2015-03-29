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

package org.xipki.ca.certprofile;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.CertprofileException;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.api.profile.DirectoryStringType;
import org.xipki.ca.api.profile.ExtensionControl;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.api.profile.GeneralNameMode;
import org.xipki.ca.api.profile.KeyParametersOption;
import org.xipki.ca.api.profile.RDNControl;
import org.xipki.ca.api.profile.SubjectInfo;
import org.xipki.ca.api.profile.x509.BaseX509Certprofile;
import org.xipki.ca.api.profile.x509.CertificatePolicyInformation;
import org.xipki.ca.api.profile.x509.ExtKeyUsageControl;
import org.xipki.ca.api.profile.x509.KeyUsageControl;
import org.xipki.ca.api.profile.x509.SpecialX509CertprofileBehavior;
import org.xipki.ca.api.profile.x509.X509CertUtil;
import org.xipki.ca.api.profile.x509.X509CertVersion;
import org.xipki.ca.certprofile.x509.jaxb.Admission;
import org.xipki.ca.certprofile.x509.jaxb.AuthorityKeyIdentifier;
import org.xipki.ca.certprofile.x509.jaxb.BasicConstraints;
import org.xipki.ca.certprofile.x509.jaxb.CertificatePolicies;
import org.xipki.ca.certprofile.x509.jaxb.ConstantExtValue;
import org.xipki.ca.certprofile.x509.jaxb.ExtendedKeyUsage;
import org.xipki.ca.certprofile.x509.jaxb.ExtensionType;
import org.xipki.ca.certprofile.x509.jaxb.ExtensionsType;
import org.xipki.ca.certprofile.x509.jaxb.InhibitAnyPolicy;
import org.xipki.ca.certprofile.x509.jaxb.KeyUsage;
import org.xipki.ca.certprofile.x509.jaxb.NameConstraints;
import org.xipki.ca.certprofile.x509.jaxb.NameValueType;
import org.xipki.ca.certprofile.x509.jaxb.OidWithDescType;
import org.xipki.ca.certprofile.x509.jaxb.PolicyConstraints;
import org.xipki.ca.certprofile.x509.jaxb.PolicyMappings;
import org.xipki.ca.certprofile.x509.jaxb.RdnType;
import org.xipki.ca.certprofile.x509.jaxb.SubjectAltName;
import org.xipki.ca.certprofile.x509.jaxb.SubjectInfoAccess;
import org.xipki.ca.certprofile.x509.jaxb.SubjectInfoAccess.Access;
import org.xipki.ca.certprofile.x509.jaxb.X509ProfileType;
import org.xipki.ca.certprofile.x509.jaxb.X509ProfileType.KeyAlgorithms;
import org.xipki.ca.certprofile.x509.jaxb.X509ProfileType.Parameters;
import org.xipki.ca.certprofile.x509.jaxb.X509ProfileType.Subject;
import org.xipki.common.ObjectIdentifiers;
import org.xipki.common.ParamChecker;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.common.util.X509Util;

/**
 * @author Lijun Liao
 */

public class XmlX509Certprofile extends BaseX509Certprofile
{
    private static final Logger LOG = LoggerFactory.getLogger(XmlX509Certprofile.class);

    private SpecialX509CertprofileBehavior specialBehavior;

    private Map<ASN1ObjectIdentifier, KeyParametersOption> keyAlgorithms;

    private Map<ASN1ObjectIdentifier, SubjectDNOption> subjectDNOptions;
    private Set<RDNControl> subjectDNControls;
    private Map<String, String> parameters;
    private Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls;

    private CertValidity validity;
    private X509CertVersion version;
    private Set<ASN1ObjectIdentifier> signatureAlgorithms;
    private boolean incSerialNoIfSubjectExists;
    private boolean raOnly;
    private boolean qaOnly;
    private boolean backwardsSubject;
    private boolean ca;
    private boolean duplicateKeyPermitted;
    private boolean duplicateSubjectPermitted;
    private boolean serialNumberInReqPermitted;
    private boolean notBeforeMidnight;
    private boolean includeIssuerAndSerialInAKI;
    private Integer pathLen;
    private Set<KeyUsageControl> keyusages;
    private Set<ExtKeyUsageControl> extendedKeyusages;
    private Set<GeneralNameMode> allowedSubjectAltNameModes;
    private Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> allowedSubjectInfoAccessModes;

    private ExtensionValue certificatePolicies;
    private ExtensionValue policyMappings;
    private ExtensionValue nameConstraints;
    private ExtensionValue policyConstraints;
    private ExtensionValue inhibitAnyPolicy;
    private ExtensionValue admission;

    private Map<ASN1ObjectIdentifier, ExtensionValue> constantExtensions;

    private void reset()
    {
        version = null;
        signatureAlgorithms = null;
        keyAlgorithms = null;
        subjectDNOptions = null;
        subjectDNControls = null;
        extensionControls = null;
        validity = null;
        notBeforeMidnight = false;
        includeIssuerAndSerialInAKI = false;
        incSerialNoIfSubjectExists = false;
        raOnly = false;
        qaOnly = false;
        backwardsSubject = false;
        ca = false;
        duplicateKeyPermitted = true;
        duplicateSubjectPermitted = true;
        serialNumberInReqPermitted = true;
        pathLen = null;
        keyusages = null;
        extendedKeyusages = null;
        allowedSubjectAltNameModes = null;
        allowedSubjectInfoAccessModes = null;
        certificatePolicies = null;
        nameConstraints = null;
        policyMappings = null;
        inhibitAnyPolicy = null;
        admission = null;
        constantExtensions = null;
    }

    @Override
    public void initialize(
            final String data)
    throws CertprofileException
    {
        ParamChecker.assertNotBlank("data", data);
        reset();
        try
        {
            doInitialize(data);
        }catch(RuntimeException e)
        {
            final String message = "RuntimeException";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            throw new CertprofileException("caught RuntimeException while initializing certprofile: " + e.getMessage());
        }
    }

    private void doInitialize(
            final String data)
    throws CertprofileException
    {
        byte[] bytes;
        try
        {
            bytes = data.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e)
        {
            bytes = data.getBytes();
        }

        X509ProfileType conf = XmlX509CertprofileUtil.parse(new ByteArrayInputStream(bytes));

        if(conf.getVersion() != null)
        {
            int intVersion = conf.getVersion().intValue();
            this.version = X509CertVersion.getInstance(intVersion);
            if(this.version == null)
            {
                throw new CertprofileException("invalid version " + intVersion);
            }
        }
        else
        {
            this.version = X509CertVersion.V3;
        }

        if(conf.getSignatureAlgorithms() != null)
        {
            this.signatureAlgorithms = XmlX509CertprofileUtil.toOIDSet(
                    conf.getSignatureAlgorithms().getAlgorithm());
        }

        this.raOnly = conf.isRaOnly();
        this.qaOnly = conf.isQaOnly();

        this.validity = CertValidity.getInstance(conf.getValidity());
        this.ca = conf.isCa();
        this.notBeforeMidnight = "midnight".equalsIgnoreCase(conf.getNotBeforeTime());

        String specialBehavior = conf.getSpecialBehavior();
        if(specialBehavior != null)
        {
            this.specialBehavior = SpecialX509CertprofileBehavior.getInstance(specialBehavior);
        }

        if(conf.isDuplicateKey() != null)
        {
            duplicateKeyPermitted = conf.isDuplicateKey().booleanValue();
        }

        if(conf.isDuplicateSubject() != null)
        {
            duplicateSubjectPermitted = conf.isDuplicateSubject().booleanValue();
        }

        if(conf.isSerialNumberInReq() != null)
        {
            serialNumberInReqPermitted = conf.isSerialNumberInReq().booleanValue();
        }

        // KeyAlgorithms
        KeyAlgorithms keyAlgos = conf.getKeyAlgorithms();
        if(keyAlgos != null)
        {
            this.keyAlgorithms = XmlX509CertprofileUtil.buildKeyAlgorithms(keyAlgos);
        }

        // parameters
        Parameters confParams = conf.getParameters();
        if(confParams == null)
        {
            parameters = null;
        }
        else
        {
            Map<String, String> tMap = new HashMap<>();
            for(NameValueType nv : confParams.getParameter())
            {
                tMap.put(nv.getName(), nv.getValue());
            }
            parameters = Collections.unmodifiableMap(tMap);
        }

        // Subject
        Subject subject = conf.getSubject();
        if(subject != null)
        {
            this.backwardsSubject = subject.isDnBackwards();
            this.incSerialNoIfSubjectExists = subject.isIncSerialNumber();

            this.subjectDNControls = new HashSet<RDNControl>();
            this.subjectDNOptions = new HashMap<>();

            for(RdnType t : subject.getRdn())
            {
                DirectoryStringType directoryStringEnum = XmlX509CertprofileUtil.convertDirectoryStringType(
                        t.getDirectoryStringType());
                ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(t.getType().getValue());
                RDNControl occ = new RDNControl(type, t.getMinOccurs(), t.getMaxOccurs(), directoryStringEnum);
                this.subjectDNControls.add(occ);

                List<Pattern> patterns = null;
                if(CollectionUtil.isNotEmpty(t.getRegex()))
                {
                    patterns = new LinkedList<>();
                    for(String regex : t.getRegex())
                    {
                        Pattern pattern = Pattern.compile(regex);
                        patterns.add(pattern);
                    }
                }

                SubjectDNOption option = new SubjectDNOption(t.getPrefix(), t.getSuffix(), patterns,
                        t.getMinLen(), t.getMaxLen());
                this.subjectDNOptions.put(type, option);
            }
        }

        // Extensions
        ExtensionsType extensionsType = conf.getExtensions();

        // Extension controls
        this.extensionControls = XmlX509CertprofileUtil.buildExtensionControls(extensionsType);

        // BasicConstrains
        ASN1ObjectIdentifier type = Extension.basicConstraints;
        if(extensionControls.containsKey(type))
        {
            BasicConstraints extConf = (BasicConstraints) getExtensionValue(
                    type, extensionsType, BasicConstraints.class);
            if(extConf != null)
            {
                this.pathLen = extConf.getPathLen();
            }
        }

        // Extension KeyUsage
        type = Extension.keyUsage;
        if(extensionControls.containsKey(type))
        {
            KeyUsage extConf = (KeyUsage) getExtensionValue(
                    type, extensionsType, KeyUsage.class);
            if(extConf != null)
            {
                this.keyusages = XmlX509CertprofileUtil.buildKeyUsageOptions(extConf);
            }
        }

        // ExtendedKeyUsage
        type = Extension.extendedKeyUsage;
        if(extensionControls.containsKey(type))
        {
            ExtendedKeyUsage extConf = (ExtendedKeyUsage) getExtensionValue(
                    type, extensionsType, ExtendedKeyUsage.class);
            if(extConf != null)
            {
                this.extendedKeyusages = XmlX509CertprofileUtil.buildExtKeyUsageOptions(extConf);
            }
        }

        // AuthorityKeyIdentifier
        type = Extension.authorityKeyIdentifier;
        if(extensionControls.containsKey(type))
        {
            AuthorityKeyIdentifier extConf = (AuthorityKeyIdentifier) getExtensionValue(
                    type, extensionsType, AuthorityKeyIdentifier.class);
            if(extConf != null)
            {
                this.includeIssuerAndSerialInAKI = extConf.isIncludeIssuerAndSerial();
            }
        }

        // Certificate Policies
        type = Extension.certificatePolicies;
        if(extensionControls.containsKey(type))
        {
            CertificatePolicies extConf = (CertificatePolicies) getExtensionValue(
                    type, extensionsType, CertificatePolicies.class);
            if(extConf != null)
            {
                List<CertificatePolicyInformation> policyInfos = XmlX509CertprofileUtil.buildCertificatePolicies(extConf);
                org.bouncycastle.asn1.x509.CertificatePolicies value = X509CertUtil.createCertificatePolicies(policyInfos);
                this.certificatePolicies = new ExtensionValue(extensionControls.get(type).isCritical(), value);
            }
        }

        // Policy Mappings
        type = Extension.policyMappings;
        if(extensionControls.containsKey(type))
        {
            PolicyMappings extConf = (PolicyMappings) getExtensionValue(
                    type, extensionsType, PolicyMappings.class);
            if(extConf != null)
            {
                org.bouncycastle.asn1.x509.PolicyMappings value = XmlX509CertprofileUtil.buildPolicyMappings(extConf);
                this.policyMappings = new ExtensionValue(extensionControls.get(type).isCritical(), value);
            }
        }

        // Name Constrains
        type = Extension.nameConstraints;
        if(extensionControls.containsKey(type))
        {
            NameConstraints extConf = (NameConstraints) getExtensionValue(
                    type, extensionsType, NameConstraints.class);
            if(extConf != null)
            {
                org.bouncycastle.asn1.x509.NameConstraints value = XmlX509CertprofileUtil.buildNameConstrains(extConf);
                this.nameConstraints = new ExtensionValue(extensionControls.get(type).isCritical(), value);
            }
        }

        // Policy Constraints
        type = Extension.policyConstraints;
        if(extensionControls.containsKey(type))
        {
            PolicyConstraints extConf = (PolicyConstraints) getExtensionValue(
                    type, extensionsType, PolicyConstraints.class);
            if(extConf != null)
            {
                ASN1Sequence value = XmlX509CertprofileUtil.buildPolicyConstrains(extConf);
                this.policyConstraints = new ExtensionValue(extensionControls.get(type).isCritical(), value);
            }
        }

        // Inhibit anyPolicy
        type = Extension.inhibitAnyPolicy;
        if(extensionControls.containsKey(type))
        {
            InhibitAnyPolicy extConf = (InhibitAnyPolicy) getExtensionValue(
                    type, extensionsType, InhibitAnyPolicy.class);
            if(extConf != null)
            {
                int skipCerts = extConf.getSkipCerts();
                if(skipCerts < 0)
                {
                    throw new CertprofileException("negative inhibitAnyPolicy.skipCerts is not allowed: " + skipCerts);
                }
                ASN1Integer value = new ASN1Integer(BigInteger.valueOf(skipCerts));
                this.inhibitAnyPolicy =new ExtensionValue(extensionControls.get(type).isCritical(), value);
            }
        }

        // admission
        type = ObjectIdentifiers.id_extension_admission;
        if(extensionControls.containsKey(type))
        {
            Admission extConf = (Admission) getExtensionValue(
                    type, extensionsType, Admission.class);
            if(extConf != null)
            {
                List<ASN1ObjectIdentifier> professionOIDs;
                List<String> professionItems;

                List<String> items = type == null ? null : extConf.getProfessionItem();
                if(CollectionUtil.isEmpty(items))
                {
                    professionItems = null;
                }
                else
                {
                    professionItems = Collections.unmodifiableList(new LinkedList<>(items));
                }

                List<OidWithDescType> oidWithDescs = (type == null) ? null : extConf.getProfessionOid();
                professionOIDs = XmlX509CertprofileUtil.toOIDList(oidWithDescs);

                this.admission = createAdmission(extensionControls.get(type).isCritical(),
                        professionOIDs, professionItems,
                        extConf.getRegistrationNumber(),
                        extConf.getAddProfessionInfo());
            }
        }

        // SubjectAltNameMode
        type = Extension.subjectAlternativeName;
        if(extensionControls.containsKey(type))
        {
            SubjectAltName extConf = (SubjectAltName) getExtensionValue(
                    type, extensionsType, SubjectAltName.class);
            if(extConf != null)
            {
                this.allowedSubjectAltNameModes = XmlX509CertprofileUtil.buildGeneralNameMode(extConf);
            }
        }

        // SubjectInfoAccess
        type = Extension.subjectInfoAccess;
        if(extensionControls.containsKey(type))
        {
            SubjectInfoAccess extConf = (SubjectInfoAccess) getExtensionValue(
                    type, extensionsType, SubjectInfoAccess.class);
            if(extConf != null)
            {
                List<Access> list = extConf.getAccess();
                this.allowedSubjectInfoAccessModes = new HashMap<>();
                for(Access entry : list)
                {
                    this.allowedSubjectInfoAccessModes.put(
                            new ASN1ObjectIdentifier(entry.getAccessMethod().getValue()),
                            XmlX509CertprofileUtil.buildGeneralNameMode(entry.getAccessLocation()));
                }
            }
        }

        // constant extensions
        this.constantExtensions = XmlX509CertprofileUtil.buildConstantExtesions(extensionsType);
    }

    @Override
    public CertValidity getValidity()
    {
        return validity;
    }

    @Override
    public String getParameter(
            String paramName)
    {
        return parameters == null ? null : parameters.get(paramName);
    }

    @Override
    public SubjectInfo getSubject(
            final X500Name requestedSubject)
    throws CertprofileException, BadCertTemplateException
    {
        verifySubjectDNOccurence(requestedSubject);
        checkSubjectContent(requestedSubject);

        RDN[] requstedRDNs = requestedSubject.getRDNs();
        Set<RDNControl> occurences = getSubjectDNControls();
        List<RDN> rdns = new LinkedList<>();
        List<ASN1ObjectIdentifier> types = backwardsSubject() ?
                ObjectIdentifiers.getBackwardDNs() : ObjectIdentifiers.getForwardDNs();

        for(ASN1ObjectIdentifier type : types)
        {
            if(Extension.subjectAlternativeName.equals(type) || Extension.subjectInfoAccess.equals(type))
            {
                continue;
            }

            RDNControl control = null;
            if(occurences != null)
            {
                control = getRDNControl(occurences, type);
                if(control == null || control.getMaxOccurs() < 1)
                {
                    continue;
                }
            }

            RDN[] thisRDNs = getRDNs(requstedRDNs, type);
            int n = thisRDNs == null ? 0 : thisRDNs.length;
            if(n == 0)
            {
                continue;
            }

            if(n == 1)
            {
                String value = X509Util.rdnValueToString(thisRDNs[0].getFirst().getValue());
                rdns.add(createSubjectRDN(value, type, control, 0));
            }
            else
            {
                String[] values = new String[n];
                for(int i = 0; i < n; i++)
                {
                    values[i] = X509Util.rdnValueToString(thisRDNs[i].getFirst().getValue());
                }
                values = sortRDNs(type, values);

                int i = 0;
                for(String value : values)
                {
                    rdns.add(createSubjectRDN(value, type, control, i++));
                }
            }
        }

        X500Name grantedSubject = new X500Name(rdns.toArray(new RDN[0]));
        return new SubjectInfo(grantedSubject, null);
    }

    @Override
    protected RDN createSubjectRDN(
            final String text,
            final ASN1ObjectIdentifier type,
            final RDNControl rdnControl,
            final int index)
    throws BadCertTemplateException
    {
        String ttext = text.trim();

        SubjectDNOption option = subjectDNOptions.get(type);
        if(option != null)
        {
            String prefix = option.getPrefix();
            String suffix = option.getSufix();

            if(prefix != null || suffix != null)
            {
                String _text = ttext.toLowerCase();
                if(prefix != null &&_text.startsWith(prefix.toLowerCase()))
                {
                    ttext = ttext.substring(prefix.length());
                    _text = ttext.toLowerCase();
                }

                if(suffix != null && _text.endsWith(suffix.toLowerCase()))
                {
                    ttext = ttext.substring(0, ttext.length() - suffix.length());
                }
            }

            List<Pattern> patterns = option.getPatterns();
            if(patterns != null)
            {
                Pattern p = patterns.get(index);
                if(p.matcher(ttext).matches() == false)
                {
                    throw new BadCertTemplateException("invalid subject " + ObjectIdentifiers.oidToDisplayName(type) +
                            " '" + ttext + "' against regex '" + p.pattern() + "'");
                }
            }

            StringBuilder sb = new StringBuilder();
            if(prefix != null)
            {
                sb.append(prefix);
            }
            sb.append(ttext);
            if(suffix != null)
            {
                sb.append(suffix);
            }
            ttext = sb.toString();

            int len = ttext.length();
            Integer minLen = option.getMinLen();
            if(minLen != null && len < minLen)
            {
                throw new BadCertTemplateException("subject " + ObjectIdentifiers.oidToDisplayName(type) +
                        " '" + ttext + "' is too short (length (" + len + ") < minLen (" + minLen + ")");
            }

            Integer maxLen = option.getMaxLen();
            if(maxLen != null && len > maxLen)
            {
                throw new BadCertTemplateException("subject " + ObjectIdentifiers.oidToDisplayName(type) +
                        " '" + ttext + "' is too long (length (" + len + ") > maxLen (" + maxLen + ")");
            }
        }

        return super.createSubjectRDN(ttext, type, rdnControl, index);
    }

    @Override
    protected String[] sortRDNs(
            final ASN1ObjectIdentifier type,
            final String[] values)
    {
        SubjectDNOption option = subjectDNOptions.get(type);
        if(option == null)
        {
            return values;
        }

        List<Pattern> patterns = option.getPatterns();
        if(CollectionUtil.isEmpty(patterns))
        {
            return values;
        }

        List<String> result = new ArrayList<>(values.length);
        for(Pattern p : patterns)
        {
            for(String value : values)
            {
                if(result.contains(value) == false && p.matcher(value).matches())
                {
                    result.add(value);
                }
            }
        }
        for(String value : values)
        {
            if(result.contains(value) == false)
            {
                result.add(value);
            }
        }

        return result.toArray(new String[0]);
    }

    @Override
    public ExtensionValues getExtensions(
            final Map<ASN1ObjectIdentifier, ExtensionControl> extensionOccurences,
            final X500Name requestedSubject,
            final Extensions requestedExtensions)
    throws CertprofileException, BadCertTemplateException
    {
        ExtensionValues values = new ExtensionValues();
        if(CollectionUtil.isEmpty(extensionOccurences))
        {
            return values;
        }

        Map<ASN1ObjectIdentifier, ExtensionControl> occurences = new HashMap<>(extensionOccurences);

        // AuthorityKeyIdentifier
        // processed by the CA

        // SubjectKeyIdentifier
        // processed by the CA

        // KeyUsage
        // processed by the CA

        // CertificatePolicies
        ASN1ObjectIdentifier type = Extension.certificatePolicies;
        if(certificatePolicies != null && occurences.remove(type) != null)
        {
            values.addExtension(type, certificatePolicies);
        }

        // Policy Mappings
        type = Extension.policyMappings;
        if(policyMappings != null && occurences.remove(type) != null)
        {
            values.addExtension(type, policyMappings);
        }

        // SubjectAltName
        // processed by the CA

        // IssuerAltName
        // processed by the CA

        // Subject Directory Attributes
        // Will not supported

        // Basic Constraints
        // processed by the CA

        // Name Constraints
        type = Extension.nameConstraints;
        if(nameConstraints != null && occurences.remove(type) != null)
        {
            values.addExtension(type, nameConstraints);
        }

        // PolicyConstrains
        type = Extension.policyConstraints;
        if(policyConstraints != null && occurences.remove(type) != null)
        {
            values.addExtension(type, policyConstraints);
        }

        // ExtendedKeyUsage
        // processed by CA

        // CRL Distribution Points
        // processed by the CA

        // Inhibit anyPolicy
        type = Extension.inhibitAnyPolicy;
        if(inhibitAnyPolicy != null && occurences.remove(type) != null)
        {
            values.addExtension(type, inhibitAnyPolicy);
        }

        // Freshest CRL
        // processed by the CA

        // Authority Information Access
        // processed by the CA

        // Subject Information Access
        // processed by the CA

        // Admission
        type = ObjectIdentifiers.id_extension_admission;
        if(admission != null && occurences.remove(type) != null)
        {
            values.addExtension(type, admission);
        }

        // OCSP Nocheck
        // processed by the CA

        // constant extensions
        if(constantExtensions != null)
        {
            for(ASN1ObjectIdentifier m : constantExtensions.keySet())
            {
                ExtensionControl occurence = occurences.remove(m);
                if(occurence == null)
                {
                    continue;
                }

                ExtensionValue extensionValue = constantExtensions.get(m);
                if(extensionValue != null)
                {
                    values.addExtension(m, extensionValue);
                }
            }
        }

        return values;
    }

    @Override
    public boolean incSerialNumberIfSubjectExists()
    {
        return incSerialNoIfSubjectExists;
    }

    @Override
    public Set<KeyUsageControl> getKeyUsage()
    {
        return keyusages;
    }

    @Override
    public Set<ExtKeyUsageControl> getExtendedKeyUsages()
    {
        return extendedKeyusages;
    }

    @Override
    public boolean isCA()
    {
        return ca;
    }

    @Override
    public Integer getPathLenBasicConstraint()
    {
        return pathLen;
    }

    @Override
    public boolean hasMidnightNotBefore()
    {
        return notBeforeMidnight;
    }

    @Override
    public Map<ASN1ObjectIdentifier, ExtensionControl> getExtensionControls()
    {
        return extensionControls;
    }

    @Override
    public boolean backwardsSubject()
    {
        return backwardsSubject;
    }

    @Override
    public boolean isOnlyForRA()
    {
        return raOnly;
    }

    @Override
    public boolean isOnlyForQA()
    {
        return qaOnly;
    }

    @Override
    public boolean includeIssuerAndSerialInAKI()
    {
        return includeIssuerAndSerialInAKI;
    }

    @Override
    public Set<RDNControl> getSubjectDNControls()
    {
        return subjectDNControls;
    }

    @Override
    public SpecialX509CertprofileBehavior getSpecialCertprofileBehavior()
    {
        return specialBehavior;
    }

    private ExtensionValue createAdmission(
            final boolean critical,
            final List<ASN1ObjectIdentifier> professionOIDs,
            final List<String> professionItems,
            final String registrationNumber,
            final byte[] addProfessionInfo)
    throws CertprofileException
    {
        if(CollectionUtil.isEmpty(professionItems)
                && CollectionUtil.isEmpty(professionOIDs)
                &&  StringUtil.isBlank(registrationNumber)
                && (addProfessionInfo == null || addProfessionInfo.length == 0))
        {
            return null;
        }

        DirectoryString[] _professionItems = null;
        if(professionItems != null && professionItems.size() > 0)
        {
            int n = professionItems.size();
            _professionItems = new DirectoryString[n];
            for(int i = 0; i < n; i++)
            {
                _professionItems[i] = new DirectoryString(professionItems.get(i));
            }
        }

        ASN1ObjectIdentifier[] _professionOIDs = null;
        if(professionOIDs != null && professionOIDs.size() > 0)
        {
            _professionOIDs = professionOIDs.toArray(new ASN1ObjectIdentifier[0]);
        }

        ASN1OctetString _addProfessionInfo = null;
        if(addProfessionInfo != null && addProfessionInfo.length > 0)
        {
            _addProfessionInfo = new DEROctetString(addProfessionInfo);
        }

        ProfessionInfo professionInfo = new ProfessionInfo(
                null, _professionItems, _professionOIDs, registrationNumber, _addProfessionInfo);

        Admissions admissions = new Admissions(null, null,
                new ProfessionInfo[]{professionInfo});

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(admissions);

        AdmissionSyntax value = new AdmissionSyntax(null, new DERSequence(vector));
        return new ExtensionValue(critical, value);
    }

    @Override
    public boolean isDuplicateKeyPermitted()
    {
        return duplicateKeyPermitted;
    }

    @Override
    public boolean isDuplicateSubjectPermitted()
    {
        return duplicateSubjectPermitted;
    }

    @Override
    public boolean isSerialNumberInReqPermitted()
    {
        return serialNumberInReqPermitted;
    }

    @Override
    public Set<GeneralNameMode> getSubjectAltNameModes()
    {
        return allowedSubjectAltNameModes;
    }

    @Override
    protected Map<ASN1ObjectIdentifier, KeyParametersOption> getKeyAlgorithms()
    {
        return keyAlgorithms;
    }

    @Override
    public Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> getSubjectInfoAccessModes()
    {
        return allowedSubjectInfoAccessModes;
    }

    @Override
    public X509CertVersion getVersion()
    {
        return version;
    }

    @Override
    public Set<ASN1ObjectIdentifier> getSignatureAlgorithms()
    {
        return signatureAlgorithms;
    }

    private static Object getExtensionValue(
            final ASN1ObjectIdentifier type,
            final ExtensionsType extensionsType,
            final Class<?> expectedClass)
    throws CertprofileException
    {
        for(ExtensionType m : extensionsType.getExtension())
        {
            if(m.getType().getValue().equals(type.getId()) == false)
            {
                continue;
            }

            if(m.getValue() == null || m.getValue().getAny() == null)
            {
                return null;
            }

            Object o = m.getValue().getAny();
            if(expectedClass.isAssignableFrom(o.getClass()))
            {
                return o;
            }
            else if(ConstantExtValue.class.isAssignableFrom(o.getClass()))
            {
                // will be processed later
            }
            else
            {
                String displayName = ObjectIdentifiers.oidToDisplayName(type);
                throw new CertprofileException("the extension configuration for " + displayName +
                        " is not of the expected type " + expectedClass.getName());
            }
        }

        throw new RuntimeException("should not reach here: undefined extension " +
                ObjectIdentifiers.oidToDisplayName(type));
    }

}
