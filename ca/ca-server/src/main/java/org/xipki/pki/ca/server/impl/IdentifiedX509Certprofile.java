/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.pki.ca.server.impl;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
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
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.pki.ca.api.BadCertTemplateException;
import org.xipki.pki.ca.api.BadFormatException;
import org.xipki.pki.ca.api.EnvParameterResolver;
import org.xipki.pki.ca.api.NameId;
import org.xipki.pki.ca.api.profile.CertValidity;
import org.xipki.pki.ca.api.profile.CertprofileException;
import org.xipki.pki.ca.api.profile.ExtensionControl;
import org.xipki.pki.ca.api.profile.ExtensionValue;
import org.xipki.pki.ca.api.profile.ExtensionValues;
import org.xipki.pki.ca.api.profile.GeneralNameMode;
import org.xipki.pki.ca.api.profile.x509.AuthorityInfoAccessControl;
import org.xipki.pki.ca.api.profile.x509.ExtKeyUsageControl;
import org.xipki.pki.ca.api.profile.x509.KeyUsageControl;
import org.xipki.pki.ca.api.profile.x509.SpecialX509CertprofileBehavior;
import org.xipki.pki.ca.api.profile.x509.SubjectDnSpec;
import org.xipki.pki.ca.api.profile.x509.SubjectInfo;
import org.xipki.pki.ca.api.profile.x509.X509CertLevel;
import org.xipki.pki.ca.api.profile.x509.X509CertVersion;
import org.xipki.pki.ca.api.profile.x509.X509Certprofile;
import org.xipki.pki.ca.api.profile.x509.X509CertprofileUtil;
import org.xipki.pki.ca.server.impl.util.CaUtil;
import org.xipki.pki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.security.ExtensionExistence;
import org.xipki.security.HashAlgoType;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class IdentifiedX509Certprofile {

    private static final Set<ASN1ObjectIdentifier> CRITICAL_ONLY_EXTENSION_TYPES;

    private static final Set<ASN1ObjectIdentifier> CA_CRITICAL_ONLY_EXTENSION_TYPES;

    private static final Set<ASN1ObjectIdentifier> NONCRITICAL_ONLY_EXTENSION_TYPES;

    private static final Set<ASN1ObjectIdentifier> CA_ONLY_EXTENSION_TYPES;

    private static final Set<ASN1ObjectIdentifier> NONE_REQUEST_EXTENSION_TYPES;

    private static final Set<ASN1ObjectIdentifier> REQUIRED_CA_EXTENSION_TYPES;

    private static final Set<ASN1ObjectIdentifier> REQUIRED_EE_EXTENSION_TYPES;

    static {
        CRITICAL_ONLY_EXTENSION_TYPES = new HashSet<>();
        CRITICAL_ONLY_EXTENSION_TYPES.add(Extension.keyUsage);
        CRITICAL_ONLY_EXTENSION_TYPES.add(Extension.policyMappings);
        CRITICAL_ONLY_EXTENSION_TYPES.add(Extension.nameConstraints);
        CRITICAL_ONLY_EXTENSION_TYPES.add(Extension.policyConstraints);
        CRITICAL_ONLY_EXTENSION_TYPES.add(Extension.inhibitAnyPolicy);
        CRITICAL_ONLY_EXTENSION_TYPES.add(ObjectIdentifiers.id_pe_tlsfeature);

        CA_CRITICAL_ONLY_EXTENSION_TYPES = new HashSet<>();
        CA_CRITICAL_ONLY_EXTENSION_TYPES.add(Extension.basicConstraints);

        NONCRITICAL_ONLY_EXTENSION_TYPES = new HashSet<>();
        NONCRITICAL_ONLY_EXTENSION_TYPES.add(Extension.authorityKeyIdentifier);
        NONCRITICAL_ONLY_EXTENSION_TYPES.add(Extension.subjectKeyIdentifier);
        NONCRITICAL_ONLY_EXTENSION_TYPES.add(Extension.issuerAlternativeName);
        NONCRITICAL_ONLY_EXTENSION_TYPES.add(Extension.subjectDirectoryAttributes);
        NONCRITICAL_ONLY_EXTENSION_TYPES.add(Extension.freshestCRL);
        NONCRITICAL_ONLY_EXTENSION_TYPES.add(Extension.authorityInfoAccess);
        NONCRITICAL_ONLY_EXTENSION_TYPES.add(Extension.subjectInfoAccess);

        CA_ONLY_EXTENSION_TYPES = new HashSet<>();
        CA_ONLY_EXTENSION_TYPES.add(Extension.policyMappings);
        CA_ONLY_EXTENSION_TYPES.add(Extension.nameConstraints);
        CA_ONLY_EXTENSION_TYPES.add(Extension.policyConstraints);
        CA_ONLY_EXTENSION_TYPES.add(Extension.inhibitAnyPolicy);

        NONE_REQUEST_EXTENSION_TYPES = new HashSet<ASN1ObjectIdentifier>();
        NONE_REQUEST_EXTENSION_TYPES.add(Extension.subjectKeyIdentifier);
        NONE_REQUEST_EXTENSION_TYPES.add(Extension.authorityKeyIdentifier);
        NONE_REQUEST_EXTENSION_TYPES.add(Extension.issuerAlternativeName);
        NONE_REQUEST_EXTENSION_TYPES.add(Extension.cRLDistributionPoints);
        NONE_REQUEST_EXTENSION_TYPES.add(Extension.freshestCRL);
        NONE_REQUEST_EXTENSION_TYPES.add(Extension.basicConstraints);
        NONE_REQUEST_EXTENSION_TYPES.add(Extension.inhibitAnyPolicy);

        REQUIRED_CA_EXTENSION_TYPES = new HashSet<>();
        REQUIRED_CA_EXTENSION_TYPES.add(Extension.basicConstraints);
        REQUIRED_CA_EXTENSION_TYPES.add(Extension.subjectKeyIdentifier);
        REQUIRED_CA_EXTENSION_TYPES.add(Extension.keyUsage);

        REQUIRED_EE_EXTENSION_TYPES = new HashSet<>();
        REQUIRED_EE_EXTENSION_TYPES.add(Extension.authorityKeyIdentifier);
        REQUIRED_EE_EXTENSION_TYPES.add(Extension.subjectKeyIdentifier);
    } // end static

    private final CertprofileEntry dbEntry;
    private final X509Certprofile certprofile;

    IdentifiedX509Certprofile(final CertprofileEntry dbEntry, final X509Certprofile certProfile)
            throws CertprofileException {
        this.dbEntry = ParamUtil.requireNonNull("entry", dbEntry);
        this.certprofile = ParamUtil.requireNonNull("certProfile", certProfile);

        this.certprofile.initialize(dbEntry.conf());
        if (certProfile.specialCertprofileBehavior()
                == SpecialX509CertprofileBehavior.gematik_gSMC_K) {
            String paramName = SpecialX509CertprofileBehavior.PARAMETER_MAXLIFTIME;
            String str = certProfile.parameter(paramName);
            if (str == null) {
                throw new CertprofileException("parameter " + paramName + " is not defined");
            }

            str = str.trim();
            int idx;
            try {
                idx = Integer.parseInt(str);
            } catch (NumberFormatException ex) {
                throw new CertprofileException("invalid " + paramName + ": " + str);
            }
            if (idx < 1) {
                throw new CertprofileException("invalid " + paramName + ": " + str);
            }
        }

    } // constructor

    public NameId ident() {
        return dbEntry.ident();
    }

    public CertprofileEntry dbEntry() {
        return dbEntry;
    }

    public X509CertVersion version() {
        return certprofile.version();
    }

    public List<String> signatureAlgorithms() {
        return certprofile.signatureAlgorithms();
    }

    public SpecialX509CertprofileBehavior specialCertprofileBehavior() {
        return certprofile.specialCertprofileBehavior();
    }

    public void setEnvParameterResolver(final EnvParameterResolver envParameterResolver) {
        if (certprofile != null) {
            certprofile.setEnvParameterResolver(envParameterResolver);
        }
    }

    public Date notBefore(final Date notBefore) {
        return certprofile.getNotBefore(notBefore);
    }

    public CertValidity validity() {
        return certprofile.validity();
    }

    public boolean hasMidnightNotBefore() {
        return certprofile.hasMidnightNotBefore();
    }

    public TimeZone timezone() {
        return certprofile.timezone();
    }

    public SubjectInfo getSubject(final X500Name requestedSubject)
            throws CertprofileException, BadCertTemplateException {
        SubjectInfo subjectInfo = certprofile.getSubject(requestedSubject);
        RDN[] countryRdns = subjectInfo.grantedSubject().getRDNs(ObjectIdentifiers.DN_C);
        if (countryRdns != null) {
            for (RDN rdn : countryRdns) {
                String textValue = IETFUtils.valueToString(rdn.getFirst().getValue());
                if (!SubjectDnSpec.isValidCountryAreaCode(textValue)) {
                    throw new BadCertTemplateException("invalid country/area code '" + textValue
                            + "'");
                }
            }
        }
        return subjectInfo;
    }

    /**
     *
     * @param requestedSubject
     *          Subject requested subject. Must not be {@code null}.
     * @param grantedSubject
     *          Granted subject. Must not be {@code null}.
     * @param requestedExtensions
     *          Extensions requested by the requestor. Could be {@code null}.
     * @param publicKeyInfo
     *          Subject public key. Must not be {@code null}.
     * @param publicCaInfo
     *          CA information. Must not be {@code null}.
     * @param crlSignerCert
     *          CRL signer certificate. Could be {@code null}.
     * @param notBefore
     *          NotBefore. Must not be {@code null}.
     * @param notAfter
     *          NotAfter. Must not be {@code null}.
     * @return the extensions of the certificate to be issued.
     */
    public ExtensionValues getExtensions(final X500Name requestedSubject,
            final X500Name grantedSubject, final Extensions requestedExtensions,
            final SubjectPublicKeyInfo publicKeyInfo,
            final PublicCaInfo publicCaInfo, final X509Certificate crlSignerCert,
            final Date notBefore, final Date notAfter)
            throws CertprofileException, BadCertTemplateException {
        ParamUtil.requireNonNull("publicKeyInfo", publicKeyInfo);
        ExtensionValues values = new ExtensionValues();

        Map<ASN1ObjectIdentifier, ExtensionControl> controls
                = new HashMap<>(certprofile.extensionControls());

        Set<ASN1ObjectIdentifier> neededExtTypes = new HashSet<>();
        Set<ASN1ObjectIdentifier> wantedExtTypes = new HashSet<>();
        if (requestedExtensions != null) {
            Extension reqExtension = requestedExtensions.getExtension(
                    ObjectIdentifiers.id_xipki_ext_cmpRequestExtensions);
            if (reqExtension != null) {
                ExtensionExistence ee = ExtensionExistence.getInstance(
                        reqExtension.getParsedValue());
                neededExtTypes.addAll(ee.needExtensions());
                wantedExtTypes.addAll(ee.wantExtensions());
            }

            for (ASN1ObjectIdentifier oid : neededExtTypes) {
                if (wantedExtTypes.contains(oid)) {
                    wantedExtTypes.remove(oid);
                }

                if (!controls.containsKey(oid)) {
                    throw new BadCertTemplateException(
                            "could not add needed extension " + oid.getId());
                }
            }
        }

        // SubjectKeyIdentifier
        ASN1ObjectIdentifier extType = Extension.subjectKeyIdentifier;
        ExtensionControl extControl = controls.remove(extType);
        if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
            byte[] encodedSpki = publicKeyInfo.getPublicKeyData().getBytes();
            byte[] skiValue = HashAlgoType.SHA1.hash(encodedSpki);
            SubjectKeyIdentifier value = new SubjectKeyIdentifier(skiValue);
            addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
        }

        // Authority key identifier
        extType = Extension.authorityKeyIdentifier;
        extControl = controls.remove(extType);
        if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
            byte[] ikiValue = publicCaInfo.subjectKeyIdentifer();
            AuthorityKeyIdentifier value = null;
            if (ikiValue != null) {
                if (certprofile.includeIssuerAndSerialInAki()) {
                    GeneralNames x509CaSubject = new GeneralNames(
                            new GeneralName(publicCaInfo.x500Subject()));
                    value = new AuthorityKeyIdentifier(ikiValue, x509CaSubject,
                            publicCaInfo.serialNumber());
                } else {
                    value = new AuthorityKeyIdentifier(ikiValue);
                }
            }

            addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
        }

        // IssuerAltName
        extType = Extension.issuerAlternativeName;
        extControl = controls.remove(extType);
        if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
            GeneralNames value = publicCaInfo.subjectAltName();
            addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
        }

        // AuthorityInfoAccess
        extType = Extension.authorityInfoAccess;
        extControl = controls.remove(extType);
        if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
            AuthorityInfoAccessControl aiaControl = certprofile.aiaControl();

            List<String> caIssuers = null;
            if (aiaControl == null || aiaControl.includesCaIssuers()) {
                caIssuers = publicCaInfo.caCertUris();
            }

            List<String> ocspUris = null;
            if (aiaControl == null || aiaControl.includesOcsp()) {
                ocspUris = publicCaInfo.ocspUris();
            }

            if (CollectionUtil.isNonEmpty(caIssuers) || CollectionUtil.isNonEmpty(ocspUris)) {
                AuthorityInformationAccess value = CaUtil.createAuthorityInformationAccess(
                        caIssuers, ocspUris);
                addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
            }
        }

        if (controls.containsKey(Extension.cRLDistributionPoints)
                || controls.containsKey(Extension.freshestCRL)) {
            X500Name crlSignerSubject = (crlSignerCert == null) ? null
                    : X500Name.getInstance(crlSignerCert.getSubjectX500Principal().getEncoded());
            X500Name x500CaPrincipal = publicCaInfo.x500Subject();

            // CRLDistributionPoints
            extType = Extension.cRLDistributionPoints;
            extControl = controls.remove(extType);
            if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
                if (CollectionUtil.isNonEmpty(publicCaInfo.crlUris())) {
                    CRLDistPoint value = CaUtil.createCrlDistributionPoints(
                            publicCaInfo.crlUris(), x500CaPrincipal, crlSignerSubject);
                    addExtension(values, extType, value, extControl, neededExtTypes,
                            wantedExtTypes);
                }
            }

            // FreshestCRL
            extType = Extension.freshestCRL;
            extControl = controls.remove(extType);
            if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
                if (CollectionUtil.isNonEmpty(publicCaInfo.deltaCrlUris())) {
                    CRLDistPoint value = CaUtil.createCrlDistributionPoints(
                            publicCaInfo.deltaCrlUris(), x500CaPrincipal, crlSignerSubject);
                    addExtension(values, extType, value, extControl, neededExtTypes,
                            wantedExtTypes);
                }
            }
        }

        // BasicConstraints
        extType = Extension.basicConstraints;
        extControl = controls.remove(extType);
        if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
            BasicConstraints value = CaUtil.createBasicConstraints(certprofile.certLevel(),
                    certprofile.pathLenBasicConstraint());
            addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
        }

        // KeyUsage
        extType = Extension.keyUsage;
        extControl = controls.remove(extType);
        if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
            Set<KeyUsage> usages = new HashSet<>();
            Set<KeyUsageControl> usageOccs = certprofile.keyUsage();
            for (KeyUsageControl k : usageOccs) {
                if (k.isRequired()) {
                    usages.add(k.keyUsage());
                }
            }

            // the optional KeyUsage will only be set if requested explicitly
            if (requestedExtensions != null && extControl.isRequest()) {
                addRequestedKeyusage(usages, requestedExtensions, usageOccs);
            }

            org.bouncycastle.asn1.x509.KeyUsage value = X509Util.createKeyUsage(usages);
            addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
        }

        // ExtendedKeyUsage
        extType = Extension.extendedKeyUsage;
        extControl = controls.remove(extType);
        if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
            List<ASN1ObjectIdentifier> usages = new LinkedList<>();
            Set<ExtKeyUsageControl> usageOccs = certprofile.extendedKeyUsages();
            for (ExtKeyUsageControl k : usageOccs) {
                if (k.isRequired()) {
                    usages.add(k.extKeyUsage());
                }
            }

            // the optional ExtKeyUsage will only be set if requested explicitly
            if (requestedExtensions != null && extControl.isRequest()) {
                addRequestedExtKeyusage(usages, requestedExtensions, usageOccs);
            }

            if (extControl.isCritical()
                    && usages.contains(ObjectIdentifiers.id_anyExtendedKeyUsage)) {
                extControl = new ExtensionControl(false, extControl.isRequired(),
                        extControl.isRequest());
            }

            ExtendedKeyUsage value = X509Util.createExtendedUsage(usages);
            addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
        }

        // ocsp-nocheck
        extType = ObjectIdentifiers.id_extension_pkix_ocsp_nocheck;
        extControl = controls.remove(extType);
        if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
            // the extension ocsp-nocheck will only be set if requested explicitly
            DERNull value = DERNull.INSTANCE;
            addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
        }

        // SubjectInfoAccess
        extType = Extension.subjectInfoAccess;
        extControl = controls.remove(extType);
        if (extControl != null && addMe(extType, extControl, neededExtTypes, wantedExtTypes)) {
            ASN1Sequence value = null;
            if (requestedExtensions != null && extControl.isRequest()) {
                value = createSubjectInfoAccess(requestedExtensions,
                        certprofile.subjectInfoAccessModes());
            }
            addExtension(values, extType, value, extControl, neededExtTypes, wantedExtTypes);
        }

        ExtensionValues subvalues = certprofile.getExtensions(
                Collections.unmodifiableMap(controls), requestedSubject, grantedSubject,
                requestedExtensions, notBefore, notAfter);

        Set<ASN1ObjectIdentifier> extTypes = new HashSet<>(controls.keySet());
        for (ASN1ObjectIdentifier type : extTypes) {
            extControl = controls.remove(type);
            boolean addMe = addMe(type, extControl, neededExtTypes, wantedExtTypes);
            if (addMe) {
                ExtensionValue value = null;
                if (requestedExtensions != null && extControl.isRequest()) {
                    Extension reqExt = requestedExtensions.getExtension(type);
                    if (reqExt != null) {
                        value = new ExtensionValue(reqExt.isCritical(), reqExt.getParsedValue());
                    }
                }

                if (value == null) {
                    value = subvalues.getExtensionValue(type);
                }

                addExtension(values, type, value, extControl, neededExtTypes, wantedExtTypes);
            }
        }

        Set<ASN1ObjectIdentifier> unprocessedExtTypes = new HashSet<>();
        for (ASN1ObjectIdentifier type : controls.keySet()) {
            if (controls.get(type).isRequired()) {
                unprocessedExtTypes.add(type);
            }
        }

        if (CollectionUtil.isNonEmpty(unprocessedExtTypes)) {
            throw new CertprofileException(
                    "could not add required extensions " + toString(unprocessedExtTypes));
        }

        if (CollectionUtil.isNonEmpty(neededExtTypes)) {
            throw new BadCertTemplateException(
                    "could not add requested extensions " + toString(neededExtTypes));
        }

        return values;
    } // method getExtensions

    public X509CertLevel certLevel() {
        return certprofile.certLevel();
    }

    public boolean isOnlyForRa() {
        return certprofile.isOnlyForRa();
    }

    public SubjectPublicKeyInfo checkPublicKey(final SubjectPublicKeyInfo publicKey)
            throws BadCertTemplateException {
        ParamUtil.requireNonNull("publicKey", publicKey);
        return certprofile.checkPublicKey(publicKey);
    }

    public boolean incSerialNumberIfSubjectExists() {
        return certprofile.incSerialNumberIfSubjectExists();
    }

    public void shutdown() {
        if (certprofile != null) {
            certprofile.shutdown();
        }
    }

    public boolean includeIssuerAndSerialInAki() {
        return certprofile.includeIssuerAndSerialInAki();
    }

    public String incSerialNumber(final String currentSerialNumber) throws BadFormatException {
        return certprofile.incSerialNumber(currentSerialNumber);
    }

    public boolean isDuplicateKeyPermitted() {
        return certprofile.isDuplicateKeyPermitted();
    }

    public boolean isDuplicateSubjectPermitted() {
        return certprofile.isDuplicateSubjectPermitted();
    }

    public boolean isSerialNumberInReqPermitted() {
        return certprofile.isSerialNumberInReqPermitted();
    }

    public String parameter(final String paramName) {
        return certprofile.parameter(paramName);
    }

    public Map<ASN1ObjectIdentifier, ExtensionControl> extensionControls() {
        return certprofile.extensionControls();
    }

    public Set<KeyUsageControl> keyUsage() {
        return certprofile.keyUsage();
    }

    public Integer pathLenBasicConstraint() {
        return certprofile.pathLenBasicConstraint();
    }

    public Set<ExtKeyUsageControl> extendedKeyUsages() {
        return certprofile.extendedKeyUsages();
    }

    public int maxCertSize() {
        return certprofile.maxCertSize();
    }

    public void validate() throws CertprofileException {
        StringBuilder msg = new StringBuilder();

        Map<ASN1ObjectIdentifier, ExtensionControl> controls = extensionControls();

        // make sure that non-request extensions are not permitted in requests
        Set<ASN1ObjectIdentifier> set = new HashSet<>();
        for (ASN1ObjectIdentifier type : NONE_REQUEST_EXTENSION_TYPES) {
            ExtensionControl control = controls.get(type);
            if (control != null && control.isRequest()) {
                set.add(type);
            }
        }

        if (CollectionUtil.isNonEmpty(set)) {
            msg.append("extensions ").append(toString(set));
            msg.append(" must not be contained in request, ");
        }

        X509CertLevel level = certLevel();
        boolean ca = (level == X509CertLevel.RootCA) || (level == X509CertLevel.SubCA);

        // make sure that CA-only extensions are not permitted in EE certificate
        set.clear();
        if (!ca) {
            set.clear();
            for (ASN1ObjectIdentifier type : CA_ONLY_EXTENSION_TYPES) {
                if (controls.containsKey(type)) {
                    set.add(type);
                }
            }

            if (CollectionUtil.isNonEmpty(set)) {
                msg.append("EE profile contains CA-only extensions ").append(toString(set))
                    .append(", ");
            }
        }

        // make sure that critical only extensions are not marked as non-critical.
        set.clear();
        for (ASN1ObjectIdentifier type : controls.keySet()) {
            ExtensionControl control = controls.get(type);
            if (CRITICAL_ONLY_EXTENSION_TYPES.contains(type)) {
                if (!control.isCritical()) {
                    set.add(type);
                }
            }

            if (ca && CA_CRITICAL_ONLY_EXTENSION_TYPES.contains(type)) {
                if (!control.isCritical()) {
                    set.add(type);
                }
            }
        }

        if (CollectionUtil.isNonEmpty(set)) {
            msg.append("critical only extensions are marked as non-critical ");
            msg.append(toString(set)).append(", ");
        }

        // make sure that non-critical only extensions are not marked as critical.
        set.clear();
        for (ASN1ObjectIdentifier type : controls.keySet()) {
            ExtensionControl control = controls.get(type);
            if (NONCRITICAL_ONLY_EXTENSION_TYPES.contains(type)) {
                if (control.isCritical()) {
                    set.add(type);
                }
            }
        }

        if (CollectionUtil.isNonEmpty(set)) {
            msg.append("non-critical extensions are marked as critical ").append(toString(set));
            msg.append(", ");
        }

        // make sure that required extensions are present
        set.clear();
        Set<ASN1ObjectIdentifier> requiredTypes = ca ? REQUIRED_CA_EXTENSION_TYPES
                : REQUIRED_EE_EXTENSION_TYPES;

        for (ASN1ObjectIdentifier type : requiredTypes) {
            ExtensionControl extCtrl = controls.get(type);
            if (extCtrl == null || !extCtrl.isRequired()) {
                set.add(type);
            }
        }

        if (level == X509CertLevel.SubCA) {
            ASN1ObjectIdentifier type = Extension.authorityKeyIdentifier;
            ExtensionControl extCtrl = controls.get(type);
            if (extCtrl == null || !extCtrl.isRequired()) {
                set.add(type);
            }
        }

        if (!set.isEmpty()) {
            msg.append("required extensions are not marked as required ");
            msg.append(toString(set)).append(", ");
        }

        // KeyUsage
        Set<KeyUsageControl> usages = keyUsage();

        if (ca) {
            // make sure the CA certificate contains usage keyCertSign
            if (!containsKeyusage(usages, KeyUsage.keyCertSign)) {
                msg.append("CA profile does not contain keyUsage ");
                msg.append(KeyUsage.keyCertSign).append(", ");
            }
        } else {
            // make sure the EE certificate does not contain CA-only usages
            KeyUsage[] caOnlyUsages = new KeyUsage[] {KeyUsage.keyCertSign, KeyUsage.cRLSign};

            Set<KeyUsage> setUsages = new HashSet<>();
            for (KeyUsage caOnlyUsage : caOnlyUsages) {
                if (containsKeyusage(usages, caOnlyUsage)) {
                    setUsages.add(caOnlyUsage);
                }
            }

            if (CollectionUtil.isNonEmpty(set)) {
                msg.append("EE profile contains CA-only keyUsage ").append(setUsages).append(", ");
            }
        }

        final int len = msg.length();
        if (len > 2) {
            msg.delete(len - 2, len);
            throw new CertprofileException(msg.toString());
        }
    } // method validate

    private static String toString(final Set<ASN1ObjectIdentifier> oids) {
        if (oids == null) {
            return "null";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("[");

        for (ASN1ObjectIdentifier oid : oids) {
            String name = ObjectIdentifiers.getName(oid);
            if (name != null) {
                sb.append(name);
                sb.append(" (").append(oid.getId()).append(")");
            } else {
                sb.append(oid.getId());
            }
            sb.append(", ");
        }

        if (CollectionUtil.isNonEmpty(oids)) {
            int len = sb.length();
            sb.delete(len - 2, len);
        }
        sb.append("]");

        return sb.toString();
    } // method toString

    private static boolean containsKeyusage(final Set<KeyUsageControl> usageControls,
            final KeyUsage usage) {
        for (KeyUsageControl entry : usageControls) {
            if (usage == entry.keyUsage()) {
                return true;
            }
        }
        return false;
    }

    private static boolean addMe(final ASN1ObjectIdentifier extType,
            final ExtensionControl extControl, final Set<ASN1ObjectIdentifier> neededExtTypes,
            final Set<ASN1ObjectIdentifier> wantedExtTypes) {
        boolean addMe = extControl.isRequired();
        if (addMe) {
            return true;
        }

        return neededExtTypes.contains(extType) || wantedExtTypes.contains(extType);
    } // method addMe

    private static void addRequestedKeyusage(final Set<KeyUsage> usages,
            final Extensions requestedExtensions, final Set<KeyUsageControl> usageOccs) {
        Extension extension = requestedExtensions.getExtension(Extension.keyUsage);
        if (extension == null) {
            return;
        }

        org.bouncycastle.asn1.x509.KeyUsage reqKeyUsage =
                org.bouncycastle.asn1.x509.KeyUsage.getInstance(extension.getParsedValue());
        for (KeyUsageControl k : usageOccs) {
            if (k.isRequired()) {
                continue;
            }

            if (reqKeyUsage.hasUsages(k.keyUsage().bcUsage())) {
                usages.add(k.keyUsage());
            }
        }
    } // method addRequestedKeyusage

    private static void addRequestedExtKeyusage(final List<ASN1ObjectIdentifier> usages,
            final Extensions requestedExtensions, final Set<ExtKeyUsageControl> usageOccs) {
        Extension extension = requestedExtensions.getExtension(Extension.extendedKeyUsage);
        if (extension == null) {
            return;
        }

        ExtendedKeyUsage reqKeyUsage =
                ExtendedKeyUsage.getInstance(extension.getParsedValue());
        for (ExtKeyUsageControl k : usageOccs) {
            if (k.isRequired()) {
                continue;
            }

            if (reqKeyUsage.hasKeyPurposeId(KeyPurposeId.getInstance(k.extKeyUsage()))) {
                usages.add(k.extKeyUsage());
            }
        }
    } // method addRequestedExtKeyusage

    private static ASN1Sequence createSubjectInfoAccess(final Extensions requestedExtensions,
            final Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> modes)
            throws BadCertTemplateException {
        if (modes == null) {
            return null;
        }

        ASN1Encodable extValue = requestedExtensions.getExtensionParsedValue(
                Extension.subjectInfoAccess);
        if (extValue == null) {
            return null;
        }

        ASN1Sequence reqSeq = ASN1Sequence.getInstance(extValue);
        int size = reqSeq.size();

        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (int i = 0; i < size; i++) {
            AccessDescription ad = AccessDescription.getInstance(reqSeq.getObjectAt(i));
            ASN1ObjectIdentifier accessMethod = ad.getAccessMethod();
            Set<GeneralNameMode> generalNameModes = modes.get(accessMethod);

            if (generalNameModes == null) {
                throw new BadCertTemplateException("subjectInfoAccess.accessMethod "
                        + accessMethod.getId() + " is not allowed");
            }

            GeneralName accessLocation = X509CertprofileUtil.createGeneralName(
                    ad.getAccessLocation(), generalNameModes);
            vec.add(new AccessDescription(accessMethod, accessLocation));
        } // end for

        return vec.size() > 0 ? new DERSequence(vec) : null;
    } // method createSubjectInfoAccess

    private static void addExtension(final ExtensionValues values,
            final ASN1ObjectIdentifier extType, final ExtensionValue extValue,
            final ExtensionControl extControl, final Set<ASN1ObjectIdentifier> neededExtensionTypes,
            final Set<ASN1ObjectIdentifier> wantedExtensionTypes) throws CertprofileException {
        if (extValue != null) {
            values.addExtension(extType, extValue);
            neededExtensionTypes.remove(extType);
            wantedExtensionTypes.remove(extType);
            return;
        }

        if (!extControl.isRequired()) {
            return;
        }

        String description = ObjectIdentifiers.getName(extType);
        if (description == null) {
            description = extType.getId();
        }
        throw new CertprofileException("could not add required extension " + description);
    } // method addExtension

    private static void addExtension(final ExtensionValues values,
            final ASN1ObjectIdentifier extType, final ASN1Encodable extValue,
            final ExtensionControl extControl, final Set<ASN1ObjectIdentifier> neededExtensionTypes,
            final Set<ASN1ObjectIdentifier> wantedExtensionTypes) throws CertprofileException {
        if (extValue != null) {
            values.addExtension(extType, extControl.isCritical(), extValue);
            neededExtensionTypes.remove(extType);
            wantedExtensionTypes.remove(extType);
            return;
        }

        if (!extControl.isRequired()) {
            return;
        }

        String description = ObjectIdentifiers.getName(extType);
        if (description == null) {
            description = extType.getId();
        }
        throw new CertprofileException("could not add required extension " + description);
    } // method addExtension

}
