/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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

package org.xipki.commons.security.shell;

import java.io.File;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import javax.annotation.Nonnull;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.qualified.BiometricData;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.console.karaf.completer.ExtKeyusageCompleter;
import org.xipki.commons.console.karaf.completer.ExtensionNameCompleter;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.commons.console.karaf.completer.HashAlgCompleter;
import org.xipki.commons.console.karaf.completer.KeyusageCompleter;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.ExtensionExistence;
import org.xipki.commons.security.api.InvalidOidOrNameException;
import org.xipki.commons.security.api.KeyUsage;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.commons.security.api.P10RequestGenerator;
import org.xipki.commons.security.api.SignatureAlgoControl;
import org.xipki.commons.security.api.util.AlgorithmUtil;
import org.xipki.commons.security.api.util.KeyUtil;
import org.xipki.commons.security.api.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class CertRequestGenCommandSupport extends SecurityCommandSupport {

    @Option(name = "--hash",
            description = "hash algorithm name")
    @Completion(HashAlgCompleter.class)
    protected String hashAlgo = "SHA256";

    @Option(name = "--subject", aliases = "-s",
            required = true,
            description = "subject in the PKCS#10 request\n"
                    + "(required)")
    private String subject;

    @Option(name = "--rsa-mgf1",
            description = "whether to use the RSAPSS MGF1 for the POPO computation\n"
                    + "(only applied to RSA key)")
    private Boolean rsaMgf1 = Boolean.FALSE;

    @Option(name = "--ecdsa-plain",
            description = "whether to use the Plain ECDSA for the POPO computation")
    private Boolean ecdsaPlain = Boolean.FALSE;

    @Option(name = "--out", aliases = "-o",
            required = true,
            description = "output file name\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String outputFilename;

    @Option(name = "--challenge-password", aliases = "-c",
            description = "Challenge password")
    private String challengePassword;

    @Option(name = "--keyusage",
            multiValued = true,
            description = "keyusage\n"
                    + "(multi-valued)")
    @Completion(KeyusageCompleter.class)
    private List<String> keyusages;

    @Option(name = "--ext-keyusage",
            multiValued = true,
            description = "extended keyusage\n"
                    + "(multi-valued)")
    @Completion(ExtKeyusageCompleter.class)
    private List<String> extkeyusages;

    @Option(name = "--subject-alt-name",
            multiValued = true,
            description = "subjectAltName\n"
                    + "(multi-valued)")
    private List<String> subjectAltNames;

    @Option(name = "--subject-info-access",
            multiValued = true,
            description = "subjectInfoAccess\n"
                    + "(multi-valued)")
    private List<String> subjectInfoAccesses;

    @Option(name = "--qc-eu-limit",
            multiValued = true,
            description = "QC EuLimitValue of format <currency>:<amount>:<exponent>.\n"
                    + "(multi-valued)")
    private List<String> qcEuLimits;

    @Option(name = "--biometric-type",
            description = "Biometric type")
    private String biometricType;

    @Option(name = "--biometric-hash",
            description = "Biometric hash algorithm")
    @Completion(HashAlgCompleter.class)
    private String biometricHashAlgo;

    @Option(name = "--biometric-file",
            description = "Biometric hash algorithm")
    private String biometricFile;

    @Option(name = "--biometric-uri",
            description = "Biometric sourcedata URI")
    @Completion(FilePathCompleter.class)
    private String biometricUri;

    @Option(name = "--need-extension",
            multiValued = true,
            description = "types of extension that must be contaied in the certificate\n"
                    + "(multi-valued)")
    @Completion(ExtensionNameCompleter.class)
    private List<String> needExtensionTypes;

    @Option(name = "--want-extension",
            multiValued = true,
            description = "types of extension that should be contaied in the certificate if"
                    + " possible\n"
                    + "(multi-valued)")
    @Completion(ExtensionNameCompleter.class)
    private List<String> wantExtensionTypes;

    @Reference
    private P10RequestGenerator p10Gen;

    protected abstract ConcurrentContentSigner getSigner(
            @Nonnull SignatureAlgoControl signatureAlgoControl)
    throws Exception;

    @Override
    protected Object doExecute()
    throws Exception {
        hashAlgo = hashAlgo.trim().toUpperCase();
        if (hashAlgo.indexOf('-') != -1) {
            hashAlgo = hashAlgo.replaceAll("-", "");
        }

        if (needExtensionTypes == null) {
            needExtensionTypes = new LinkedList<>();
        }

        // SubjectAltNames
        List<Extension> extensions = new LinkedList<>();

        if (isNotEmpty(subjectAltNames)) {
            extensions.add(X509Util.createExtensionSubjectAltName(
                    subjectAltNames, false));
            needExtensionTypes.add(Extension.subjectAlternativeName.getId());
        }

        // SubjectInfoAccess
        if (isNotEmpty(subjectInfoAccesses)) {
            extensions.add(X509Util.createExtensionSubjectInfoAccess(
                    subjectInfoAccesses, false));
            needExtensionTypes.add(Extension.subjectInfoAccess.getId());
        }

        // Keyusage
        if (isNotEmpty(keyusages)) {
            Set<KeyUsage> usages = new HashSet<>();
            for (String usage : keyusages) {
                usages.add(KeyUsage.getKeyUsage(usage));
            }
            org.bouncycastle.asn1.x509.KeyUsage extValue = X509Util.createKeyUsage(usages);
            ASN1ObjectIdentifier extType = Extension.keyUsage;
            extensions.add(new Extension(extType, false, extValue.getEncoded()));
            needExtensionTypes.add(extType.getId());
        }

        // ExtendedKeyusage
        if (isNotEmpty(extkeyusages)) {
            ExtendedKeyUsage extValue = X509Util.createExtendedUsage(
                    textToAsn1ObjectIdentifers(extkeyusages));
            ASN1ObjectIdentifier extType = Extension.extendedKeyUsage;
            extensions.add(new Extension(extType, false, extValue.getEncoded()));
            needExtensionTypes.add(extType.getId());
        }

        // QcEuLimitValue
        if (isNotEmpty(qcEuLimits)) {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            for (String m : qcEuLimits) {
                StringTokenizer st = new StringTokenizer(m, ":");
                try {
                    String currencyS = st.nextToken();
                    String amountS = st.nextToken();
                    String exponentS = st.nextToken();

                    Iso4217CurrencyCode currency;
                    try {
                        int intValue = Integer.parseInt(currencyS);
                        currency = new Iso4217CurrencyCode(intValue);
                    } catch (NumberFormatException ex) {
                        currency = new Iso4217CurrencyCode(currencyS);
                    }

                    int amount = Integer.parseInt(amountS);
                    int exponent = Integer.parseInt(exponentS);

                    MonetaryValue monterayValue = new MonetaryValue(currency, amount, exponent);
                    QCStatement statment = new QCStatement(
                            ObjectIdentifiers.id_etsi_qcs_QcLimitValue, monterayValue);
                    vec.add(statment);
                } catch (Exception ex) {
                    throw new Exception("invalid qc-eu-limit '" + m + "'");
                }
            }

            ASN1ObjectIdentifier extType = Extension.qCStatements;
            ASN1Sequence extValue = new DERSequence(vec);
            extensions.add(new Extension(extType, false, extValue.getEncoded()));
            needExtensionTypes.add(extType.getId());
        }

        // biometricInfo
        if (biometricType != null && biometricHashAlgo != null && biometricFile != null) {
            TypeOfBiometricData tmpBiometricType;
            if (StringUtil.isNumber(biometricType)) {
                tmpBiometricType = new TypeOfBiometricData(Integer.parseInt(biometricType));
            } else {
                tmpBiometricType = new TypeOfBiometricData(
                        new ASN1ObjectIdentifier(biometricType));
            }

            ASN1ObjectIdentifier tmpBiometricHashAlgo
                    = AlgorithmUtil.getHashAlg(biometricHashAlgo);
            byte[] biometricBytes = IoUtil.read(biometricFile);
            MessageDigest md = MessageDigest.getInstance(tmpBiometricHashAlgo.getId());
            md.reset();
            byte[] tmpBiometricDataHash = md.digest(biometricBytes);

            DERIA5String tmpSourceDataUri = null;
            if (biometricUri != null) {
                tmpSourceDataUri = new DERIA5String(biometricUri);
            }
            BiometricData biometricData = new BiometricData(tmpBiometricType,
                    new AlgorithmIdentifier(tmpBiometricHashAlgo),
                    new DEROctetString(tmpBiometricDataHash),
                    tmpSourceDataUri);

            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add(biometricData);

            ASN1ObjectIdentifier extType = Extension.biometricInfo;
            ASN1Sequence extValue = new DERSequence(vec);
            extensions.add(new Extension(extType, false, extValue.getEncoded()));
            needExtensionTypes.add(extType.getId());
        } else if (biometricType == null && biometricHashAlgo == null && biometricFile == null) {
            // Do nothing
        } else {
            throw new Exception("either all of biometric triples (type, hash algo, file)"
                    + " must be set or none of them should be set");
        }

        if (isNotEmpty(needExtensionTypes) || isNotEmpty(wantExtensionTypes)) {
            ExtensionExistence ee = new ExtensionExistence(
                    textToAsn1ObjectIdentifers(needExtensionTypes),
                    textToAsn1ObjectIdentifers(wantExtensionTypes));
            extensions.add(new Extension(
                    ObjectIdentifiers.id_xipki_ext_cmpRequestExtensions, false,
                    ee.toASN1Primitive().getEncoded()));
        }

        ConcurrentContentSigner signer = getSigner(
                new SignatureAlgoControl(rsaMgf1, ecdsaPlain));

        Map<ASN1ObjectIdentifier, ASN1Encodable> attributes = new HashMap<>();
        if (CollectionUtil.isNonEmpty(extensions)) {
            attributes.put(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                    new Extensions(extensions.toArray(new Extension[0])));
        }

        if (StringUtil.isNotBlank(challengePassword)) {
            attributes.put(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                    new DERPrintableString(challengePassword));
        }

        SubjectPublicKeyInfo subjectPublicKeyInfo;
        if (signer.getCertificate() != null) {
            Certificate cert = Certificate.getInstance(
                    signer.getCertificate().getEncoded());
            subjectPublicKeyInfo = cert.getSubjectPublicKeyInfo();
        } else {
            subjectPublicKeyInfo = KeyUtil.createSubjectPublicKeyInfo(
                    signer.getPublicKey());
        }

        X500Name subjectDn = getSubject(subject);
        PKCS10CertificationRequest p10Req = p10Gen.generateRequest(signer, subjectPublicKeyInfo,
                subjectDn, attributes);

        File file = new File(outputFilename);
        saveVerbose("saved PKCS#10 request to file", file, p10Req.getEncoded());
        return null;
    } // method doExecute

    protected X500Name getSubject(
            final String subjectText) {
        ParamUtil.requireNonBlank("subjectText", subjectText);
        return new X500Name(subjectText);
    }

    private static List<ASN1ObjectIdentifier> textToAsn1ObjectIdentifers(
            final List<String> oidTexts)
    throws InvalidOidOrNameException {
        if (oidTexts == null) {
            return null;
        }

        List<ASN1ObjectIdentifier> ret = new ArrayList<>(oidTexts.size());
        for (String oidText : oidTexts) {
            if (oidText.isEmpty()) {
                continue;
            }

            ASN1ObjectIdentifier oid = toOid(oidText);
            if (!ret.contains(oid)) {
                ret.add(oid);
            }
        }
        return ret;
    }

    private static ASN1ObjectIdentifier toOid(
            final String str)
    throws InvalidOidOrNameException {
        final int n = str.length();
        boolean isName = false;
        for (int i = 0; i < n; i++) {
            char ch = str.charAt(i);
            if (!((ch >= '0' && ch <= '1') || ch == '.')) {
                isName = true;
            }
        }

        if (!isName) {
            try {
                return new ASN1ObjectIdentifier(str);
            } catch (IllegalArgumentException ex) { // CHECKSTYLE:SKIP
            }
        }

        ASN1ObjectIdentifier oid = ObjectIdentifiers.nameToOid(str);
        if (oid == null) {
            throw new InvalidOidOrNameException(str);
        }
        return oid;
    }

}
