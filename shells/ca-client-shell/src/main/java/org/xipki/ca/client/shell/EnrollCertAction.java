/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.client.shell;

import java.io.File;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.qualified.BiometricData;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.ProofOfPossessionSigningKeyBuilder;
import org.xipki.ca.client.api.CertOrError;
import org.xipki.ca.client.api.EnrollCertResult;
import org.xipki.ca.client.api.dto.EnrollCertRequest;
import org.xipki.ca.client.api.dto.EnrollCertRequestEntry;
import org.xipki.ca.client.shell.completer.CaNameCompleter;
import org.xipki.common.ObjectCreationException;
import org.xipki.common.RequestResponseDebug;
import org.xipki.common.util.DateUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.completer.ExtKeyusageCompleter;
import org.xipki.console.karaf.completer.ExtensionNameCompleter;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.console.karaf.completer.HashAlgCompleter;
import org.xipki.console.karaf.completer.KeyusageCompleter;
import org.xipki.security.ConcurrentBagEntrySigner;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.ExtensionExistence;
import org.xipki.security.KeyUsage;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignatureAlgoControl;
import org.xipki.security.exception.InvalidOidOrNameException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class EnrollCertAction extends ClientAction {

    @Reference
    protected SecurityFactory securityFactory;

    @Option(name = "--hash",
            description = "hash algorithm name for the POPO computation")
    protected String hashAlgo = "SHA256";

    @Option(name = "--subject", aliases = "-s", required = true,
            description = "subject to be requested\n(required)")
    private String subject;

    @Option(name = "--profile", aliases = "-p", required = true,
            description = "certificate profile\n(required)")
    private String profile;

    @Option(name = "--not-before",
            description = "notBefore, UTC time of format yyyyMMddHHmmss")
    private String notBeforeS;

    @Option(name = "--not-after",
            description = "notAfter, UTC time of format yyyyMMddHHmmss")
    private String notAfterS;

    @Option(name = "--out", aliases = "-o", required = true,
            description = "where to save the certificate\n(required)")
    @Completion(FilePathCompleter.class)
    private String outputFile;

    @Option(name = "--rsa-mgf1",
            description = "whether to use the RSAPSS MGF1 for the POPO computation\n"
                    + "(only applied to RSA key)")
    private Boolean rsaMgf1 = Boolean.FALSE;

    @Option(name = "--dsa-plain",
            description = "whether to use the Plain DSA for the POPO computation\n"
                    + "(only applied to DSA and ECDSA key)")
    private Boolean dsaPlain = Boolean.FALSE;

    @Option(name = "--gm",
            description = "whether to use the chinese GM algorithm for the POPO computation\n"
                    + "(only applied to EC key with GM curves)")
    private Boolean gm = Boolean.FALSE;

    @Option(name = "--ca",
            description = "CA name\n"
                    + "(required if the profile is supported by more than one CA)")
    @Completion(CaNameCompleter.class)
    private String caName;

    @Option(name = "--keyusage", multiValued = true,
            description = "keyusage\n(multi-valued)")
    @Completion(KeyusageCompleter.class)
    private List<String> keyusages;

    @Option(name = "--ext-keyusage", multiValued = true,
            description = "extended keyusage\n(multi-valued)")
    @Completion(ExtKeyusageCompleter.class)
    private List<String> extkeyusages;

    @Option(name = "--subject-alt-name", multiValued = true,
            description = "subjectAltName\n(multi-valued)")
    private List<String> subjectAltNames;

    @Option(name = "--subject-info-access", multiValued = true,
            description = "subjectInfoAccess.\n(multi-valued)")
    private List<String> subjectInfoAccesses;

    @Option(name = "--qc-eu-limit", multiValued = true,
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
    @Completion(FilePathCompleter.class)
    private String biometricFile;

    @Option(name = "--biometric-uri",
            description = "Biometric source data URI")
    private String biometricUri;

    @Option(name = "--need-extension", multiValued = true,
            description = "type (OID or name) of extension that must be contained in the"
                    + " certificate\n(multi-valued)")
    @Completion(ExtensionNameCompleter.class)
    private List<String> needExtensionTypes;

    @Option(name = "--want-extension", multiValued = true,
            description = "type (OID or name) of extension that should be contained in the"
                    + " certificate if possible\n(multi-valued)")
    @Completion(ExtensionNameCompleter.class)
    private List<String> wantExtensionTypes;

    /**
     *
     * @param signatureAlgoControl
     *          Signature algorithm control. Must not be {@code null}.
     */
    protected abstract ConcurrentContentSigner getSigner(
            SignatureAlgoControl signatureAlgoControl) throws ObjectCreationException;

    @Override
    protected Object execute0() throws Exception {
        if (caName != null) {
            caName = caName.toLowerCase();
        }

        CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();

        ConcurrentContentSigner signer = getSigner(
                new SignatureAlgoControl(rsaMgf1, dsaPlain, gm));
        X509CertificateHolder ssCert = signer.getBcCertificate();

        X500Name x500Subject = new X500Name(subject);
        certTemplateBuilder.setSubject(x500Subject);
        certTemplateBuilder.setPublicKey(ssCert.getSubjectPublicKeyInfo());

        if (StringUtil.isNotBlank(notBeforeS) || StringUtil.isNotBlank(notAfterS)) {
            Time notBefore = StringUtil.isNotBlank(notBeforeS)
                    ? new Time(DateUtil.parseUtcTimeyyyyMMddhhmmss(notBeforeS)) : null;
            Time notAfter = StringUtil.isNotBlank(notAfterS)
                    ? new Time(DateUtil.parseUtcTimeyyyyMMddhhmmss(notAfterS)) : null;
            OptionalValidity validity = new OptionalValidity(notBefore, notAfter);
            certTemplateBuilder.setValidity(validity);
        }

        if (needExtensionTypes == null) {
            needExtensionTypes = new LinkedList<>();
        }

        // SubjectAltNames
        List<Extension> extensions = new LinkedList<>();
        if (isNotEmpty(subjectAltNames)) {
            extensions.add(X509Util.createExtnSubjectAltName(subjectAltNames, false));
            needExtensionTypes.add(Extension.subjectAlternativeName.getId());
        }

        // SubjectInfoAccess
        if (isNotEmpty(subjectInfoAccesses)) {
            extensions.add(X509Util.createExtnSubjectInfoAccess(subjectInfoAccesses, false));
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
            TypeOfBiometricData objBiometricType = StringUtil.isNumber(biometricType)
                    ? new TypeOfBiometricData(Integer.parseInt(biometricType))
                    : new TypeOfBiometricData(new ASN1ObjectIdentifier(biometricType));

            ASN1ObjectIdentifier objBiometricHashAlgo = AlgorithmUtil.getHashAlg(biometricHashAlgo);
            byte[] biometricBytes = IoUtil.read(biometricFile);
            MessageDigest md = MessageDigest.getInstance(objBiometricHashAlgo.getId());
            md.reset();
            byte[] biometricDataHash = md.digest(biometricBytes);

            DERIA5String sourceDataUri = null;
            if (biometricUri != null) {
                sourceDataUri = new DERIA5String(biometricUri);
            }
            BiometricData biometricData = new BiometricData(objBiometricType,
                    new AlgorithmIdentifier(objBiometricHashAlgo),
                    new DEROctetString(biometricDataHash), sourceDataUri);

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
            extensions.add(
                    new Extension(ObjectIdentifiers.id_xipki_ext_cmpRequestExtensions, false,
                            ee.toASN1Primitive().getEncoded()));
        }

        if (isNotEmpty(extensions)) {
            Extensions asn1Extensions = new Extensions(extensions.toArray(new Extension[0]));
            certTemplateBuilder.setExtensions(asn1Extensions);
        }

        CertRequest certReq = new CertRequest(1, certTemplateBuilder.build(), null);

        ProofOfPossessionSigningKeyBuilder popoBuilder
                = new ProofOfPossessionSigningKeyBuilder(certReq);
        ConcurrentBagEntrySigner signer0 = signer.borrowSigner();
        POPOSigningKey popoSk;
        try {
            popoSk = popoBuilder.build(signer0.value());
        } finally {
            signer.requiteSigner(signer0);
        }

        ProofOfPossession popo = new ProofOfPossession(popoSk);
        EnrollCertRequestEntry reqEntry = new EnrollCertRequestEntry("id-1", profile, certReq,
                popo);
        EnrollCertRequest request = new EnrollCertRequest(EnrollCertRequest.Type.CERT_REQ);
        request.addRequestEntry(reqEntry);

        RequestResponseDebug debug = getRequestResponseDebug();
        EnrollCertResult result;
        try {
            result = caClient.requestCerts(caName, request, debug);
        } finally {
            saveRequestResponse(debug);
        }

        X509Certificate cert = null;
        if (result != null) {
            String id = result.allIds().iterator().next();
            CertOrError certOrError = result.getCertOrError(id);
            cert = (X509Certificate) certOrError.certificate();
        }

        if (cert == null) {
            throw new CmdFailure("no certificate received from the server");
        }

        File certFile = new File(outputFile);
        saveVerbose("saved certificate to file", certFile, cert.getEncoded());

        return null;
    } // method execute0

    private static List<ASN1ObjectIdentifier> textToAsn1ObjectIdentifers(
            List<String> oidTexts) throws InvalidOidOrNameException {
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

    private static ASN1ObjectIdentifier toOid(String str) throws InvalidOidOrNameException {
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
                // CHECKSTYLE:SKIP
            } catch (IllegalArgumentException ex) {
            }
        }

        ASN1ObjectIdentifier oid = ObjectIdentifiers.nameToOid(str);
        if (oid == null) {
            throw new InvalidOidOrNameException(str);
        }
        return oid;
    }

}
