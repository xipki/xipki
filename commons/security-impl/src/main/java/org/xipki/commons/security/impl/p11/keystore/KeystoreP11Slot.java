/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.commons.security.impl.p11.keystore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.security.api.HashCalculator;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.p11.P11Constants;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11Identity;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11MechanismFilter;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.p11.P11UnsupportedMechanismException;
import org.xipki.commons.security.api.p11.P11WritableSlot;
import org.xipki.commons.security.api.util.KeyUtil;
import org.xipki.commons.security.api.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class KeystoreP11Slot implements P11WritableSlot {

    private static class InfoFilenameFilter implements FilenameFilter {

        @Override
        public boolean accept(File dir, String name) {
            return name.endsWith(INFO_FILE_SUFFIX);
        }

    }

    // slotinfo
    private static final String FILE_SLOTINFO = "slot.info";
    private static final String PROP_NAMED_CURVE_SUPPORTED = "namedCurveSupported";

    private static final String DIR_PRIV_KEY = "privkey";
    private static final String DIR_PUB_KEY = "pubkey";
    private static final String DIR_CERT = "cert";

    private static final String INFO_FILE_SUFFIX = ".info";
    private static final String VALUE_FILE_SUFFIX = ".value";

    private static final String PROP_ID = "id";
    private static final String PROP_LABEL = "label";
    private static final String PROP_SHA1SUM = "sha1";

    private static final String PROP_ALGORITHM = "algorithm";

    // RSA
    private static final String PROP_RSA_MODUS = "modus";
    private static final String PROP_RSA_PUBLIC_EXPONENT = "publicExponent";

    // DSA
    private static final String PROP_DSA_PRIME = "prime"; // p
    private static final String PROP_DSA_SUBPRIME = "subprime"; // q
    private static final String PROP_DSA_BASE = "base"; // g
    private static final String PROP_DSA_VALUE = "value"; // y

    // EC
    private static final String PROP_EC_ECDSA_PARAMS = "ecdsaParams";
    private static final String PROP_EC_EC_POINT = "ecPoint";

    private static final Logger LOG = LoggerFactory.getLogger(KeystoreP11Slot.class);

    private static final InfoFilenameFilter INFO_FILENAME_FILTER = new InfoFilenameFilter();

    private final String moduleName;

    private final File slotDir;

    private final boolean namedCurveSupported;

    private final File privKeyDir;

    private final File pubKeyDir;

    private final File certDir;

    private final P11SlotIdentifier slotId;

    private final List<KeystoreP11Identity> identities = new LinkedList<>();

    private final PrivateKeyCryptor privateKeyCryptor;

    private final SecurityFactory securityFactory;

    private Set<Long> supportedMechanisms = new HashSet<>();

    KeystoreP11Slot(
            final String moduleName,
            final File slotDir,
            final P11SlotIdentifier slotId,
            final PrivateKeyCryptor privateKeyCryptor,
            final SecurityFactory securityFactory,
            final P11MechanismFilter mechanismFilter)
    throws P11TokenException {
        this.moduleName = ParamUtil.requireNonBlank("moduleName", moduleName);
        this.slotDir = ParamUtil.requireNonNull("slotDir", slotDir);
        this.slotId = ParamUtil.requireNonNull("slotId", slotId);
        this.securityFactory = ParamUtil.requireNonNull("securityFactory", securityFactory);
        this.privateKeyCryptor = ParamUtil.requireNonNull("privateKeyCryptor", privateKeyCryptor);

        this.privKeyDir = new File(slotDir, DIR_PRIV_KEY);
        if (!this.privKeyDir.exists()) {
            this.privKeyDir.mkdirs();
        }

        this.pubKeyDir = new File(slotDir, DIR_PUB_KEY);
        if (!this.pubKeyDir.exists()) {
            this.pubKeyDir.mkdirs();
        }

        this.certDir = new File(slotDir, DIR_CERT);
        if (!this.certDir.exists()) {
            this.certDir.mkdirs();
        }

        File slotInfoFile = new File(slotDir, FILE_SLOTINFO);
        if (slotInfoFile.exists()) {
            Properties props = loadProperties(slotInfoFile);
            this.namedCurveSupported = Boolean.parseBoolean(
                    props.getProperty(PROP_NAMED_CURVE_SUPPORTED, "true"));
        } else {
            this.namedCurveSupported = true;
        }

        addMechanism(P11Constants.CKM_DSA_KEY_PAIR_GEN, mechanismFilter);
        addMechanism(P11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN, mechanismFilter);
        addMechanism(P11Constants.CKM_EC_KEY_PAIR_GEN, mechanismFilter);

        addMechanism(P11Constants.CKM_RSA_X_509, mechanismFilter);

        addMechanism(P11Constants.CKM_RSA_PKCS, mechanismFilter);
        addMechanism(P11Constants.CKM_SHA1_RSA_PKCS, mechanismFilter);
        addMechanism(P11Constants.CKM_SHA224_RSA_PKCS, mechanismFilter);
        addMechanism(P11Constants.CKM_SHA256_RSA_PKCS, mechanismFilter);
        addMechanism(P11Constants.CKM_SHA384_RSA_PKCS, mechanismFilter);
        addMechanism(P11Constants.CKM_SHA512_RSA_PKCS, mechanismFilter);

        addMechanism(P11Constants.CKM_RSA_PKCS_PSS, mechanismFilter);
        addMechanism(P11Constants.CKM_SHA1_RSA_PKCS_PSS, mechanismFilter);
        addMechanism(P11Constants.CKM_SHA224_RSA_PKCS_PSS, mechanismFilter);
        addMechanism(P11Constants.CKM_SHA256_RSA_PKCS_PSS, mechanismFilter);
        addMechanism(P11Constants.CKM_SHA384_RSA_PKCS_PSS, mechanismFilter);
        addMechanism(P11Constants.CKM_SHA512_RSA_PKCS_PSS, mechanismFilter);

        addMechanism(P11Constants.CKM_DSA, mechanismFilter);
        addMechanism(P11Constants.CKM_DSA_SHA1, mechanismFilter);
        addMechanism(P11Constants.CKM_DSA_SHA224, mechanismFilter);
        addMechanism(P11Constants.CKM_DSA_SHA256, mechanismFilter);
        addMechanism(P11Constants.CKM_DSA_SHA384, mechanismFilter);
        addMechanism(P11Constants.CKM_DSA_SHA512, mechanismFilter);

        addMechanism(P11Constants.CKM_ECDSA, mechanismFilter);
        addMechanism(P11Constants.CKM_ECDSA_SHA1, mechanismFilter);

        this.supportedMechanisms = Collections.unmodifiableSet(this.supportedMechanisms);
        if (LOG.isInfoEnabled()) {
            LOG.info("module {}, slot {}: supported mechanisms: {}", this.moduleName, this.slotId,
                    this.supportedMechanisms);
        }

        refresh();
    }

    private void addMechanism(
            final long mechanism,
            final P11MechanismFilter filter) {
        if (filter.isMechanismPermitted(slotId, mechanism)) {
            supportedMechanisms.add(mechanism);
        }
    }

    void refresh() {
        File[] privKeyInfoFiles = privKeyDir.listFiles(INFO_FILENAME_FILTER);
        if (privKeyInfoFiles == null || privKeyInfoFiles.length == 0) {
            this.identities.clear();
            this.supportedMechanisms.clear();
            return;
        }

        Map<String, X509Certificate> certs = getAllCertificates();

        Set<KeystoreP11Identity> currentIdentifies = new HashSet<>();

        for (File privKeyInfoFile : privKeyInfoFiles) {
            byte[] keyId = getKeyIdFromInfoFilename(privKeyInfoFile.getName());
            String hexKeyId = Hex.toHexString(keyId);

            try {
                Properties props = loadProperties(privKeyInfoFile);
                String keyLabel = props.getProperty(PROP_LABEL);

                P11KeyIdentifier p11KeyId = new P11KeyIdentifier(keyId, keyLabel);

                X509Certificate cert = certs.get(hexKeyId);
                java.security.PublicKey publicKey = null;

                if (cert != null) {
                    publicKey = cert.getPublicKey();
                } else {
                    publicKey = readPublicKey(keyId);
                }

                if (publicKey == null) {
                    LOG.warn("Neither public key nor certificate is associated with private key {}",
                            p11KeyId);
                    continue;
                }

                List<X509Certificate> certChain = new LinkedList<>();
                if (cert != null) {
                    certChain.add(cert);

                    boolean changed = true;
                    while (changed) {
                        X509Certificate lastCert = certChain.get(certChain.size() - 1);

                        changed = false;
                        for (X509Certificate c : certs.values()) {
                            if (c == lastCert) {
                                continue;
                            }
                            if (X509Util.issues(c, cert)) {
                                certChain.add(c);
                                changed = true;
                            }
                        }
                    }
                }

                byte[] encodedValue = IoUtil.read(
                        new File(privKeyDir, hexKeyId + VALUE_FILE_SUFFIX));

                PKCS8EncryptedPrivateKeyInfo epki = new PKCS8EncryptedPrivateKeyInfo(encodedValue);
                PrivateKey privateKey = privateKeyCryptor.decrypt(epki);

                KeystoreP11Identity identity = new KeystoreP11Identity(
                        new P11EntityIdentifier(slotId, p11KeyId), privateKey, publicKey,
                        certChain.toArray(new X509Certificate[0]), 20,
                        securityFactory.getRandom4Sign());
                LOG.info("added PKCS#11 key {}", p11KeyId);
                currentIdentifies.add(identity);
            } catch (InvalidKeyException ex) {
                final String message = "InvalidKeyException while initializing key with key-id "
                        + hexKeyId;
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                            ex.getMessage());
                }
                LOG.debug(message, ex);
                continue;
            } catch (Throwable th) {
                final String message =
                        "unexpected exception while initializing key with key-id " + hexKeyId;
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), th.getClass().getName(),
                            th.getMessage());
                }
                LOG.debug(message, th);
                continue;
            }
        }

        this.identities.clear();
        this.identities.addAll(currentIdentifies);
        currentIdentifies.clear();
    } // method refresh

    File getSlotDir() {
        return slotDir;
    }

    P11SlotIdentifier getSlotId() {
        return slotId;
    }

    Set<Long> getSupportedMechanisms() {
        return supportedMechanisms;
    }

    boolean supportsMechanism(
            final long mechanism) {
        return supportedMechanisms.contains(mechanism);
    }

    @Override
    public List<? extends P11Identity> getP11Identities() {
        return Collections.unmodifiableList(identities);
    }

    private boolean privKeyLabelExists(String label) {
        for (KeystoreP11Identity id : identities) {
            if (id.getEntityId().getKeyId().getKeyLabel().equals(label)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean removeKey(
            final P11KeyIdentifier keyIdentifier)
    throws P11TokenException, SecurityException {
        ParamUtil.requireNonNull("keyIdentifier", keyIdentifier);

        KeystoreP11Identity identity = getIdentity(keyIdentifier);
        if (identity != null) {
            identities.remove(identity);
        }
        boolean b1 = removePkcs11PrivateKey(keyIdentifier);
        boolean b2 = removePkcs11PublicKey(keyIdentifier);
        return b1 | b2;
    }

    @Override
    public boolean removeKeyAndCerts(
            final P11KeyIdentifier keyIdentifier)
    throws P11TokenException, SecurityException {
        ParamUtil.requireNonNull("keyIdentifier", keyIdentifier);

        KeystoreP11Identity identity = getIdentity(keyIdentifier);
        if (identity != null) {
            identities.remove(identity);
        }

        boolean b1 = removePkcs11PrivateKey(keyIdentifier);
        boolean b2 = removePkcs11PublicKey(keyIdentifier);
        boolean b3 = removePkcs11Cert(keyIdentifier);
        return b1 | b2 | b3;
    }

    @Override
    public void updateCertificate(
            final P11KeyIdentifier keyIdentifier,
            final X509Certificate newCert,
            final Set<X509Certificate> caCerts,
            final SecurityFactory securityFactory)
    throws P11TokenException, SecurityException {
        ParamUtil.requireNonNull("keyIdentifier", keyIdentifier);
        ParamUtil.requireNonNull("newCert", newCert);

        KeystoreP11Identity identity = getIdentity(keyIdentifier);
        if (identity == null) {
            throw new SecurityException("could not find identity " + keyIdentifier);
        }

        assertMatch(newCert, keyIdentifier);

        X509Certificate[] certChain = X509Util.buildCertPath(newCert, caCerts);

        P11KeyIdentifier certKeyId = identity.getEntityId().getKeyId();
        savePkcs11Cert(certKeyId.getKeyId(), certKeyId.getKeyLabel(), newCert);
        if (certChain.length < 2) {
            return;
        }

        for (int i = 1; i < certChain.length; i++) {
            addCert(certChain[i]);
        }
    } // method updateCertificate

    @Override
    public void removeCerts(
            final P11KeyIdentifier keyIdentifier)
    throws P11TokenException, SecurityException {
        removePkcs11Cert(keyIdentifier);
    }

    @Override
    public P11KeyIdentifier addCert(
            final X509Certificate cert)
    throws P11TokenException, SecurityException {
        ParamUtil.requireNonNull("cert", cert);
        byte[] encodedCert;
        try {
            encodedCert = cert.getEncoded();
        } catch (CertificateEncodingException ex) {
            throw new SecurityException("could not encoded cert: " + ex.getMessage(), ex);
        }
        String sha1sum = HashCalculator.hexSha1(encodedCert);

        // make sure that the certificate does not exist in the PKCS#11 module
        File[] infoFiles = certDir.listFiles(INFO_FILENAME_FILTER);
        if (infoFiles != null) {
            for (File infoFile : infoFiles) {
                Properties props = loadProperties(infoFile);
                if (props == null) {
                    continue;
                }

                if (sha1sum.equals(props.getProperty(PROP_SHA1SUM))) {
                    String label = props.getProperty(PROP_LABEL);
                    byte[] id = getKeyIdFromInfoFilename(infoFile.getName());
                    return new P11KeyIdentifier(id, label);
                }
            }
        }

        byte[] keyId = generateKeyId();
        String keyLabel;
        String cn = X509Util.getCommonName(cert.getSubjectX500Principal());
        if (StringUtil.isBlank(cn)) {
            keyLabel = "NO-COMMON-NAME";
        } else {
            keyLabel = cn;
        }
        savePkcs11Cert(keyId, keyLabel, cert);
        return new P11KeyIdentifier(keyId, keyLabel);
    }

    @Override
    public P11KeyIdentifier generateRSAKeypair(
            final int keySize,
            final BigInteger publicExponent,
            final String label)
    throws P11TokenException, SecurityException {
        ParamUtil.requireNonBlank("label", label);
        ParamUtil.requireMin("keySize", keySize, 1024);

        if (keySize % 1024 != 0) {
            throw new IllegalArgumentException("key size is not multiple of 1024: " + keySize);
        }

        if (privKeyLabelExists(label)) {
            throw new IllegalArgumentException("label " + label
                    + " exists, please specify another one");
        }

        assertMechanismSupported(P11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
        KeyPair kp;
        try {
            kp = KeyUtil.generateRSAKeypair(keySize, publicExponent,
                    securityFactory.getRandom4Key());
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                | InvalidAlgorithmParameterException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }

        byte[] keyId = generateKeyId();
        savePkcs11PrivateKey(keyId, label, kp.getPrivate());
        savePkcs11PublicKey(keyId, label, kp.getPublic());
        return new P11KeyIdentifier(keyId, label);
    } // method generateRSAKeypairAndCert

    @Override
    public P11KeyIdentifier generateDSAKeypair(
            final int plength,
            final int qlength,
            final String label)
    throws P11TokenException, SecurityException {
        ParamUtil.requireNonBlank("label", label);
        ParamUtil.requireMax("pLength", plength, 1024);

        if (plength % 1024 != 0) {
            throw new IllegalArgumentException("key size is not multiple of 1024: " + plength);
        }

        if (privKeyLabelExists(label)) {
            throw new IllegalArgumentException("label " + label
                    + " exists, please specify another one");
        }

        assertMechanismSupported(P11Constants.CKM_DSA_KEY_PAIR_GEN);
        KeyPair kp;
        try {
            kp = KeyUtil.generateDSAKeypair(plength, qlength, securityFactory.getRandom4Key());
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                | InvalidAlgorithmParameterException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }

        byte[] keyId = generateKeyId();
        savePkcs11PrivateKey(keyId, label, kp.getPrivate());
        savePkcs11PublicKey(keyId, label, kp.getPublic());
        return new P11KeyIdentifier(keyId, label);
    } // method generateDSAKeypairAndCert

    @Override
    public P11KeyIdentifier generateECKeypair(
            final String curveNameOrOid,
            final String label)
    throws P11TokenException, SecurityException {
        ParamUtil.requireNonBlank("curveNameOrOid", curveNameOrOid);
        ParamUtil.requireNonBlank("label", label);

        if (privKeyLabelExists(label)) {
            throw new IllegalArgumentException("label " + label
                    + " exists, please specify another one");
        }

        assertMechanismSupported(P11Constants.CKM_EC_KEY_PAIR_GEN);
        KeyPair kp;
        try {
            kp = KeyUtil.generateECKeypairForCurveNameOrOid(curveNameOrOid,
                    securityFactory.getRandom4Key());
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                | InvalidAlgorithmParameterException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }

        byte[] keyId = generateKeyId();
        savePkcs11PrivateKey(keyId, label, kp.getPrivate());
        savePkcs11PublicKey(keyId, label, kp.getPublic());
        return new P11KeyIdentifier(keyId, label);
    } // method generateECDSAKeypairAndCert

    private KeystoreP11Identity getIdentity(
            final P11KeyIdentifier keyIdentifier) {
        ParamUtil.requireNonNull("keyIdentifier", keyIdentifier);

        byte[] keyId = keyIdentifier.getKeyId();
        String keyLabel = keyIdentifier.getKeyLabel();

        if (keyId == null) {
            for (KeystoreP11Identity p11Identity : identities) {
                if (p11Identity.getEntityId().getKeyId().getKeyLabel().equals(keyLabel)) {
                    return p11Identity;
                }
            }
        } else if (keyLabel == null) {
            for (KeystoreP11Identity p11Identity : identities) {
                if (Arrays.equals(p11Identity.getEntityId().getKeyId().getKeyId(), keyId)) {
                    return p11Identity;
                }
            }
        } else {
            for (KeystoreP11Identity p11Identity : identities) {
                if (p11Identity.getEntityId().getKeyId().getKeyLabel().equals(keyLabel)) {
                    if (Arrays.equals(p11Identity.getEntityId().getKeyId().getKeyId(), keyId)) {
                        return p11Identity;
                    }
                }
            }
        }

        return null;
    } // method getIdentity

    private void assertMatch(
            final X509Certificate cert,
            final P11KeyIdentifier keyId)
    throws SecurityException {
        ConfPairs pairs = new ConfPairs("slot", Integer.toString(slotId.getSlotIndex()));
        if (keyId.getKeyId() != null) {
            pairs.putPair("key-id", Hex.toHexString(keyId.getKeyId()));
        }
        if (keyId.getKeyLabel() != null) {
            pairs.putPair("key-label", keyId.getKeyLabel());
        }

        securityFactory.createSigner("PKCS11", pairs.getEncoded(), "SHA1", null, cert);
    }

    @Override
    public X509Certificate exportCert(
            final P11KeyIdentifier keyIdentifier)
    throws P11TokenException, SecurityException {
        KeystoreP11Identity identity = getIdentity(keyIdentifier);
        if (identity == null) {
            return null;
        }

        return identity.getCertificate();
    }

    @Override
    public String getModuleName() {
        return moduleName;
    }

    @Override
    public P11SlotIdentifier getSlotIdentifier() {
        return slotId;
    }

    @Override
    public void showDetails(
            final OutputStream stream,
            final boolean verbose)
    throws P11TokenException, IOException, SecurityException {
        ParamUtil.requireNonNull("stream", stream);
        List<? extends P11Identity> p11Identities = getP11Identities();

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < p11Identities.size(); i++) {
            P11Identity identity = p11Identities.get(i);
            P11KeyIdentifier p11KeyId = identity.getEntityId().getKeyId();

            sb.append("\t")
                .append(i + 1)
                .append(". ")
                .append(p11KeyId.getKeyLabel())
                .append(" (").append("id: ")
                .append(Hex.toHexString(p11KeyId.getKeyId()).toLowerCase())
                .append(")\n");

            sb.append("\t\tAlgorithm: ")
                .append(identity.getPublicKey().getAlgorithm())
                .append("\n");

            formatString(sb, identity.getCertificate(), verbose);
        }

        if (sb.length() > 0) {
            stream.write(sb.toString().getBytes());
        }
    }

    private void formatString(
            final StringBuilder sb,
            final X509Certificate cert,
            final boolean verbose) {
        String subject = X509Util.getRfc4519Name(cert.getSubjectX500Principal());

        if (!verbose) {
            sb.append("\t\tCertificate: ").append(subject).append("\n");
            return;
        }

        sb.append("\t\tCertificate:\n");
        sb.append("\t\t\tSubject: ")
            .append(subject)
            .append("\n");

        String issuer = X509Util.getRfc4519Name(cert.getIssuerX500Principal());
        sb.append("\t\t\tIssuer: ")
            .append(issuer)
            .append("\n");

        sb.append("\t\t\tSerial: ")
            .append(cert.getSerialNumber())
            .append("\n");
        sb.append("\t\t\tStart time: ")
            .append(cert.getNotBefore())
            .append("\n");
        sb.append("\t\t\tEnd time: ")
            .append(cert.getNotAfter())
            .append("\n");
        sb.append("\t\t\tSHA1 Sum: ");
        try {
            sb.append(HashCalculator.hexSha1(cert.getEncoded()));
        } catch (CertificateEncodingException ex) {
            sb.append("ERROR");
        }
        sb.append("\n");
    }

    private boolean removePkcs11PrivateKey(
            final P11KeyIdentifier keyId)
    throws P11TokenException {
        return removePkcs11Entry(privKeyDir, keyId);
    }

    private boolean removePkcs11PublicKey(
            final P11KeyIdentifier keyId)
    throws P11TokenException {
        return removePkcs11Entry(pubKeyDir, keyId);
    }

    private boolean removePkcs11Cert(
            final P11KeyIdentifier keyId)
    throws P11TokenException {
        return removePkcs11Entry(certDir, keyId);
    }

    private boolean removePkcs11Entry(
            final File dir,
            final P11KeyIdentifier keyId)
    throws P11TokenException {
        byte[] id = keyId.getKeyId();
        String label = keyId.getKeyLabel();
        if (id != null) {
            String hextId = Hex.toHexString(id);
            File infoFile = new File(dir, hextId + INFO_FILE_SUFFIX);
            if (!infoFile.exists()) {
                return false;
            }

            if (StringUtil.isBlank(label)) {
                return deletePkcs11Entry(dir, id);
            } else {
                Properties props = loadProperties(infoFile);

                if (label.equals(props.getProperty("label"))) {
                    return deletePkcs11Entry(dir, id);
                } else {
                    return false;
                }
            }
        }

        // id is null, delete all entries with the specified label
        boolean deleted = false;
        File[] infoFiles = dir.listFiles(INFO_FILENAME_FILTER);
        if (infoFiles != null) {
            for (File infoFile : infoFiles) {
                if (!infoFile.isFile()) {
                    continue;
                }

                Properties props = loadProperties(infoFile);
                if (label.equals(props.getProperty("label"))) {
                    if (deletePkcs11Entry(dir, getKeyIdFromInfoFilename(infoFile.getName()))) {
                        deleted = true;
                    }
                }
            }
        }

        return deleted;
    }

    private static boolean deletePkcs11Entry(
            final File dir,
            final byte[] keyId) {
        String hextId = Hex.toHexString(keyId);
        File infoFile = new File(dir, hextId + INFO_FILE_SUFFIX);
        boolean b1 = true;
        if (infoFile.exists()) {
            b1 = infoFile.delete();
        }

        File valueFile = new File(dir, hextId + VALUE_FILE_SUFFIX);
        boolean b2 = true;
        if (valueFile.exists()) {
            b2 = valueFile.delete();
        }

        return b1 || b2;
    }

    private void savePkcs11PrivateKey(
            final byte[] id,
            final String label,
            final PrivateKey privateKey)
    throws SecurityException, P11TokenException {
        PKCS8EncryptedPrivateKeyInfo encryptedPrivKeyInfo = privateKeyCryptor.encrypt(privateKey);
        byte[] encoded;
        try {
            encoded = encryptedPrivKeyInfo.getEncoded();
        } catch (IOException ex) {
            throw new SecurityException("could not encode PrivateKey");
        }
        savePkcs11Entry(privKeyDir, id, label, encoded);
    }

    private void savePkcs11PublicKey(
            final byte[] id,
            final String label,
            final PublicKey publicKey)
    throws SecurityException, P11TokenException {
        String hexId = Hex.toHexString(id).toLowerCase();

        StringBuilder sb = new StringBuilder(100);
        sb.append(PROP_ID).append('=').append(hexId).append('\n');
        sb.append(PROP_LABEL).append('=').append(label).append('\n');

        if (publicKey instanceof RSAPublicKey) {
            sb.append(PROP_ALGORITHM).append('=');
            sb.append(PKCSObjectIdentifiers.rsaEncryption.getId());
            sb.append('\n');

            sb.append(PROP_RSA_MODUS).append('=');

            RSAPublicKey rsaKey = (RSAPublicKey) publicKey;
            sb.append(Hex.toHexString(rsaKey.getModulus().toByteArray()));
            sb.append('\n');

            sb.append(PROP_RSA_PUBLIC_EXPONENT).append('=');
            sb.append(Hex.toHexString(rsaKey.getPublicExponent().toByteArray()));
            sb.append('\n');
        } else if (publicKey instanceof DSAPublicKey) {
            sb.append(PROP_ALGORITHM).append('=');
            sb.append(X9ObjectIdentifiers.id_dsa.getId());
            sb.append('\n');

            sb.append(PROP_DSA_PRIME).append('=');
            DSAPublicKey dsaKey = (DSAPublicKey) publicKey;
            sb.append(Hex.toHexString(dsaKey.getParams().getP().toByteArray()));
            sb.append('\n');

            sb.append(PROP_DSA_SUBPRIME).append('=');
            sb.append(Hex.toHexString(dsaKey.getParams().getQ().toByteArray()));
            sb.append('\n');

            sb.append(PROP_DSA_BASE).append('=');
            sb.append(Hex.toHexString(dsaKey.getParams().getG().toByteArray()));
            sb.append('\n');

            sb.append(PROP_DSA_VALUE).append('=');
            sb.append(Hex.toHexString(dsaKey.getY().toByteArray()));
            sb.append('\n');
        } else if (publicKey instanceof ECPublicKey) {
            sb.append(PROP_ALGORITHM).append('=');
            sb.append(X9ObjectIdentifiers.id_ecPublicKey.getId());
            sb.append('\n');

            ECPublicKey ecKey = (ECPublicKey) publicKey;
            ECParameterSpec paramSpec = ecKey.getParams();

            // ecdsaParams
            org.bouncycastle.jce.spec.ECParameterSpec bcParamSpec =
                    EC5Util.convertSpec(paramSpec, false);
            ASN1ObjectIdentifier curveOid = ECUtil.getNamedCurveOid(bcParamSpec);
            if (curveOid == null) {
                throw new SecurityException("EC public key is not of namedCurve");
            }

            byte[] encodedParams;
            try {
                if (namedCurveSupported) {
                    encodedParams = curveOid.getEncoded();
                } else {
                    encodedParams = ECNamedCurveTable.getByOID(curveOid).getEncoded();
                }
            } catch (IOException | NullPointerException ex) {
                throw new SecurityException(ex.getMessage(), ex);
            }

            sb.append(PROP_EC_ECDSA_PARAMS).append('=');
            sb.append(Hex.toHexString(encodedParams));
            sb.append('\n');

            // EC point
            java.security.spec.ECPoint pointW = ecKey.getW();
            BigInteger wx = pointW.getAffineX();
            if (wx.signum() != 1) {
                throw new SecurityException("Wx is not positive");
            }

            BigInteger wy = pointW.getAffineY();
            if (wy.signum() != 1) {
                throw new SecurityException("Wy is not positive");
            }

            int keysize = (paramSpec.getOrder().bitLength() + 7) / 8;
            byte[] wxBytes = wx.toByteArray();
            byte[] wyBytes = wy.toByteArray();
            byte[] ecPoint = new byte[1 + keysize * 2];
            ecPoint[0] = 4; // uncompressed

            int numBytesToCopy = Math.min(wxBytes.length, keysize);
            int srcOffset = Math.max(0, wxBytes.length - numBytesToCopy);
            int destOffset = 1 + Math.max(0, keysize - wxBytes.length);
            System.arraycopy(wxBytes, srcOffset, ecPoint, destOffset, numBytesToCopy);

            numBytesToCopy = Math.min(wyBytes.length, keysize);
            srcOffset = Math.max(0, wyBytes.length - numBytesToCopy);
            destOffset = 1 + keysize + Math.max(0, keysize - wyBytes.length);
            System.arraycopy(wyBytes, srcOffset, ecPoint, destOffset, numBytesToCopy);

            sb.append(PROP_EC_EC_POINT).append('=');
            sb.append(Hex.toHexString(ecPoint));
            sb.append('\n');
        } else {
            throw new IllegalArgumentException(
                    "unsupported public key " + publicKey.getClass().getName());
        }

        try {
            IoUtil.save(new File(pubKeyDir, hexId + INFO_FILE_SUFFIX), sb.toString().getBytes());
        } catch (IOException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }
    }

    private void savePkcs11Cert(
            final byte[] id,
            final String label,
            final X509Certificate cert)
    throws SecurityException, P11TokenException {
        try {
            savePkcs11Entry(certDir, id, label, cert.getEncoded());
        } catch (CertificateEncodingException ex) {
            throw new SecurityException(ex.getMessage(), ex);
        }
    }

    private static void savePkcs11Entry(
            final File dir,
            final byte[] id,
            final String label,
            final byte[] value)
    throws P11TokenException {
        ParamUtil.requireNonNull("dir", dir);
        ParamUtil.requireNonNull("id", id);
        ParamUtil.requireNonBlank("label", label);
        ParamUtil.requireNonNull("value", value);

        String hexId = Hex.toHexString(id).toLowerCase();

        StringBuilder sb = new StringBuilder(200);
        sb.append(PROP_ID).append('=').append(hexId).append('\n');
        sb.append(PROP_LABEL).append('=').append(label).append('\n');
        sb.append(PROP_SHA1SUM).append('=').append(HashCalculator.hexSha1(value)).append('\n');

        try {
            IoUtil.save(new File(dir, hexId + INFO_FILE_SUFFIX), sb.toString().getBytes());
            IoUtil.save(new File(dir, hexId + VALUE_FILE_SUFFIX), value);
        } catch (IOException ex) {
            throw new P11TokenException("could not save certificate");
        }
    }

    private Map<String, X509Certificate> getAllCertificates() {
        File[] infoFiles = certDir.listFiles(INFO_FILENAME_FILTER);
        if (infoFiles == null) {
            return Collections.emptyMap();
        }

        Map<String, X509Certificate> certs = new HashMap<>();
        for (File infoFile : infoFiles) {
            byte[] keyId = getKeyIdFromInfoFilename(infoFile.getName());

            X509Certificate cert;
            try {
                cert = readCertificate(keyId);
            } catch (CertificateException | IOException ex) {
                continue;
            }

            if (cert == null) {
                continue;
            }

            certs.put(Hex.toHexString(keyId), cert);
        }

        return certs;
    }

    private PublicKey readPublicKey(
            final byte[] keyId)
    throws P11TokenException {
        String hexKeyId = Hex.toHexString(keyId);
        File pubKeyFile = new File(pubKeyDir, hexKeyId + INFO_FILE_SUFFIX);
        Properties props = loadProperties(pubKeyFile);

        String algorithm = props.getProperty(PROP_ALGORITHM);
        if (PKCSObjectIdentifiers.rsaEncryption.getId().equals(algorithm)) {
            BigInteger exp = new BigInteger(1,
                    Hex.decode(props.getProperty(PROP_RSA_PUBLIC_EXPONENT)));
            BigInteger mod = new BigInteger(1, Hex.decode(props.getProperty(PROP_RSA_MODUS)));

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
            try {
                return KeyFactory.getInstance("RSA").generatePublic(keySpec);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException ex) {
                throw new P11TokenException(ex.getMessage(), ex);
            }
        } else if (X9ObjectIdentifiers.id_dsa.getId().equals(algorithm)) {
            BigInteger prime = new BigInteger(1,
                    Hex.decode(props.getProperty(PROP_DSA_PRIME))); // p
            BigInteger subPrime = new BigInteger(1,
                    Hex.decode(props.getProperty(PROP_DSA_SUBPRIME))); // q
            BigInteger base = new BigInteger(1,
                    Hex.decode(props.getProperty(PROP_DSA_BASE))); // g
            BigInteger value = new BigInteger(1,
                    Hex.decode(props.getProperty(PROP_DSA_VALUE))); // y

            DSAPublicKeySpec keySpec = new DSAPublicKeySpec(value, prime, subPrime, base);
            try {
                return KeyFactory.getInstance("DSA").generatePublic(keySpec);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException ex) {
                throw new P11TokenException(ex.getMessage(), ex);
            }
        } else if (X9ObjectIdentifiers.id_ecPublicKey.getId().equals(algorithm)) {
            byte[] ecdsaParams = Hex.decode(props.getProperty(PROP_EC_ECDSA_PARAMS));
            byte[] ecPoint = Hex.decode(props.getProperty(PROP_EC_EC_POINT));
            try {
                return KeyUtil.createECPublicKey(ecdsaParams, ecPoint);
            } catch (InvalidKeySpecException ex) {
                throw new P11TokenException(ex.getMessage(), ex);
            }
        } else {
            throw new P11TokenException("unknown key algorithm " + algorithm);
        }
    }

    private X509Certificate readCertificate(
            final byte[] keyId)
    throws CertificateException, IOException {
        return X509Util.parseCert(new File(certDir, Hex.toHexString(keyId) + VALUE_FILE_SUFFIX));
    }

    private byte[] generateKeyId()
    throws P11TokenException {
        Random random = new Random();
        byte[] keyId = null;
        do {
            keyId = new byte[8];
            random.nextBytes(keyId);
        } while (idExists(keyId));

        return keyId;
    }

    private boolean idExists(
            final byte[] keyId) {
        String hexId = Hex.toHexString(keyId).toLowerCase();
        if (new File(privKeyDir, hexId + INFO_FILE_SUFFIX).exists()) {
            return true;
        }

        if (new File(pubKeyDir, hexId + INFO_FILE_SUFFIX).exists()) {
            return true;
        }

        if (new File(certDir, hexId + INFO_FILE_SUFFIX).exists()) {
            return true;
        }

        return false;
    }

    private Properties loadProperties(
            File file)
    throws P11TokenException {
        try {
            try (InputStream stream = new FileInputStream(file)) {
                Properties props = new Properties();
                props.load(stream);
                return props;
            }
        } catch (IOException ex) {
            throw new P11TokenException("could not load properties from the file " + file.getPath(),
                    ex);
        }
    }

    private void assertMechanismSupported(
            final long mechanism)
    throws P11UnsupportedMechanismException {
        if (!supportedMechanisms.contains(mechanism)) {
            throw new P11UnsupportedMechanismException(mechanism, slotId);
        }
    }

    private static byte[] getKeyIdFromInfoFilename(
            final String fileName) {
        return Hex.decode(fileName.substring(0, fileName.length() - INFO_FILE_SUFFIX.length()));
    }

}
