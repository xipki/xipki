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
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.p11.AbstractP11Slot;
import org.xipki.commons.security.api.p11.P11Constants;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11MechanismFilter;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.util.KeyUtil;
import org.xipki.commons.security.api.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class KeystoreP11Slot extends AbstractP11Slot {

    private static class InfoFilenameFilter implements FilenameFilter {

        @Override
        public boolean accept(File dir, String name) {
            return name.endsWith(INFO_FILE_SUFFIX);
        }

    }

    // slotinfo
    protected static final String FILE_SLOTINFO = "slot.info";
    protected static final String PROP_NAMED_CURVE_SUPPORTED = "namedCurveSupported";

    protected static final String DIR_PRIV_KEY = "privkey";
    protected static final String DIR_PUB_KEY = "pubkey";
    protected static final String DIR_CERT = "cert";

    protected static final String INFO_FILE_SUFFIX = ".info";
    protected static final String VALUE_FILE_SUFFIX = ".value";

    protected static final String PROP_ID = "id";
    protected static final String PROP_LABEL = "label";
    protected static final String PROP_SHA1SUM = "sha1";

    protected static final String PROP_ALGORITHM = "algorithm";

    // RSA
    protected static final String PROP_RSA_MODUS = "modus";
    protected static final String PROP_RSA_PUBLIC_EXPONENT = "publicExponent";

    // DSA
    protected static final String PROP_DSA_PRIME = "prime"; // p
    protected static final String PROP_DSA_SUBPRIME = "subprime"; // q
    protected static final String PROP_DSA_BASE = "base"; // g
    protected static final String PROP_DSA_VALUE = "value"; // y

    // EC
    protected static final String PROP_EC_ECDSA_PARAMS = "ecdsaParams";
    protected static final String PROP_EC_EC_POINT = "ecPoint";

    protected static final FilenameFilter INFO_FILENAME_FILTER = new InfoFilenameFilter();

    protected final boolean namedCurveSupported;

    protected final File slotDir;

    protected final File privKeyDir;

    protected final File pubKeyDir;

    protected final File certDir;

    protected final PrivateKeyCryptor privateKeyCryptor;

    protected final SecurityFactory securityFactory;

    private static final Logger LOG = LoggerFactory.getLogger(KeystoreP11Slot.class);

    KeystoreP11Slot(
            final String moduleName,
            final File slotDir,
            final P11SlotIdentifier slotId,
            final PrivateKeyCryptor privateKeyCryptor,
            final SecurityFactory securityFactory,
            final P11MechanismFilter mechanismFilter)
    throws P11TokenException {
        super(moduleName, slotId, mechanismFilter);

        this.slotDir = ParamUtil.requireNonNull("slotDir", slotDir);
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

        addMechanism(P11Constants.CKM_DSA_KEY_PAIR_GEN);
        addMechanism(P11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
        addMechanism(P11Constants.CKM_EC_KEY_PAIR_GEN);

        addMechanism(P11Constants.CKM_RSA_X_509);

        addMechanism(P11Constants.CKM_RSA_PKCS);
        addMechanism(P11Constants.CKM_SHA1_RSA_PKCS);
        addMechanism(P11Constants.CKM_SHA224_RSA_PKCS);
        addMechanism(P11Constants.CKM_SHA256_RSA_PKCS);
        addMechanism(P11Constants.CKM_SHA384_RSA_PKCS);
        addMechanism(P11Constants.CKM_SHA512_RSA_PKCS);

        addMechanism(P11Constants.CKM_RSA_PKCS_PSS);
        addMechanism(P11Constants.CKM_SHA1_RSA_PKCS_PSS);
        addMechanism(P11Constants.CKM_SHA224_RSA_PKCS_PSS);
        addMechanism(P11Constants.CKM_SHA256_RSA_PKCS_PSS);
        addMechanism(P11Constants.CKM_SHA384_RSA_PKCS_PSS);
        addMechanism(P11Constants.CKM_SHA512_RSA_PKCS_PSS);

        addMechanism(P11Constants.CKM_DSA);
        addMechanism(P11Constants.CKM_DSA_SHA1);
        addMechanism(P11Constants.CKM_DSA_SHA224);
        addMechanism(P11Constants.CKM_DSA_SHA256);
        addMechanism(P11Constants.CKM_DSA_SHA384);
        addMechanism(P11Constants.CKM_DSA_SHA512);

        addMechanism(P11Constants.CKM_ECDSA);
        addMechanism(P11Constants.CKM_ECDSA_SHA1);
        addMechanism(P11Constants.CKM_ECDSA_SHA224);
        addMechanism(P11Constants.CKM_ECDSA_SHA256);
        addMechanism(P11Constants.CKM_ECDSA_SHA384);
        addMechanism(P11Constants.CKM_ECDSA_SHA512);

        refresh();
    }

    @Override
    public void refresh()
    throws P11TokenException {
        File[] privKeyInfoFiles = privKeyDir.listFiles(INFO_FILENAME_FILTER);
        if (privKeyInfoFiles == null || privKeyInfoFiles.length == 0) {
            clearMechanisms();
            setIdentities(Collections.emptySet());
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

        setIdentities(currentIdentifies);
    } // method refresh

    File getSlotDir() {
        return slotDir;
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

    private Properties loadProperties(
            final File file)
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

    private static byte[] getKeyIdFromInfoFilename(
            final String fileName) {
        return Hex.decode(fileName.substring(0, fileName.length() - INFO_FILE_SUFFIX.length()));
    }

    @Override
    public void close() {
        LOG.info("close slot " + slotId);
    }

}
