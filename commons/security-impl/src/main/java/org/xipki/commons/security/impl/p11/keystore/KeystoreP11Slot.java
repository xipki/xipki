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

package org.xipki.commons.security.impl.p11.keystore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
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
import java.util.Properties;

import javax.annotation.Nonnull;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.security.api.HashCalculator;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.X509Cert;
import org.xipki.commons.security.api.p11.AbstractP11Slot;
import org.xipki.commons.security.api.p11.P11Constants;
import org.xipki.commons.security.api.p11.P11Identity;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11MechanismFilter;
import org.xipki.commons.security.api.p11.P11ObjectIdentifier;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11SlotRefreshResult;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.p11.P11UnknownEntityException;
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

    private static final FilenameFilter INFO_FILENAME_FILTER = new InfoFilenameFilter();

    private final boolean namedCurveSupported;

    private final File slotDir;

    private final File privKeyDir;

    private final File pubKeyDir;

    private final File certDir;

    private final PrivateKeyCryptor privateKeyCryptor;

    private final SecurityFactory securityFactory;

    private final int maxSessions;

    private static final Logger LOG = LoggerFactory.getLogger(KeystoreP11Slot.class);

    KeystoreP11Slot(
            final String moduleName,
            final File slotDir,
            final P11SlotIdentifier slotId,
            final boolean readOnly,
            final PrivateKeyCryptor privateKeyCryptor,
            final SecurityFactory securityFactory,
            final P11MechanismFilter mechanismFilter,
            final int maxSessions)
    throws P11TokenException {
        super(moduleName, slotId, readOnly, mechanismFilter);

        this.slotDir = ParamUtil.requireNonNull("slotDir", slotDir);
        this.securityFactory = ParamUtil.requireNonNull("securityFactory", securityFactory);
        this.privateKeyCryptor = ParamUtil.requireNonNull("privateKeyCryptor", privateKeyCryptor);
        this.maxSessions = ParamUtil.requireMin("maxSessions", maxSessions, 1);

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

        refresh();
    }

    @Override
    protected P11SlotRefreshResult doRefresh(
            P11MechanismFilter mechanismFilter)
    throws P11TokenException {
        P11SlotRefreshResult ret = new P11SlotRefreshResult();

        ret.addMechanism(P11Constants.CKM_DSA_KEY_PAIR_GEN);
        ret.addMechanism(P11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
        ret. addMechanism(P11Constants.CKM_EC_KEY_PAIR_GEN);

        ret.addMechanism(P11Constants.CKM_RSA_X_509);

        ret.addMechanism(P11Constants.CKM_RSA_PKCS);
        ret.addMechanism(P11Constants.CKM_SHA1_RSA_PKCS);
        ret.addMechanism(P11Constants.CKM_SHA224_RSA_PKCS);
        ret.addMechanism(P11Constants.CKM_SHA256_RSA_PKCS);
        ret.addMechanism(P11Constants.CKM_SHA384_RSA_PKCS);
        ret.addMechanism(P11Constants.CKM_SHA512_RSA_PKCS);

        ret.addMechanism(P11Constants.CKM_RSA_PKCS_PSS);
        ret.addMechanism(P11Constants.CKM_SHA1_RSA_PKCS_PSS);
        ret.addMechanism(P11Constants.CKM_SHA224_RSA_PKCS_PSS);
        ret.addMechanism(P11Constants.CKM_SHA256_RSA_PKCS_PSS);
        ret.addMechanism(P11Constants.CKM_SHA384_RSA_PKCS_PSS);
        ret.addMechanism(P11Constants.CKM_SHA512_RSA_PKCS_PSS);

        ret.addMechanism(P11Constants.CKM_DSA);
        ret.addMechanism(P11Constants.CKM_DSA_SHA1);
        ret.addMechanism(P11Constants.CKM_DSA_SHA224);
        ret.addMechanism(P11Constants.CKM_DSA_SHA256);
        ret.addMechanism(P11Constants.CKM_DSA_SHA384);
        ret.addMechanism(P11Constants.CKM_DSA_SHA512);

        ret.addMechanism(P11Constants.CKM_ECDSA);
        ret.addMechanism(P11Constants.CKM_ECDSA_SHA1);
        ret.addMechanism(P11Constants.CKM_ECDSA_SHA224);
        ret.addMechanism(P11Constants.CKM_ECDSA_SHA256);
        ret.addMechanism(P11Constants.CKM_ECDSA_SHA384);
        ret.addMechanism(P11Constants.CKM_ECDSA_SHA512);

        // Certificates

        File[] certInfoFiles = certDir.listFiles(INFO_FILENAME_FILTER);
        if (certInfoFiles != null) {
            for (File infoFile : certInfoFiles) {
                byte[] id = getKeyIdFromInfoFilename(infoFile.getName());
                Properties props = loadProperties(infoFile);
                String label = props.getProperty(PROP_LABEL);
                P11ObjectIdentifier objId = new P11ObjectIdentifier(id, label);
                try {
                    X509Cert cert = readCertificate(id);
                    ret.addCertificate(objId, cert);
                } catch (CertificateException | IOException ex) {
                    LOG.warn("could not parse certificate " + objId);
                }
            }
        }

        // Private / Public keys
        File[] privKeyInfoFiles = privKeyDir.listFiles(INFO_FILENAME_FILTER);

        if (privKeyInfoFiles == null || privKeyInfoFiles.length == 0) {
            return ret;
        }

        for (File privKeyInfoFile : privKeyInfoFiles) {
            byte[] id = getKeyIdFromInfoFilename(privKeyInfoFile.getName());
            String hexId = Hex.toHexString(id);

            try {
                Properties props = loadProperties(privKeyInfoFile);
                String label = props.getProperty(PROP_LABEL);

                P11ObjectIdentifier p11ObjId = new P11ObjectIdentifier(id, label);
                X509Cert cert = ret.getCertForId(id);
                java.security.PublicKey publicKey = (cert == null)
                        ? readPublicKey(id)
                        : cert.getCert().getPublicKey();

                if (publicKey == null) {
                    LOG.warn("Neither public key nor certificate is associated with private key {}",
                            p11ObjId);
                    continue;
                }

                byte[] encodedValue = IoUtil.read(
                        new File(privKeyDir, hexId + VALUE_FILE_SUFFIX));

                PKCS8EncryptedPrivateKeyInfo epki = new PKCS8EncryptedPrivateKeyInfo(encodedValue);
                PrivateKey privateKey = privateKeyCryptor.decrypt(epki);

                X509Certificate[] certs = (cert == null)
                        ? null
                        : new X509Certificate[]{cert.getCert()};

                KeystoreP11Identity entity = new KeystoreP11Identity(
                        new P11EntityIdentifier(slotId, p11ObjId), privateKey, publicKey,
                        certs, maxSessions, securityFactory.getRandom4Sign());
                LOG.info("added PKCS#11 key {}", p11ObjId);
                ret.addEntity(entity);
            } catch (InvalidKeyException ex) {
                final String message = "InvalidKeyException while initializing key with key-id "
                        + hexId;
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                            ex.getMessage());
                }
                LOG.debug(message, ex);
                continue;
            } catch (Throwable th) {
                final String message =
                        "unexpected exception while initializing key with key-id " + hexId;
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), th.getClass().getName(),
                            th.getMessage());
                }
                LOG.debug(message, th);
                continue;
            }
        }

        return ret;
    } // method refresh

    File getSlotDir() {
        return slotDir;
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

    private X509Cert readCertificate(
            final byte[] keyId)
    throws CertificateException, IOException {
        byte[] encoded = IoUtil.read(new File(certDir, Hex.toHexString(keyId) + VALUE_FILE_SUFFIX));
        X509Certificate cert = X509Util.parseCert(encoded);
        return new X509Cert(cert, encoded);
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

    private boolean removePkcs11Cert(
            final P11ObjectIdentifier objectId)
    throws P11TokenException {
        return removePkcs11Entry(certDir, objectId);
    }

    private boolean removePkcs11Entry(
            final File dir,
            final P11ObjectIdentifier objectId)
    throws P11TokenException {
        byte[] id = objectId.getId();
        String label = objectId.getLabel();
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
    throws P11TokenException {
        PKCS8EncryptedPrivateKeyInfo encryptedPrivKeyInfo = privateKeyCryptor.encrypt(privateKey);
        byte[] encoded;
        try {
            encoded = encryptedPrivKeyInfo.getEncoded();
        } catch (IOException ex) {
            throw new P11TokenException("could not encode PrivateKey");
        }
        savePkcs11Entry(privKeyDir, id, label, encoded);
    }

    private void savePkcs11PublicKey(
            final byte[] id,
            final String label,
            final PublicKey publicKey)
    throws P11TokenException {
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
                throw new P11TokenException("EC public key is not of namedCurve");
            }

            byte[] encodedParams;
            try {
                if (namedCurveSupported) {
                    encodedParams = curveOid.getEncoded();
                } else {
                    encodedParams = ECNamedCurveTable.getByOID(curveOid).getEncoded();
                }
            } catch (IOException | NullPointerException ex) {
                throw new P11TokenException(ex.getMessage(), ex);
            }

            sb.append(PROP_EC_ECDSA_PARAMS).append('=');
            sb.append(Hex.toHexString(encodedParams));
            sb.append('\n');

            // EC point
            java.security.spec.ECPoint pointW = ecKey.getW();
            BigInteger wx = pointW.getAffineX();
            if (wx.signum() != 1) {
                throw new P11TokenException("Wx is not positive");
            }

            BigInteger wy = pointW.getAffineY();
            if (wy.signum() != 1) {
                throw new P11TokenException("Wy is not positive");
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

    @Override
    protected void doRemoveIdentity(
            final P11ObjectIdentifier objectId)
    throws P11TokenException {
        boolean b1 = removePkcs11Entry(certDir, objectId);
        boolean b2 = removePkcs11Entry(privKeyDir, objectId);
        boolean b3 = removePkcs11Entry(pubKeyDir, objectId);
        if (! (b1 || b2 || b3)) {
            throw new P11UnknownEntityException(slotId, objectId);
        }
    }

    @Override
    protected void doRemoveCerts(
            final P11ObjectIdentifier objectId)
    throws P11TokenException {
        deletePkcs11Entry(certDir, objectId.getId());
    }

    @Override
    protected void doAddCert(
            final P11ObjectIdentifier objectId,
            final X509Certificate cert)
    throws P11TokenException, SecurityException {
        savePkcs11Cert(objectId.getId(), objectId.getLabel(), cert);
    }

    @Override
    protected P11Identity doGenerateRSAKeypair(
            final int keysize,
            final BigInteger publicExponent,
            final String label)
    throws P11TokenException {
        KeyPair keypair;
        try {
            keypair = KeyUtil.generateRSAKeypair(keysize, publicExponent,
                    securityFactory.getRandom4Key());
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                | InvalidAlgorithmParameterException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }
        return saveP11Entity(keypair, label);
    }

    @Override
    protected P11Identity doGenerateDSAKeypair(
            final BigInteger p, // CHECKSTYLE:SKIP
            final BigInteger q, // CHECKSTYLE:SKIP
            final BigInteger g, // CHECKSTYLE:SKIP
            final String label)
    throws P11TokenException {
        DSAParameters dsaParams = new DSAParameters(p, q, g);
        KeyPair keypair;
        try {
            keypair = KeyUtil.generateDSAKeypair(dsaParams, securityFactory.getRandom4Key());
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                | InvalidAlgorithmParameterException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }
        return saveP11Entity(keypair, label);
    }

    @Override
    protected P11Identity doGenerateECKeypair(
            final ASN1ObjectIdentifier curveId,
            final String label)
    throws P11TokenException {
        KeyPair keypair;
        try {
            keypair = KeyUtil.generateECKeypairForCurveNameOrOid(curveId.getId(),
                    securityFactory.getRandom4Key());
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                | InvalidAlgorithmParameterException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }
        return saveP11Entity(keypair, label);
    }

    private P11Identity saveP11Entity(
            @Nonnull final KeyPair keypair,
            @Nonnull final String label)
    throws P11TokenException {
        byte[] id = generateId();
        savePkcs11PrivateKey(id, label, keypair.getPrivate());
        savePkcs11PublicKey(id, label, keypair.getPublic());
        P11EntityIdentifier entityId = new P11EntityIdentifier(slotId,
                new P11ObjectIdentifier(id, label));
        try {
            return new KeystoreP11Identity(entityId, keypair.getPrivate(), keypair.getPublic(),
                    null, maxSessions, securityFactory.getRandom4Sign());
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new P11TokenException(
                    "could not counstruct KeyStoreP11Identity: " + ex.getMessage(), ex);
        }
    }

    @Override
    protected void doUpdateCertificate(
            final P11ObjectIdentifier objectId,
            final X509Certificate newCert)
    throws SecurityException, P11TokenException {
        removePkcs11Cert(objectId);
        doAddCert(objectId, newCert);
    }

}
