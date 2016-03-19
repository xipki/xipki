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

package org.xipki.commons.security.impl.p11.iaik;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.DSAParameterGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.HashCalculator;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.p11.P11Constants;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11MechanismFilter;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.p11.P11UnknownEntityException;
import org.xipki.commons.security.api.p11.P11WritableSlot;
import org.xipki.commons.security.api.util.KeyUtil;
import org.xipki.commons.security.api.util.X509Util;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Certificate.CertificateType;
import iaik.pkcs.pkcs11.objects.DSAPrivateKey;
import iaik.pkcs.pkcs11.objects.DSAPublicKey;
import iaik.pkcs.pkcs11.objects.ECDSAPrivateKey;
import iaik.pkcs.pkcs11.objects.ECDSAPublicKey;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

// FIXME: call the removeIdentity() after deleting key and addIdentity() after adding key instead
// of refresh()
// FIXME: remove the refresh from the shell commands.
// FIXME: check if the cached identify exists if possible, before listing new identities
class IaikP11WritableSlot extends IaikP11Slot implements P11WritableSlot {

    private static final Logger LOG = LoggerFactory.getLogger(IaikP11WritableSlot.class);

    private boolean writableSessionInUse;

    private Session writableSession;

    IaikP11WritableSlot(
            final String moduleName,
            final P11SlotIdentifier slotId,
            final Slot slot,
            final long userType,
            final List<char[]> password,
            final int maxMessageSize,
            final P11MechanismFilter mechanismFilter)
    throws P11TokenException {
        super(moduleName, slotId, slot, userType, password, maxMessageSize, mechanismFilter);
    }

    private synchronized Session borrowWritableSession()
    throws P11TokenException {
        if (writableSession == null) {
            writableSession = openSession(true);
        }

        if (writableSessionInUse) {
            throw new P11TokenException("no idle writable session available");
        }

        writableSessionInUse = true;
        return writableSession;
    }

    private synchronized void returnWritableSession(
            final Session session)
    throws P11TokenException {
        if (session != writableSession) {
            throw new P11TokenException("the returned session does not belong to me");
        }
        this.writableSessionInUse = false;
    }

    private List<X509PublicKeyCertificate> getAllCertificateObjects()
    throws P11TokenException {
        Session session = borrowIdleSession();
        try {
            if (LOG.isTraceEnabled()) {
                String info = listCertificateObjects(session);
                LOG.debug(info);
            }
            X509PublicKeyCertificate template = new X509PublicKeyCertificate();
            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            final int n = tmpObjects.size();
            List<X509PublicKeyCertificate> certs = new ArrayList<>(n);
            for (iaik.pkcs.pkcs11.objects.Object tmpObject : tmpObjects) {
                X509PublicKeyCertificate cert = (X509PublicKeyCertificate) tmpObject;
                certs.add(cert);
            }
            return certs;
        } finally {
            returnIdleSession(session);
        }
    }

    private PrivateKey getPrivateObject(
            final Boolean forSigning,
            final Boolean forDecrypting,
            final P11KeyIdentifier keyIdentifier)
    throws P11TokenException {
        Session session = borrowIdleSession();

        try {
            if (LOG.isTraceEnabled()) {
                String info = listPrivateKeyObjects(session, forSigning, forDecrypting);
                LOG.debug(info);
            }

            PrivateKey template = new PrivateKey();
            if (forSigning != null) {
                template.getSign().setBooleanValue(forSigning);
            }
            if (forDecrypting != null) {
                template.getDecrypt().setBooleanValue(forDecrypting);
            }

            template.getId().setByteArrayValue(keyIdentifier.getKeyId());
            template.getLabel().setCharArrayValue(keyIdentifier.getKeyLabel().toCharArray());

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            if (CollectionUtil.isEmpty(tmpObjects)) {
                return null;
            }

            int size = tmpObjects.size();
            if (size > 1) {
                LOG.warn("found {} private key identified by {}, use the first one", size,
                        keyIdentifier);
            }
            return (PrivateKey) tmpObjects.get(0);
        } finally {
            returnIdleSession(session);
        }
    } // method getPrivateObject

    private boolean existsCertificateObjects(
            final byte[] keyId,
            final char[] keyLabel)
    throws P11TokenException {
        Session session = borrowIdleSession();

        try {
            if (LOG.isTraceEnabled()) {
                String info = listCertificateObjects(session);
                LOG.debug(info);
            }

            X509PublicKeyCertificate template = new X509PublicKeyCertificate();
            if (keyId != null) {
                template.getId().setByteArrayValue(keyId);
            }
            if (keyLabel != null) {
                template.getLabel().setCharArrayValue(keyLabel);
            }

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template, 1);
            return !CollectionUtil.isEmpty(tmpObjects);
        } finally {
            returnIdleSession(session);
        }
    }

    @Override
    public void updateCertificate(
            final P11KeyIdentifier keyIdentifier,
            final X509Certificate newCert,
            final Set<X509Certificate> caCerts,
            final SecurityFactory securityFactory)
    throws SecurityException, P11TokenException {
        ParamUtil.requireNonNull("keyIdentifier", keyIdentifier);
        ParamUtil.requireNonNull("newCert", newCert);

        PrivateKey privKey = getPrivateObject(null, null, keyIdentifier);

        if (privKey == null) {
            throw new P11UnknownEntityException("could not find private key " + keyIdentifier);
        }

        byte[] keyId = privKey.getId().getByteArrayValue();
        X509PublicKeyCertificate[] existingCerts = getCertificateObjects(keyId, null);

        assertMatch(newCert, keyIdentifier, securityFactory);

        X509Certificate[] certChain = X509Util.buildCertPath(newCert, caCerts);

        Session session = borrowWritableSession();
        try {
            X509PublicKeyCertificate newCertTemp = createPkcs11Template(newCert, null, keyId,
                    privKey.getLabel().getCharArrayValue());
            // delete existing signer certificate objects
            if (existingCerts != null && existingCerts.length > 0) {
                for (X509PublicKeyCertificate existingCert : existingCerts) {
                    session.destroyObject(existingCert);
                }
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ex) {
                    throw new P11TokenException("could not destroy object, interrupted");
                }
            }

            // create new signer certificate object
            session.createObject(newCertTemp);

            // create CA certificate objects
            if (certChain.length > 1) {
                for (int i = 1; i < certChain.length; i++) {
                    X509Certificate caCert = certChain[i];
                    byte[] encodedCaCert;
                    try {
                        encodedCaCert = caCert.getEncoded();
                    } catch (CertificateEncodingException ex) {
                        throw new SecurityException(
                                "could not encode certificate: " + ex.getMessage(), ex);
                    }

                    boolean alreadyExists = false;
                    X509PublicKeyCertificate[] certObjs = getCertificateObjects(
                            caCert.getSubjectX500Principal());
                    if (certObjs != null) {
                        for (X509PublicKeyCertificate certObj : certObjs) {
                            if (Arrays.equals(encodedCaCert,
                                    certObj.getValue().getByteArrayValue())) {
                                alreadyExists = true;
                                break;
                            }
                        }
                    }

                    if (alreadyExists) {
                        continue;
                    }

                    byte[] caCertKeyId = IaikP11Util.generateKeyId(session);

                    X500Name caX500Name = X500Name.getInstance(
                            caCert.getSubjectX500Principal().getEncoded());
                    String caCommonName = X509Util.getCommonName(caX500Name);

                    String label = null;
                    for (int j = 0;; j++) {
                        label = (j == 0)
                                ? caCommonName
                                : caCommonName + "-" + j;
                        if (!existsCertificateObjects(null, label.toCharArray())) {
                            break;
                        }
                    }

                    X509PublicKeyCertificate newCaCertTemp = createPkcs11Template(
                            caCert, encodedCaCert, caCertKeyId, label.toCharArray());
                    session.createObject(newCaCertTemp);
                }
            } // end if(certChain.length)
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        } finally {
            returnWritableSession(session);
        }
    } // method updateCertificate

    @Override
    public boolean removeKey(
            final P11KeyIdentifier keyIdentifier)
    throws SecurityException, P11TokenException {
        return doRemoveKeyAndCerts(keyIdentifier, false);
    }

    @Override
    public boolean removeKeyAndCerts(
            final P11KeyIdentifier keyIdentifier)
    throws SecurityException, P11TokenException {
        return doRemoveKeyAndCerts(keyIdentifier, true);
    }

    private boolean doRemoveKeyAndCerts(
            final P11KeyIdentifier keyIdentifier, boolean removeCerts)
    throws SecurityException, P11TokenException {
        ParamUtil.requireNonNull("keyIdentifier", keyIdentifier);

        PrivateKey privKey = getPrivateObject(null, null, keyIdentifier);
        if (privKey == null) {
            return false;
        }

        StringBuilder msgBuilder = new StringBuilder();
        Session session = borrowWritableSession();
        try {
            try {
                session.destroyObject(privKey);
            } catch (TokenException ex) {
                msgBuilder.append("could not delete private key, ");
            }

            PublicKey pubKey = getPublicKeyObject(null, null,
                    privKey.getId().getByteArrayValue(), null);
            if (pubKey != null) {
                try {
                    session.destroyObject(pubKey);
                } catch (TokenException ex) {
                    msgBuilder.append("could not delete public key, ");
                }
            }

            if (removeCerts) {
                X509PublicKeyCertificate[] certs = getCertificateObjects(
                        privKey.getId().getByteArrayValue(), null);
                if (certs != null && certs.length > 0) {
                    for (int i = 0; i < certs.length; i++) {
                        try {
                            session.destroyObject(certs[i]);
                        } catch (TokenException ex) {
                            msgBuilder.append("could not delete certificate at index ")
                                .append(i)
                                .append(", ");
                        }
                    } // end for
                } // end if (certs)
            } // end removeCerts
        } finally {
            returnWritableSession(session);
        }

        final int n = msgBuilder.length();
        if (n > 2) {
            throw new SecurityException(msgBuilder.substring(0, n - 2));
        }

        return true;
    } // method doRemoveKeyAndCerts

    @Override
    public void removeCerts(
            final P11KeyIdentifier keyIdentifier)
    throws SecurityException, P11TokenException {
        ParamUtil.requireNonNull("keyIdentifier", keyIdentifier);

        String keyLabel = keyIdentifier.getKeyLabel();
        char[] keyLabelChars = (keyLabel == null)
                ? null
                : keyLabel.toCharArray();

        X509PublicKeyCertificate[] existingCerts = getCertificateObjects(
                keyIdentifier.getKeyId(), keyLabelChars);

        if (existingCerts == null || existingCerts.length == 0) {
            throw new SecurityException("could not find certificates with id " + keyIdentifier);
        }

        Session session = borrowWritableSession();
        try {
            for (X509PublicKeyCertificate cert : existingCerts) {
                session.destroyObject(cert);
            }
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        } finally {
            returnWritableSession(session);
        }
    }

    private void assertMatch(
            final X509Certificate cert,
            final P11KeyIdentifier keyId,
            final SecurityFactory securityFactory)
    throws SecurityException {
        ParamUtil.requireNonNull("securityFactory", securityFactory);
        ConfPairs pairs = new ConfPairs("slot-id", Long.toString(slot.getSlotID()));
        if (keyId.getKeyId() != null) {
            pairs.putPair("key-id", Hex.toHexString(keyId.getKeyId()));
        }
        if (keyId.getKeyLabel() != null) {
            pairs.putPair("key-label", keyId.getKeyLabel());
        }

        securityFactory.createSigner("PKCS11", pairs.getEncoded(), "SHA1", null, cert);
    }

    @Override
    public P11KeyIdentifier addCert(
            final X509Certificate cert)
    throws SecurityException, P11TokenException {
        ParamUtil.requireNonNull("cert", cert);
        Session session = borrowWritableSession();
        try {
            byte[] encodedCert = cert.getEncoded();

            X509PublicKeyCertificate[] certObjs = getCertificateObjects(
                    cert.getSubjectX500Principal());
            if (certObjs != null) {
                for (X509PublicKeyCertificate certObj : certObjs) {
                    if (Arrays.equals(encodedCert, certObj.getValue().getByteArrayValue())) {
                        P11KeyIdentifier p11KeyId = new P11KeyIdentifier(
                                certObj.getId().getByteArrayValue(),
                                new String(certObj.getLabel().getCharArrayValue()));
                        throw new SecurityException(
                                "given certificate already exists under " + p11KeyId);
                    }
                }
            }

            byte[] keyId = IaikP11Util.generateKeyId(session);

            X500Name x500Name = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
            String cn = X509Util.getCommonName(x500Name);

            String label = null;
            for (int j = 0;; j++) {
                label = (j == 0)
                        ? cn
                        : cn + "-" + j;
                if (!existsCertificateObjects(null, label.toCharArray())) {
                    break;
                }
            }

            X509PublicKeyCertificate newCaCertTemp = createPkcs11Template(
                    cert, encodedCert, keyId, label.toCharArray());
            session.createObject(newCaCertTemp);
            P11KeyIdentifier p11KeyId = new P11KeyIdentifier(keyId,
                    new String(newCaCertTemp.getLabel().getCharArrayValue()));
            return p11KeyId;
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        } catch (CertificateEncodingException ex) {
            throw new SecurityException(ex.getMessage(), ex);
        } finally {
            returnWritableSession(session);
        }
    } // method addCert

    @Override
    public P11KeyIdentifier generateRSAKeypair(
            final int keySize,
            final BigInteger publicExponent,
            final String label)
    throws P11TokenException {
        ParamUtil.requireNonBlank("label", label);
        ParamUtil.requireMin("keySize", keySize, 1024);

        if (keySize % 1024 != 0) {
            throw new IllegalArgumentException("key size is not multiple of 1024: " + keySize);
        }

        Session session = borrowWritableSession();
        try {
            if (IaikP11Util.labelExists(session, label)) {
                throw new IllegalArgumentException(
                        "label " + label + " exists, please specify another one");
            }

            byte[] id = IaikP11Util.generateKeyId(session);

            generateRSAKeyPair(
                    session,
                    keySize, publicExponent, id, label);

            return new P11KeyIdentifier(id, label);
        } finally {
            returnWritableSession(session);
        }
    } // method generateRSAKeypair

    @Override
    public P11KeyIdentifier generateDSAKeypair(
            final int plength,
            final int qlength,
            final String label)
    throws P11TokenException {
        ParamUtil.requireNonBlank("label", label);
        ParamUtil.requireMin("pLength", plength, 1024);

        if (plength % 1024 != 0) {
            throw new IllegalArgumentException("key size is not multiple of 1024: " + plength);
        }

        Session session = borrowWritableSession();
        try {
            if (IaikP11Util.labelExists(session, label)) {
                throw new IllegalArgumentException(
                        "label " + label + " exists, please specify another one");
            }

            byte[] id = IaikP11Util.generateKeyId(session);
            generateDSAKeyPair(session, plength, qlength, id, label);
            return new P11KeyIdentifier(id, label);
        } finally {
            returnWritableSession(session);
        }
    }

    @Override
    public P11KeyIdentifier generateECKeypair(
            final String curveNameOrOid,
            final String label)
    throws SecurityException, P11TokenException {
        ParamUtil.requireNonBlank("curveNameOrOid", curveNameOrOid);
        ParamUtil.requireNonBlank("label", label);

        ASN1ObjectIdentifier curveId = getCurveId(curveNameOrOid);
        if (curveId == null) {
            throw new IllegalArgumentException("unknown curve " + curveNameOrOid);
        }

        X9ECParameters ecParams = ECNamedCurveTable.getByOID(curveId);
        if (ecParams == null) {
            throw new IllegalArgumentException("unknown curve " + curveNameOrOid);
        }

        Session session = borrowWritableSession();
        try {
            if (IaikP11Util.labelExists(session, label)) {
                throw new IllegalArgumentException(
                        "label " + label + " exists, please specify another one");
            }

            byte[] id = IaikP11Util.generateKeyId(session);

            generateECKeyPair(
                    session, curveId, ecParams, id, label);

            return new P11KeyIdentifier(id, label);
        } finally {
            returnWritableSession(session);
        }
    } // method generateECKeypair

    // CHECKSTYLE:SKIP
    private void generateDSAKeyPair(
            final Session session,
            final int plength,
            final int qlength,
            final byte[] id,
            final String label)
    throws P11TokenException {
        long mech = P11Constants.CKM_DSA_KEY_PAIR_GEN;
        assertMechanismSupported(mech);

        DSAParametersGenerator paramGen = new DSAParametersGenerator(new SHA512Digest());
        DSAParameterGenerationParameters genParams = new DSAParameterGenerationParameters(
                plength, qlength, 80, new SecureRandom());
        paramGen.init(genParams);
        DSAParameters dsaParams = paramGen.generateParameters();

        DSAPrivateKey privateKey = new DSAPrivateKey();
        DSAPublicKey publicKey = new DSAPublicKey();

        setKeyAttributes(id, label, P11Constants.CKK_DSA, publicKey, privateKey);

        publicKey.getPrime().setByteArrayValue(dsaParams.getP().toByteArray());
        publicKey.getSubprime().setByteArrayValue(dsaParams.getQ().toByteArray());
        publicKey.getBase().setByteArrayValue(dsaParams.getG().toByteArray());

        try {
            session.generateKeyPair(Mechanism.get(mech), publicKey, privateKey);
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }
    } // method generateDSAKeyPair

    // CHECKSTYLE:SKIP
    private void generateRSAKeyPair(
            final Session session,
            final int keySize,
            final BigInteger publicExponent,
            final byte[] id,
            final String label)
    throws P11TokenException {
        long mech = P11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;
        assertMechanismSupported(mech);

        BigInteger tmpPublicExponent = publicExponent;
        if (tmpPublicExponent == null) {
            tmpPublicExponent = BigInteger.valueOf(65537);
        }

        RSAPrivateKey privateKey = new RSAPrivateKey();
        RSAPublicKey publicKey = new RSAPublicKey();

        setKeyAttributes(id, label, P11Constants.CKK_RSA, publicKey, privateKey);

        publicKey.getModulusBits().setLongValue((long) keySize);
        publicKey.getPublicExponent().setByteArrayValue(tmpPublicExponent.toByteArray());

        try {
            session.generateKeyPair(Mechanism.get(mech), publicKey, privateKey);
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }
    } // method generateRSAKeyPair

    // CHECKSTYLE:SKIP
    private void generateECKeyPair(
            final Session session,
            final ASN1ObjectIdentifier curveId,
            final X9ECParameters ecParams,
            final byte[] id,
            final String label)
    throws SecurityException, P11TokenException {
        long mech = P11Constants.CKM_EC_KEY_PAIR_GEN;
        assertMechanismSupported(mech);

        ECDSAPrivateKey privateKey = new ECDSAPrivateKey();
        ECDSAPublicKey publicKey = new ECDSAPublicKey();
        setKeyAttributes(id, label, P11Constants.CKK_EC, publicKey, privateKey);

        byte[] encodedCurveId;
        try {
            encodedCurveId = curveId.getEncoded();
        } catch (IOException ex) {
            throw new SecurityException(ex.getMessage(), ex);
        }
        try {
            publicKey.getEcdsaParams().setByteArrayValue(encodedCurveId);
            session.generateKeyPair(Mechanism.get(mech), publicKey, privateKey);
        } catch (TokenException ex) {
            try {
                publicKey.getEcdsaParams().setByteArrayValue(ecParams.getEncoded());
            } catch (IOException ex2) {
                throw new SecurityException(ex.getMessage(), ex);
            }
            try {
                session.generateKeyPair(Mechanism.get(mech), publicKey, privateKey);
            } catch (TokenException ex2) {
                throw new P11TokenException("could not generate EC keypair", ex2);
            }
        }
    }

    @Override
    public X509Certificate exportCert(
            final P11KeyIdentifier keyId)
    throws SecurityException, P11TokenException {
        ParamUtil.requireNonNull("keyId", keyId);
        try {
            return getIdentity(keyId).getCertificate();
        } catch (P11UnknownEntityException ex) {
            // CHECKSTYLE:SKIP
        }

        X509PublicKeyCertificate cert = getCertificateObject(keyId.getKeyId(), null);
        if (cert == null) {
            throw new P11UnknownEntityException(slotId, keyId);
        }
        try {
            return X509Util.parseCert(cert.getValue().getByteArrayValue());
        } catch (CertificateException | IOException ex) {
            throw new SecurityException(ex.getMessage(), ex);
        }
    }

    private static X509PublicKeyCertificate createPkcs11Template(
            final X509Certificate cert,
            final byte[] encodedCert,
            final byte[] keyId,
            final char[] label)
    throws SecurityException, P11TokenException {
        if (label == null || label.length == 0) {
            throw new IllegalArgumentException("label must not be null or empty");
        }

        byte[] tmpEncodedCert = encodedCert;
        if (tmpEncodedCert == null) {
            try {
                tmpEncodedCert = cert.getEncoded();
            } catch (CertificateEncodingException ex) {
                throw new SecurityException(ex.getMessage(), ex);
            }
        }

        X509PublicKeyCertificate newCertTemp = new X509PublicKeyCertificate();
        newCertTemp.getId().setByteArrayValue(keyId);
        newCertTemp.getLabel().setCharArrayValue(label);
        newCertTemp.getToken().setBooleanValue(true);
        newCertTemp.getCertificateType().setLongValue(
                CertificateType.X_509_PUBLIC_KEY);

        newCertTemp.getSubject().setByteArrayValue(
                cert.getSubjectX500Principal().getEncoded());
        newCertTemp.getIssuer().setByteArrayValue(
                cert.getIssuerX500Principal().getEncoded());
        newCertTemp.getSerialNumber().setByteArrayValue(
                cert.getSerialNumber().toByteArray());
        newCertTemp.getValue().setByteArrayValue(tmpEncodedCert);
        return newCertTemp;
    }

    private static void setKeyAttributes(
            final byte[] id,
            final String label,
            final long keyType,
            final PublicKey publicKey,
            final PrivateKey privateKey) {
        if (privateKey != null) {
            privateKey.getId().setByteArrayValue(id);
            privateKey.getToken().setBooleanValue(true);
            privateKey.getLabel().setCharArrayValue(label.toCharArray());
            privateKey.getKeyType().setLongValue(keyType);
            privateKey.getSign().setBooleanValue(true);
            privateKey.getPrivate().setBooleanValue(true);
            privateKey.getSensitive().setBooleanValue(true);
        }

        if (publicKey != null) {
            publicKey.getId().setByteArrayValue(id);
            publicKey.getToken().setBooleanValue(true);
            publicKey.getLabel().setCharArrayValue(label.toCharArray());
            publicKey.getKeyType().setLongValue(keyType);
            publicKey.getVerify().setBooleanValue(true);
            publicKey.getModifiable().setBooleanValue(Boolean.TRUE);
        }
    }

    private static ASN1ObjectIdentifier getCurveId(
            final String curveNameOrOid) {
        try {
            return new ASN1ObjectIdentifier(curveNameOrOid);
        } catch (Exception ex) { // CHECKSTYLE:SKIP
        }

        ASN1ObjectIdentifier curveId = X962NamedCurves.getOID(curveNameOrOid);

        if (curveId == null) {
            curveId = SECNamedCurves.getOID(curveNameOrOid);
        }

        if (curveId == null) {
            curveId = TeleTrusTNamedCurves.getOID(curveNameOrOid);
        }

        if (curveId == null) {
            curveId = NISTNamedCurves.getOID(curveNameOrOid);
        }

        return curveId;
    }

    @Override
    public void showDetails(
            final OutputStream stream,
            final boolean verbose)
    throws IOException, SecurityException, P11TokenException {
        ParamUtil.requireNonNull("stream", stream);
        List<PrivateKey> allPrivateObjects = getAllPrivateObjects(null, null);
        int size = allPrivateObjects.size();

        List<ComparableIaikPrivateKey> privateKeys = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            PrivateKey key = allPrivateObjects.get(i);
            byte[] id = key.getId().getByteArrayValue();
            if (id != null) {
                char[] label = key.getLabel().getCharArrayValue();
                ComparableIaikPrivateKey privKey = new ComparableIaikPrivateKey(id, label);
                privateKeys.add(privKey);
            }
        }

        Collections.sort(privateKeys);
        size = privateKeys.size();

        List<X509PublicKeyCertificate> allCertObjects = getAllCertificateObjects();

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < size; i++) {
            ComparableIaikPrivateKey privKey = privateKeys.get(i);
            byte[] keyId = privKey.getKeyId();
            char[] keyLabel = privKey.getKeyLabel();

            PublicKey pubKey = getPublicKeyObject(null, null, keyId, keyLabel);
            sb.append("\t")
                .append(i + 1)
                .append(". ")
                .append(privKey.getKeyLabelAsText())
                .append(" (").append("id: ")
                .append(Hex.toHexString(privKey.getKeyId()).toUpperCase())
                .append(")\n");

            sb.append("\t\tAlgorithm: ")
                .append(getKeyAlgorithm(pubKey))
                .append("\n");

            X509PublicKeyCertificate cert = removeCertificateObject(allCertObjects, keyId,
                    keyLabel);
            if (cert == null) {
                sb.append("\t\tCertificate: NONE\n");
            } else {
                formatString(verbose, sb, cert);
            }
        }

        for (int i = 0; i < allCertObjects.size(); i++) {
            X509PublicKeyCertificate certObj = allCertObjects.get(i);
            sb.append("\tCert-")
                .append(i + 1)
                .append(". ")
                .append(certObj.getLabel().getCharArrayValue())
                .append(" (").append("id: ")
                .append(Hex.toHexString(certObj.getId().getByteArrayValue()).toUpperCase())
                .append(")\n");

            formatString(verbose, sb, certObj);
        }

        if (sb.length() > 0) {
            stream.write(sb.toString().getBytes());
        }
    }

    private static String getKeyAlgorithm(
            final PublicKey key) {
        if (key instanceof RSAPublicKey) {
            return "RSA";
        } else if (key instanceof ECDSAPublicKey) {
            byte[] paramBytes = ((ECDSAPublicKey) key).getEcdsaParams().getByteArrayValue();
            if (paramBytes.length < 50) {
                try {
                    ASN1ObjectIdentifier curveId =
                            (ASN1ObjectIdentifier) ASN1ObjectIdentifier.fromByteArray(paramBytes);
                    String curveName = KeyUtil.getCurveName(curveId);
                    return "EC (named curve " + curveName + ")";
                } catch (Exception ex) {
                    return "EC";
                }
            } else {
                return "EC (specified curve)";
            }
        } else if (key instanceof DSAPublicKey) {
            return "DSA";
        } else {
            return "UNKNOWN";
        }
    }

    private static X509PublicKeyCertificate removeCertificateObject(
            final List<X509PublicKeyCertificate> certificateObjects,
            final byte[] keyId,
            final char[] keyLabel) {
        X509PublicKeyCertificate cert = null;
        for (X509PublicKeyCertificate certObj : certificateObjects) {
            if (keyId != null
                    && !Arrays.equals(keyId, certObj.getId().getByteArrayValue())) {
                continue;
            }

            if (keyLabel != null
                    && !Arrays.equals(keyLabel, certObj.getLabel().getCharArrayValue())) {
                continue;
            }

            cert = certObj;
            break;
        }

        if (cert != null) {
            certificateObjects.remove(cert);
        }

        return cert;
    }

    private void formatString(
            final boolean verbose,
            final StringBuilder sb,
            final X509PublicKeyCertificate cert) {
        byte[] bytes = cert.getSubject().getByteArrayValue();
        String subject;
        try {
            X500Principal x500Prin = new X500Principal(bytes);
            subject = X509Util.getRfc4519Name(x500Prin);
        } catch (Exception ex) {
            subject = new String(bytes);
        }

        if (!verbose) {
            sb.append("\t\tCertificate: ").append(subject).append("\n");
            return;
        }

        sb.append("\t\tCertificate:\n");
        sb.append("\t\t\tSubject: ")
            .append(subject)
            .append("\n");

        bytes = cert.getIssuer().getByteArrayValue();
        String issuer;
        try {
            X500Principal x500Prin = new X500Principal(bytes);
            issuer = X509Util.getRfc4519Name(x500Prin);
        } catch (Exception ex) {
            issuer = new String(bytes);
        }
        sb.append("\t\t\tIssuer: ")
            .append(issuer)
            .append("\n");

        byte[] certBytes = cert.getValue().getByteArrayValue();

        X509Certificate x509Cert = null;
        try {
            x509Cert = X509Util.parseCert(certBytes);
        } catch (Exception ex) {
            sb.append("\t\t\tError: " + ex.getMessage());
            return;
        }

        sb.append("\t\t\tSerial: ")
            .append(x509Cert.getSerialNumber())
            .append("\n");
        sb.append("\t\t\tStart time: ")
            .append(x509Cert.getNotBefore())
            .append("\n");
        sb.append("\t\t\tEnd time: ")
            .append(x509Cert.getNotAfter())
            .append("\n");
        sb.append("\t\t\tSHA1 Sum: ")
            .append(HashCalculator.hexSha1(certBytes))
            .append("\n");
    }

}
