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

package org.xipki.commons.security.impl.p11.iaik;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

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
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.password.api.PasswordResolverException;
import org.xipki.commons.security.api.HashCalculator;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.SignerException;
import org.xipki.commons.security.api.p11.P11Identity;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11WritableSlot;
import org.xipki.commons.security.api.util.KeyUtil;
import org.xipki.commons.security.api.util.X509Util;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.SessionInfo;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.State;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.ByteArrayAttribute;
import iaik.pkcs.pkcs11.objects.Certificate.CertificateType;
import iaik.pkcs.pkcs11.objects.CharArrayAttribute;
import iaik.pkcs.pkcs11.objects.DSAPrivateKey;
import iaik.pkcs.pkcs11.objects.DSAPublicKey;
import iaik.pkcs.pkcs11.objects.ECDSAPrivateKey;
import iaik.pkcs.pkcs11.objects.ECDSAPublicKey;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class IaikP11Slot implements P11WritableSlot {

    public static final long YEAR = 365L * 24 * 60 * 60 * 1000; // milliseconds of one year

    private static final long DEFAULT_MAX_COUNT_SESSION = 20;

    private static final Logger LOG = LoggerFactory.getLogger(IaikP11Slot.class);

    private final String moduleName;
    private Slot slot;

    private int maxSessionCount;

    private List<char[]> password;

    private long timeOutWaitNewSession = 10000; // maximal wait for 10 second

    private AtomicLong countSessions = new AtomicLong(0);

    private BlockingQueue<Session> idleSessions = new LinkedBlockingDeque<>();

    private ConcurrentHashMap<String, PrivateKey> signingKeysById = new ConcurrentHashMap<>();

    private ConcurrentHashMap<String, PrivateKey> signingKeysByLabel = new ConcurrentHashMap<>();

    private final List<IaikP11Identity> identities = new LinkedList<>();

    private boolean writableSessionInUse;

    private Session writableSession;

    private final P11SlotIdentifier slotId;

    IaikP11Slot(
            final String moduleName,
            final P11SlotIdentifier slotId,
            final Slot slot,
            final List<char[]> password)
    throws SignerException {
        ParamUtil.assertNotBlank("moduleName", moduleName);
        ParamUtil.assertNotNull("slotId", slotId);
        ParamUtil.assertNotNull("slot", slot);

        this.moduleName = moduleName;
        this.slotId = slotId;
        this.slot = slot;
        this.password = password;

        Session session;
        try {
            session = openSession();
        } catch (TokenException ex) {
            final String message = "openSession";
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
            close();
            throw new SignerException(ex.getMessage(), ex);
        }

        try {
            firstLogin(session, password);
        } catch (TokenException ex) {
            final String message = "firstLogin";
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
            close();
            throw new SignerException(ex.getMessage(), ex);
        }

        long maxSessionCount2 = 1;
        try {
            maxSessionCount2 = this.slot.getToken().getTokenInfo().getMaxSessionCount();
        } catch (TokenException ex) {
            final String message = "getToken";
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
        }

        if (maxSessionCount2 == 0) {
            maxSessionCount2 = DEFAULT_MAX_COUNT_SESSION;
        } else {
            // 2 sessions as buffer, they may be used elsewhere.
            maxSessionCount2 = (maxSessionCount2 < 3)
                    ? 1
                    : maxSessionCount2 - 2;
        }

        this.maxSessionCount = (int) maxSessionCount2;

        LOG.info("maxSessionCount: {}", this.maxSessionCount);

        returnIdleSession(session);

        refresh();
    } // constructor

    public void refresh()
    throws SignerException {
        Set<IaikP11Identity> currentIdentifies = new HashSet<>();

        List<PrivateKey> signatureKeys = getAllPrivateObjects(Boolean.TRUE, null);
        for (PrivateKey signatureKey : signatureKeys) {
            byte[] keyId = signatureKey.getId().getByteArrayValue();
            if (keyId == null || keyId.length == 0) {
                continue;
            }

            try {
                X509PublicKeyCertificate certificateObject = getCertificateObject(keyId, null);

                X509Certificate signatureCert = null;
                java.security.PublicKey signaturePublicKey = null;

                if (certificateObject != null) {
                    byte[] encoded = certificateObject.getValue().getByteArrayValue();
                    try {
                        signatureCert = (X509Certificate) X509Util.parseCert(
                                    new ByteArrayInputStream(encoded));
                    } catch (Exception ex) {
                        String keyIdStr = hex(keyId);
                        final String message = "could not parse certificate with id " + keyIdStr;
                        if (LOG.isWarnEnabled()) {
                            LOG.warn(LogUtil.buildExceptionLogFormat(message),
                                    ex.getClass().getName(), ex.getMessage());
                        }
                        LOG.debug(message, ex);
                        continue;
                    }
                    signaturePublicKey = signatureCert.getPublicKey();
                } else {
                    signatureCert = null;
                    PublicKey publicKeyObject = getPublicKeyObject(
                            Boolean.TRUE, null, keyId, null);
                    if (publicKeyObject == null) {
                        String msg =
                                "neither certificate nor public key for signing is available";
                        LOG.info(msg);
                        continue;
                    }

                    signaturePublicKey = generatePublicKey(publicKeyObject);
                }

                Map<String, Set<X509Certificate>> allCerts = new HashMap<>();
                List<X509Certificate> certChain = new LinkedList<>();

                if (signatureCert != null) {
                    certChain.add(signatureCert);
                    while (true) {
                        X509Certificate context = certChain.get(certChain.size() - 1);
                        if (X509Util.isSelfSigned(context)) {
                            break;
                        }

                        String issuerSubject = signatureCert.getIssuerX500Principal().getName();
                        Set<X509Certificate> issuerCerts = allCerts.get(issuerSubject);
                        if (issuerCerts == null) {
                            issuerCerts = new HashSet<>();
                            X509PublicKeyCertificate[] certObjects = getCertificateObjects(
                                    signatureCert.getIssuerX500Principal());
                            if (certObjects != null && certObjects.length > 0) {
                                for (X509PublicKeyCertificate certObject : certObjects) {
                                    issuerCerts.add(X509Util.parseCert(
                                            certObject.getValue().getByteArrayValue()));
                                }
                            }

                            if (CollectionUtil.isNotEmpty(issuerCerts)) {
                                allCerts.put(issuerSubject, issuerCerts);
                            }
                        }

                        if (CollectionUtil.isEmpty(issuerCerts)) {
                            break;
                        }

                        // find the certificate
                        for (X509Certificate issuerCert : issuerCerts) {
                            try {
                                context.verify(issuerCert.getPublicKey());
                                certChain.add(issuerCert);
                            } catch (Exception ex) {
                            }
                        }
                    } // end while (true)
                } // end if (signatureCert != null)

                P11KeyIdentifier tKeyId = new P11KeyIdentifier(
                        signatureKey.getId().getByteArrayValue(),
                        new String(signatureKey.getLabel().getCharArrayValue()));

                IaikP11Identity identity = new IaikP11Identity(slotId, tKeyId,
                        certChain.toArray(new X509Certificate[0]), signaturePublicKey);
                currentIdentifies.add(identity);
            } catch (SignerException ex) {
                String keyIdStr = hex(keyId);
                final String message = "SignerException while initializing key with key-id "
                        + keyIdStr;
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                            ex.getMessage());
                }
                LOG.debug(message, ex);
                continue;
            } catch (Throwable th) {
                String keyIdStr = hex(keyId);
                final String message =
                        "unexpected exception while initializing key with key-id " + keyIdStr;
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), th.getClass().getName(),
                            th.getMessage());
                }
                LOG.debug(message, th);
                continue;
            }
        } // end for (PrivateKey signatureKey : signatureKeys)

        this.identities.clear();
        this.identities.addAll(currentIdentifies);
        currentIdentifies.clear();
    } // method refresh

    // CHECKSTYLE:OFF
    public byte[] CKM_ECDSA(
            final byte[] hash,
            final P11KeyIdentifier keyId)
    throws SignerException {
        // CHECKSTYLE:ON
        return CKM_SIGN(PKCS11Constants.CKM_ECDSA, hash, keyId);
    }

    // CHECKSTYLE:OFF
    public byte[] CKM_DSA(
            final byte[] hash,
            final P11KeyIdentifier keyId)
    throws SignerException {
        // CHECKSTYLE:ON
        return CKM_SIGN(PKCS11Constants.CKM_DSA, hash, keyId);
    }

    // CHECKSTYLE:OFF
    public byte[] CKM_RSA_PKCS(
            final byte[] encodedDigestInfo,
            final P11KeyIdentifier keyId)
    throws SignerException {
        // CHECKSTYLE:ON
        return CKM_SIGN(PKCS11Constants.CKM_RSA_PKCS, encodedDigestInfo, keyId);
    }

    // CHECKSTYLE:OFF
    public byte[] CKM_RSA_X509(
            final byte[] hash,
            final P11KeyIdentifier keyId)
    throws SignerException {
        // CHECKSTYLE:ON
        return CKM_SIGN(PKCS11Constants.CKM_RSA_X_509, hash, keyId);
    }

    // CHECKSTYLE:OFF
    private byte[] CKM_SIGN(
            final long mech,
            final byte[] hash,
            final P11KeyIdentifier keyId)
    throws SignerException {
        // CHECKSTYLE:ON
        PrivateKey signingKey;
        synchronized (keyId) {
            if (keyId.getKeyId() != null) {
                signingKey = signingKeysById.get(keyId.getKeyIdHex());
            } else {
                signingKey = signingKeysByLabel.get(keyId.getKeyLabel());
            }

            if (signingKey == null) {
                LOG.info("try to retieve private key " + keyId);
                signingKey = getPrivateObject(Boolean.TRUE, null, keyId);

                if (signingKey != null) {
                    LOG.info("found private key " + keyId);
                    cacheSigningKey(signingKey);
                } else {
                    LOG.warn("could not find private key " + keyId);
                }
                throw new SignerException("no key for signing is available");
            }
        }

        Session session = borrowIdleSession();
        if (session == null) {
            throw new SignerException("no idle session available");
        }

        try {
            Mechanism algorithmId = Mechanism.get(mech);

            if (LOG.isTraceEnabled()) {
                LOG.debug("sign with private key:\n{}", signingKey);
            }

            synchronized (session) {
                login(session);
                session.signInit(algorithmId, signingKey);
                byte[] signature = session.sign(hash);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("signature:\n{}", Hex.toHexString(signature));
                }
                return signature;
            }
        } catch (TokenException ex) {
            throw new SignerException(ex.getMessage(), ex);
        } finally {
            returnIdleSession(session);
        }
    } // method CKM_SIGN

    private Session openSession()
    throws TokenException {
        return openSession(false);
    }

    private Session openSession(
            final boolean rwSession)
    throws TokenException {
        Session session = slot.getToken().openSession(
                Token.SessionType.SERIAL_SESSION, rwSession, null, null);
        countSessions.incrementAndGet();
        return session;
    }

    private void closeSession(
            final Session session)
    throws TokenException {
        try {
            session.closeSession();
        } finally {
            countSessions.decrementAndGet();
        }
    }

    private synchronized Session borrowWritableSession()
    throws SignerException {
        if (writableSession == null) {
            try {
                writableSession = openSession(true);
            } catch (TokenException ex) {
                throw new SignerException("could not open writable session", ex);
            }
        }

        if (writableSessionInUse) {
            throw new SignerException("no idle writable session available");
        }

        writableSessionInUse = true;
        return writableSession;
    }

    private synchronized void returnWritableSession(
            final Session session)
    throws SignerException {
        if (session != writableSession) {
            throw new SignerException("the returned session does not belong to me");
        }
        this.writableSessionInUse = false;
    }

    public Session borrowIdleSession()
    throws SignerException {
        if (countSessions.get() < maxSessionCount) {
            Session session = idleSessions.poll();
            if (session == null) {
                // create new session
                try {
                    session = openSession();
                } catch (TokenException ex) {
                    LOG.error("openSession(), TokenException: {}", ex.getMessage());
                    LOG.debug("openSession()", ex);
                }
            }

            if (session != null) {
                return session;
            }
        }

        try {
            return idleSessions.poll(timeOutWaitNewSession, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ex) {
        }

        throw new SignerException("no idle session");
    }

    public void returnIdleSession(
            final Session session) {
        if (session == null) {
            return;
        }

        for (int i = 0; i < 3; i++) {
            try {
                idleSessions.put(session);
                return;
            } catch (InterruptedException ex) {
            }
        }

        try {
            closeSession(session);
        } catch (TokenException ex) {
            LOG.error("closeSession.{}: {}", ex.getClass().getName(), ex.getMessage());
            LOG.debug("closeSession", ex);
        }
    }

    private void firstLogin(
            final Session session,
            final List<char[]> pPassword)
    throws TokenException {
        boolean isProtectedAuthenticationPath =
                session.getToken().getTokenInfo().isProtectedAuthenticationPath();

        try {
            if (isProtectedAuthenticationPath || CollectionUtil.isEmpty(pPassword)) {
                LOG.info("verify on PKCS11Module with PROTECTED_AUTHENTICATION_PATH");
                // some driver does not accept null PIN
                session.login(Session.UserType.USER, "".toCharArray());
                this.password = null;
            } else {
                LOG.info("verify on PKCS11Module with PIN");

                for (char[] singlePwd : pPassword) {
                    session.login(Session.UserType.USER, singlePwd);
                }
                this.password = pPassword;
            }
        } catch (PKCS11Exception p11e) {
            // 0x100: user already logged in
            if (p11e.getErrorCode() != 0x100) {
                throw p11e;
            }
        }
    }

    public void login()
    throws SignerException {
        Session session = borrowIdleSession();
        try {
            login(session);
        } finally {
            returnIdleSession(session);
        }
    }

    private void login(
            final Session session)
    throws SignerException {
        try {
            boolean isSessionLoggedIn = checkSessionLoggedIn(session);
            if (isSessionLoggedIn) {
                return;
            }
            boolean loginRequired = session.getToken().getTokenInfo().isLoginRequired();

            LOG.debug("loginRequired: {}", loginRequired);
            if (!loginRequired) {
                return;
            }

            if (CollectionUtil.isEmpty(password)) {
                session.login(Session.UserType.USER, null);
            } else {
                for (char[] singlePwd : password) {
                    session.login(Session.UserType.USER, singlePwd);
                }
            }
        } catch (TokenException ex) {
            throw new SignerException(ex.getMessage(), ex);
        }
    }

    public void close() {
        if (slot != null) {
            try {
                LOG.info("close all sessions on token: {}", slot.getSlotID());
                slot.getToken().closeAllSessions();
            } catch (Throwable th) {
                final String message = "error while slot.getToken().closeAllSessions()";
                if (LOG.isWarnEnabled()) {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), th.getClass().getName(),
                            th.getMessage());
                }
                LOG.debug(message, th);
            }

            slot = null;
        }

        // clear the session pool
        idleSessions.clear();
        countSessions.lazySet(0);
    }

    public List<PrivateKey> getAllPrivateObjects(
            final Boolean forSigning,
            final Boolean forDecrypting)
    throws SignerException {
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

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            if (CollectionUtil.isEmpty(tmpObjects)) {
                return Collections.emptyList();
            }

            int n = tmpObjects.size();
            LOG.info("found {} private keys", n);

            List<PrivateKey> privateKeys = new ArrayList<>(n);
            for (iaik.pkcs.pkcs11.objects.Object tmpObject : tmpObjects) {
                PrivateKey privateKey = (PrivateKey) tmpObject;
                privateKeys.add(privateKey);
                cacheSigningKey(privateKey);
            }

            return privateKeys;
        } finally {
            returnIdleSession(session);
        }
    }

    public List<X509PublicKeyCertificate> getAllCertificateObjects()
    throws SignerException {
        Session session = borrowIdleSession();
        try {
            if (LOG.isTraceEnabled()) {
                String info = listCertificateObjects(session);
                LOG.debug(info);
            }
            X509PublicKeyCertificate template = new X509PublicKeyCertificate();
            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            int n = tmpObjects.size();
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

    private void cacheSigningKey(
            final PrivateKey privateKey) {
        Boolean b = privateKey.getSign().getBooleanValue();
        byte[] id = privateKey.getId().getByteArrayValue();
        char[] localLabel = privateKey.getLabel().getCharArrayValue();
        String label = (localLabel == null)
                ? null
                : new String(localLabel);

        if (b == null || !b.booleanValue()) {
            LOG.warn("key {} is not for signing", new P11KeyIdentifier(id, label));
            return;
        }

        if (b != null && b.booleanValue()) {
            if (id != null) {
                signingKeysById.put(Hex.toHexString(id).toUpperCase(), privateKey);
            }
            if (label != null) {
                signingKeysByLabel.put(label, privateKey);
            }
        }
    }

    private PrivateKey getPrivateObject(
            final Boolean forSigning,
            final Boolean forDecrypting,
            final P11KeyIdentifier keyIdentifier)
    throws SignerException {
        String localKeyLabel = keyIdentifier.getKeyLabel();
        char[] keyLabel = (localKeyLabel == null)
                ? null
                : localKeyLabel.toCharArray();
        byte[] keyId = keyIdentifier.getKeyId();

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
            if (keyId != null) {
                template.getId().setByteArrayValue(keyId);
            }
            if (keyLabel != null) {
                template.getLabel().setCharArrayValue(keyLabel);
            }

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            if (CollectionUtil.isEmpty(tmpObjects)) {
                return null;
            }

            int size = tmpObjects.size();
            if (size > 1) {
                LOG.warn("found {} private key identified by {}, use the first one",
                        size, getDescription(keyId, keyLabel));
            }
            return (PrivateKey) tmpObjects.get(0);
        } finally {
            returnIdleSession(session);
        }
    } // method getPrivateObject

    private String listPrivateKeyObjects(
            final Session session,
            final Boolean forSigning,
            final Boolean forDecrypting) {
        try {
            StringBuilder msg = new StringBuilder();
            msg.append("available private keys: ");
            msg.append("forSigning: ").append(forSigning);
            msg.append(", forDecrypting: ").append(forDecrypting).append("\n");

            PrivateKey template = new PrivateKey();
            if (forSigning != null) {
                template.getSign().setBooleanValue(forSigning);
            }
            if (forDecrypting != null) {
                template.getDecrypt().setBooleanValue(forDecrypting);
            }
            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            if (CollectionUtil.isEmpty(tmpObjects)) {
                msg.append(" empty");
            }
            for (int i = 0; i < tmpObjects.size(); i++) {
                PrivateKey privKey = (PrivateKey) tmpObjects.get(i);
                msg.append("------------------------PrivateKey ");
                msg.append(i + 1);
                msg.append("-------------------------\n");

                msg.append("\tid(hex): ");
                ByteArrayAttribute id = privKey.getId();

                byte[] bytes = null;
                if (id != null) {
                    bytes = id.getByteArrayValue();
                }
                if (bytes == null) {
                    msg.append("null");
                } else {
                    msg.append(Hex.toHexString(bytes));
                }
                msg.append("\n");

                msg.append("\tlabel: ");
                CharArrayAttribute label = privKey.getLabel();
                char[] chars = null;
                if (label != null) {
                    chars = label.getCharArrayValue();
                }
                msg.append(chars).append("\n");
            }
            return msg.toString();
        } catch (Throwable th) {
            return "Exception while calling listPrivateKeyObjects(): " + th.getMessage();
        }
    } // method listPrivateKeyObjects

    public PublicKey getPublicKeyObject(
            final Boolean forSignature,
            final Boolean forCipher,
            final byte[] keyId,
            final char[] keyLabel)
    throws SignerException {
        Session session = borrowIdleSession();

        try {
            if (LOG.isTraceEnabled()) {
                String info = listPublicKeyObjects(session, forSignature, forCipher);
                LOG.debug(info);
            }

            iaik.pkcs.pkcs11.objects.PublicKey template =
                    new iaik.pkcs.pkcs11.objects.PublicKey();
            if (keyId != null) {
                template.getId().setByteArrayValue(keyId);
            }
            if (keyLabel != null) {
                template.getLabel().setCharArrayValue(keyLabel);
            }

            if (forSignature != null) {
                template.getVerify().setBooleanValue(forSignature);
            }
            if (forCipher != null) {
                template.getEncrypt().setBooleanValue(forCipher);
            }

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            if (CollectionUtil.isEmpty(tmpObjects)) {
                return null;
            }

            int size = tmpObjects.size();
            if (size > 1) {
                LOG.warn("found {} public key identified by {}, use the first one",
                        size, getDescription(keyId, keyLabel));
            }

            iaik.pkcs.pkcs11.objects.PublicKey p11Key =
                    (iaik.pkcs.pkcs11.objects.PublicKey) tmpObjects.get(0);
            return p11Key;
        } finally {
            returnIdleSession(session);
        }
    } // method getPublicKeyObject

    private X509PublicKeyCertificate[] getCertificateObjects(
            final X500Principal subject)
    throws SignerException {
        Session session = borrowIdleSession();

        try {
            if (LOG.isTraceEnabled()) {
                String info = listCertificateObjects(session);
                LOG.debug(info);
            }

            X509PublicKeyCertificate template = new X509PublicKeyCertificate();
            template.getCertificateType().setLongValue(CertificateType.X_509_PUBLIC_KEY);
            template.getSubject().setByteArrayValue(subject.getEncoded());

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            int n = (tmpObjects == null)
                    ? 0
                    : tmpObjects.size();

            if (n == 0) {
                LOG.warn("found no certificate with subject {}",
                        X509Util.getRfc4519Name(subject));
                return null;
            }

            X509PublicKeyCertificate[] certs = new X509PublicKeyCertificate[n];
            for (int i = 0; i < n; i++) {
                certs[i] = (X509PublicKeyCertificate) tmpObjects.get(i);
            }
            return certs;
        } finally {
            returnIdleSession(session);
        }
    } // method getCertificateObjects

    private X509PublicKeyCertificate getCertificateObject(
            final byte[] keyId,
            final char[] keyLabel)
    throws SignerException {
        X509PublicKeyCertificate[] certs = getCertificateObjects(keyId, keyLabel);
        if (certs == null) {
            return null;
        }
        if (certs.length > 1) {
            LOG.warn("found {} public key identified by {}, use the first one",
                    certs.length, getDescription(keyId, keyLabel));
        }
        return certs[0];
    }

    private X509PublicKeyCertificate[] getCertificateObjects(
            final byte[] keyId,
            final char[] keyLabel)
    throws SignerException {
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

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            if (CollectionUtil.isEmpty(tmpObjects)) {
                LOG.info("found no certificate identified by {}",
                        getDescription(keyId, keyLabel));
                return null;
            }

            int size = tmpObjects.size();
            X509PublicKeyCertificate[] certs = new X509PublicKeyCertificate[size];
            for (int i = 0; i < size; i++) {
                certs[i] = (X509PublicKeyCertificate) tmpObjects.get(i);
            }
            return certs;
        } finally {
            returnIdleSession(session);
        }
    } // method getCertificateObjects

    private boolean existsCertificateObjects(
            final byte[] keyId,
            final char[] keyLabel)
    throws SignerException {
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

    private String listCertificateObjects(
            final Session session) {
        try {
            StringBuilder msg = new StringBuilder();
            msg.append("available certificates: ");

            X509PublicKeyCertificate template = new X509PublicKeyCertificate();

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            if (CollectionUtil.isEmpty(tmpObjects)) {
                msg.append(" empty");
            }
            for (int i = 0; i < tmpObjects.size(); i++) {
                X509PublicKeyCertificate cert = (X509PublicKeyCertificate) tmpObjects.get(i);
                msg.append("------------------------Certificate ")
                    .append(i + 1)
                    .append("-------------------------\n");

                msg.append("\tid(hex): ");
                ByteArrayAttribute id = cert.getId();
                byte[] bytes = null;
                if (id != null) {
                    bytes = id.getByteArrayValue();
                }

                if (bytes == null) {
                    msg.append("null");
                } else {
                    msg.append(Hex.toHexString(bytes));
                }
                msg.append("\n");

                msg.append("\tlabel: ");
                CharArrayAttribute label = cert.getLabel();
                char[] chars = null;
                if (label != null) {
                    chars = label.getCharArrayValue();
                }
                msg.append(chars).append("\n");
            }
            return msg.toString();
        } catch (Throwable th) {
            return "Exception while calling listCertificateObjects(): " + th.getMessage();
        }
    } // method listCertificateObjects

    @Override
    public void updateCertificate(
            final P11KeyIdentifier keyIdentifier,
            final X509Certificate newCert,
            final Set<X509Certificate> caCerts,
            final SecurityFactory securityFactory)
    throws Exception {
        ParamUtil.assertNotNull("keyIdentifier", keyIdentifier);
        ParamUtil.assertNotNull("newCert", newCert);

        PrivateKey privKey = getPrivateObject(null, null, keyIdentifier);

        if (privKey == null) {
            throw new SignerException("could not find private key " + keyIdentifier);
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
                Thread.sleep(1000);
            }

            // create new signer certificate object
            session.createObject(newCertTemp);

            // create CA certificate objects
            if (certChain.length > 1) {
                for (int i = 1; i < certChain.length; i++) {
                    X509Certificate caCert = certChain[i];
                    byte[] encodedCaCert = caCert.getEncoded();

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
                    String caCN = X509Util.getCommonName(caX500Name);

                    String label = null;
                    for (int j = 0;; j++) {
                        label = (j == 0)
                                ? caCN
                                : caCN + "-" + j;
                        if (!existsCertificateObjects(null, label.toCharArray())) {
                            break;
                        }
                    }

                    X509PublicKeyCertificate newCaCertTemp = createPkcs11Template(
                            caCert, encodedCaCert, caCertKeyId, label.toCharArray());
                    session.createObject(newCaCertTemp);
                }
            } // end if(certChain.length)
        } finally {
            returnWritableSession(session);
        }
    } // method updateCertificate

    @Override
    public boolean removeKey(
            final P11KeyIdentifier keyIdentifier)
    throws Exception {
        return doRemoveKeyAndCerts(keyIdentifier, false);
    }

    @Override
    public boolean removeKeyAndCerts(
            final P11KeyIdentifier keyIdentifier)
    throws Exception {
        return doRemoveKeyAndCerts(keyIdentifier, true);
    }

    private boolean doRemoveKeyAndCerts(
            final P11KeyIdentifier keyIdentifier, boolean removeCerts)
    throws Exception {
        ParamUtil.assertNotNull("keyIdentifier", keyIdentifier);

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

        int n = msgBuilder.length();
        if (n > 2) {
            throw new SignerException(msgBuilder.substring(0, n - 2));
        }

        return true;
    } // method doRemoveKeyAndCerts

    @Override
    public void removeCerts(
            final P11KeyIdentifier keyIdentifier)
    throws Exception {
        ParamUtil.assertNotNull("keyIdentifier", keyIdentifier);

        String keyLabel = keyIdentifier.getKeyLabel();
        char[] keyLabelChars = (keyLabel == null)
                ? null
                : keyLabel.toCharArray();

        X509PublicKeyCertificate[] existingCerts = getCertificateObjects(
                keyIdentifier.getKeyId(), keyLabelChars);

        if (existingCerts == null || existingCerts.length == 0) {
            throw new SignerException("could not find certificates with id " + keyIdentifier);
        }

        Session session = borrowWritableSession();
        try {
            for (X509PublicKeyCertificate cert : existingCerts) {
                session.destroyObject(cert);
            }
        } finally {
            returnWritableSession(session);
        }
    }

    private String listPublicKeyObjects(
            final Session session,
            final Boolean forSignature,
            final Boolean forCipher) {
        try {
            StringBuilder msg = new StringBuilder();
            msg.append("available public keys: ");
            msg.append("forSignature: ").append(forSignature);
            msg.append(", forCipher: ").append(forCipher).append("\n");

            iaik.pkcs.pkcs11.objects.PublicKey template =
                    new iaik.pkcs.pkcs11.objects.PublicKey();
            if (forSignature != null) {
                template.getVerify().setBooleanValue(forSignature);
            }
            if (forCipher != null) {
                template.getEncrypt().setBooleanValue(forCipher);
            }

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            if (CollectionUtil.isEmpty(tmpObjects)) {
                msg.append(" empty");
            }
            for (int i = 0; i < tmpObjects.size(); i++) {
                iaik.pkcs.pkcs11.objects.PublicKey pubKey =
                        (iaik.pkcs.pkcs11.objects.PublicKey) tmpObjects.get(i);
                msg.append("------------------------Public Key ")
                    .append(i + 1)
                    .append("-------------------------\n");
                msg.append("\tid(hex): ");
                ByteArrayAttribute id = pubKey.getId();
                byte[] bytes = null;
                if (id != null) {
                    bytes = id.getByteArrayValue();
                }

                if (bytes == null) {
                    msg.append("null");
                } else {
                    msg.append(Hex.toHexString(bytes));
                }
                msg.append("\n");

                msg.append("\tlabel: ");
                CharArrayAttribute label = pubKey.getLabel();
                char[] chars = null;
                if (label != null) {
                    chars = label.getCharArrayValue();
                }
                msg.append(chars).append("\n");
            } // end for
            return msg.toString();
        } catch (Throwable th) {
            return "Exception while calling listPublicKeyObjects(): " + th.getMessage();
        }
    } // method listPublicKeyObjects

    private void assertMatch(
            final X509Certificate cert,
            final P11KeyIdentifier keyId,
            final SecurityFactory securityFactory)
    throws SignerException, PasswordResolverException {
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
    throws Exception {
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
                        throw new SignerException(
                                "given certificate already exists under " + p11KeyId);
                    }
                }
            }

            byte[] keyId = IaikP11Util.generateKeyId(session);

            X500Name x500Name = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
            String cN = X509Util.getCommonName(x500Name);

            String label = null;
            for (int j = 0;; j++) {
                label = (j == 0)
                        ? cN
                        : cN + "-" + j;
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
        } finally {
            returnWritableSession(session);
        }
    } // method addCert

    @Override
    public P11KeyIdentifier generateRSAKeypair(
            final int keySize,
            final BigInteger publicExponent,
            final String label)
    throws Exception {
        ParamUtil.assertNotBlank("label", label);

        if (keySize < 1024) {
            throw new IllegalArgumentException("keysize not allowed: " + keySize);
        }

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
            final int pLength,
            final int qLength,
            final String label)
    throws Exception {
        ParamUtil.assertNotBlank("label", label);

        if (pLength < 1024) {
            throw new IllegalArgumentException("keysize not allowed: " + pLength);
        }

        if (pLength % 1024 != 0) {
            throw new IllegalArgumentException("key size is not multiple of 1024: " + pLength);
        }

        Session session = borrowWritableSession();
        try {
            if (IaikP11Util.labelExists(session, label)) {
                throw new IllegalArgumentException(
                        "label " + label + " exists, please specify another one");
            }

            byte[] id = IaikP11Util.generateKeyId(session);
            generateDSAKeyPair(session, pLength, qLength, id, label);
            return new P11KeyIdentifier(id, label);
        } finally {
            returnWritableSession(session);
        }
    }

    @Override
    public P11KeyIdentifier generateECKeypair(
            final String curveNameOrOid,
            final String label)
    throws Exception {
        ParamUtil.assertNotBlank("curveNameOrOid", curveNameOrOid);
        ParamUtil.assertNotBlank("label", label);

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

    private void generateDSAKeyPair(
            final Session session,
            final int pLength,
            final int qLength,
            final byte[] id,
            final String label)
    throws Exception {
        DSAParametersGenerator paramGen = new DSAParametersGenerator(new SHA512Digest());
        DSAParameterGenerationParameters genParams = new DSAParameterGenerationParameters(
                pLength, qLength, 80, new SecureRandom());
        paramGen.init(genParams);
        DSAParameters dsaParams = paramGen.generateParameters();

        DSAPrivateKey privateKey = new DSAPrivateKey();
        DSAPublicKey publicKey = new DSAPublicKey();

        setKeyAttributes(id, label, PKCS11Constants.CKK_DSA, privateKey, publicKey);

        publicKey.getPrime().setByteArrayValue(dsaParams.getP().toByteArray());
        publicKey.getSubprime().setByteArrayValue(dsaParams.getQ().toByteArray());
        publicKey.getBase().setByteArrayValue(dsaParams.getG().toByteArray());

        session.generateKeyPair(
                Mechanism.get(PKCS11Constants.CKM_DSA_KEY_PAIR_GEN), publicKey, privateKey);
    } // method generateDSAKeyPair

    private void generateRSAKeyPair(
            final Session session,
            final int keySize,
            final BigInteger publicExponent,
            final byte[] id,
            final String label)
    throws Exception {

        BigInteger localPublicExponent = publicExponent;
        if (localPublicExponent == null) {
            localPublicExponent = BigInteger.valueOf(65537);
        }

        RSAPrivateKey privateKey = new RSAPrivateKey();
        RSAPublicKey publicKey = new RSAPublicKey();

        setKeyAttributes(id, label, PKCS11Constants.CKK_RSA, privateKey, publicKey);

        publicKey.getModulusBits().setLongValue((long) keySize);
        publicKey.getPublicExponent().setByteArrayValue(localPublicExponent.toByteArray());

        session.generateKeyPair(
                Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN), publicKey, privateKey);
    } // method generateRSAKeyPair

    private void generateECKeyPair(
            final Session session,
            final ASN1ObjectIdentifier curveId,
            final X9ECParameters ecParams,
            final byte[] id,
            final String label)
    throws Exception {
        try {
            generateNamedECKeyPair(session, curveId, id, label);
        } catch (TokenException ex) {
            generateSpecifiedECDSAKeyPair(session, curveId, ecParams, id, label);
        }
    }

    private void generateNamedECKeyPair(
            final Session session,
            final ASN1ObjectIdentifier curveId,
            final byte[] id,
            final String label)
    throws TokenException, IOException {
        ECDSAPrivateKey privateKeyTemplate = new ECDSAPrivateKey();
        ECDSAPublicKey publicKeyTemplate = new ECDSAPublicKey();
        setKeyAttributes(id, label, PKCS11Constants.CKK_ECDSA,
                privateKeyTemplate, publicKeyTemplate);

        byte[] ecdsaParamsBytes = curveId.getEncoded();
        publicKeyTemplate.getEcdsaParams().setByteArrayValue(ecdsaParamsBytes);

        session.generateKeyPair(Mechanism.get(PKCS11Constants.CKM_EC_KEY_PAIR_GEN),
                publicKeyTemplate, privateKeyTemplate);
    }

    private KeyPair generateSpecifiedECDSAKeyPair(
            final Session session,
            final ASN1ObjectIdentifier curveId,
            final X9ECParameters ecParams,
            final byte[] id,
            String label)
    throws TokenException, IOException {
        ECDSAPrivateKey privateKeyTemplate = new ECDSAPrivateKey();
        ECDSAPublicKey publicKeyTemplate = new ECDSAPublicKey();
        setKeyAttributes(id, label, PKCS11Constants.CKK_ECDSA, privateKeyTemplate,
                publicKeyTemplate);

        byte[] ecdsaParamsBytes = ecParams.getEncoded();
        publicKeyTemplate.getEcdsaParams().setByteArrayValue(ecdsaParamsBytes);

        return session.generateKeyPair(Mechanism.get(PKCS11Constants.CKM_EC_KEY_PAIR_GEN),
                publicKeyTemplate, privateKeyTemplate);
    }

    @Override
    public List<? extends P11Identity> getP11Identities() {
        return Collections.unmodifiableList(identities);
    }

    @Override
    public X509Certificate exportCert(
            final P11KeyIdentifier keyIdentifier)
    throws Exception {
        PrivateKey privKey = getPrivateObject(null, null, keyIdentifier);
        if (privKey == null) {
            return null;
        }

        X509PublicKeyCertificate cert =
                getCertificateObject(privKey.getId().getByteArrayValue(), null);
        return X509Util.parseCert(cert.getValue().getByteArrayValue());
    }

    @Override
    public String getModuleName() {
        return moduleName;
    }

    @Override
    public P11SlotIdentifier getSlotIdentifier() {
        return slotId;
    }

    private static boolean checkSessionLoggedIn(
            final Session session)
    throws SignerException {
        SessionInfo info;
        try {
            info = session.getSessionInfo();
        } catch (TokenException ex) {
            throw new SignerException(ex.getMessage(), ex);
        }
        if (LOG.isTraceEnabled()) {
            LOG.debug("SessionInfo: {}", info);
        }

        State state = info.getState();
        long deviceError = info.getDeviceError();

        LOG.debug("to be verified PKCS11Module: state = {}, deviceError: {}", state, deviceError);

        boolean isRwSessionLoggedIn = state.equals(State.RW_USER_FUNCTIONS);
        boolean isRoSessionLoggedIn = state.equals(State.RO_USER_FUNCTIONS);

        boolean sessionSessionLoggedIn = ((isRoSessionLoggedIn || isRwSessionLoggedIn)
                && deviceError == 0);
        LOG.debug("sessionSessionLoggedIn: {}", sessionSessionLoggedIn);
        return sessionSessionLoggedIn;
    }

    private static List<iaik.pkcs.pkcs11.objects.Object> getObjects(
            final Session session,
            final iaik.pkcs.pkcs11.objects.Object template)
    throws SignerException {
        return getObjects(session, template, 9999);
    }

    private static List<iaik.pkcs.pkcs11.objects.Object> getObjects(
            final Session session,
            final iaik.pkcs.pkcs11.objects.Object template,
            final int maxNo)
    throws SignerException {
        List<iaik.pkcs.pkcs11.objects.Object> objList = new LinkedList<>();

        try {
            session.findObjectsInit(template);

            while (objList.size() < maxNo) {
                iaik.pkcs.pkcs11.objects.Object[] foundObjects = session.findObjects(1);
                if (foundObjects == null || foundObjects.length == 0) {
                    break;
                }

                for (iaik.pkcs.pkcs11.objects.Object object : foundObjects) {
                    if (LOG.isTraceEnabled()) {
                        LOG.debug("foundObject: {}", object);
                    }
                    objList.add(object);
                }
            }
        } catch (TokenException ex) {
            throw new SignerException(ex.getMessage(), ex);
        } finally {
            try {
                session.findObjectsFinal();
            } catch (Exception ex) {
            }
        }

        return objList;
    } // method getObjects

    private static String getDescription(
            final byte[] keyId,
            final char[] keyLabel) {
        StringBuilder sb = new StringBuilder();
        sb.append("id ");
        if (keyId == null) {
            sb.append("null");
        } else {
            sb.append(Hex.toHexString(keyId));
        }

        sb.append(" and label ");
        if (keyLabel == null) {
            sb.append("null");
        } else {
            sb.append(new String(keyLabel));
        }
        return sb.toString();
    }

    private static X509PublicKeyCertificate createPkcs11Template(
            final X509Certificate cert,
            final byte[] encodedCert,
            final byte[] keyId,
            final char[] label)
    throws Exception {
        if (label == null || label.length == 0) {
            throw new IllegalArgumentException("label could not be null or empty");
        }

        byte[] localEncodedCert = encodedCert;
        if (localEncodedCert == null) {
            localEncodedCert = cert.getEncoded();
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
        newCertTemp.getValue().setByteArrayValue(localEncodedCert);
        return newCertTemp;
    }

    private static void setKeyAttributes(
            final byte[] id,
            final String label,
            final long keyType,
            final PrivateKey privateKey,
            final PublicKey publicKey) {
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
        ASN1ObjectIdentifier curveId;

        try {
            curveId = new ASN1ObjectIdentifier(curveNameOrOid);
            return curveId;
        } catch (Exception ex) {
        }

        curveId = X962NamedCurves.getOID(curveNameOrOid);

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

    private static String hex(
            final byte[] bytes) {
        return Hex.toHexString(bytes).toUpperCase();
    }

    private static java.security.PublicKey generatePublicKey(
            final PublicKey p11Key)
    throws SignerException {
        if (p11Key instanceof RSAPublicKey) {
            RSAPublicKey rsaP11Key = (RSAPublicKey) p11Key;
            byte[] expBytes = rsaP11Key.getPublicExponent().getByteArrayValue();
            BigInteger exp = new BigInteger(1, expBytes);

            byte[] modBytes = rsaP11Key.getModulus().getByteArrayValue();
            BigInteger mod = new BigInteger(1, modBytes);

            if (LOG.isDebugEnabled()) {
                LOG.debug("modulus:\n {}", Hex.toHexString(modBytes));
            }
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
            try {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                return keyFactory.generatePublic(keySpec);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                throw new SignerException(ex.getMessage(), ex);
            }
        } else if (p11Key instanceof DSAPublicKey) {
            DSAPublicKey dsaP11Key = (DSAPublicKey) p11Key;

            BigInteger prime = new BigInteger(1, dsaP11Key.getPrime().getByteArrayValue()); // p
            BigInteger subPrime = new BigInteger(1,
                    dsaP11Key.getSubprime().getByteArrayValue()); // q
            BigInteger base = new BigInteger(1, dsaP11Key.getBase().getByteArrayValue()); // g
            BigInteger value = new BigInteger(1, dsaP11Key.getValue().getByteArrayValue()); // y

            DSAPublicKeySpec keySpec = new DSAPublicKeySpec(value, prime, subPrime, base);
            try {
                KeyFactory keyFactory = KeyFactory.getInstance("DSA");
                return keyFactory.generatePublic(keySpec);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                throw new SignerException(ex.getMessage(), ex);
            }
        } else if (p11Key instanceof ECDSAPublicKey) {
            ECDSAPublicKey ecP11Key = (ECDSAPublicKey) p11Key;
            byte[] encodedAlgorithmIdParameters = ecP11Key.getEcdsaParams().getByteArrayValue();
            byte[] encodedPoint = ecP11Key.getEcPoint().getByteArrayValue();
            try {
                return KeyUtil.createECPublicKey(encodedAlgorithmIdParameters, encodedPoint);
            } catch (InvalidKeySpecException ex) {
                throw new SignerException(ex.getMessage(), ex);
            }
        } else {
            throw new SignerException("unknown public key class " + p11Key.getClass().getName());
        }
    } // method generatePublicKey

    @Override
    public void showDetails(
            final OutputStream stream,
            final boolean verbose)
    throws IOException, SignerException {
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
