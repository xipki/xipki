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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.p11.AbstractP11Slot;
import org.xipki.commons.security.api.p11.P11Constants;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11Identity;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11MechanismFilter;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.p11.parameters.P11Params;
import org.xipki.commons.security.api.p11.parameters.P11RSAPkcsPssParams;
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
import iaik.pkcs.pkcs11.objects.DSAPublicKey;
import iaik.pkcs.pkcs11.objects.ECDSAPublicKey;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.parameters.RSAPkcsPssParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class IaikP11Slot extends AbstractP11Slot {

    private static final Logger LOG = LoggerFactory.getLogger(IaikP11Slot.class);

    protected static final long DEFAULT_MAX_COUNT_SESSION = 32;

    protected final int maxMessageSize;

    protected Slot slot;

    private final long userType;

    private List<char[]> password;

    private int maxSessionCount;

    private long timeOutWaitNewSession = 10000; // maximal wait for 10 second

    private final AtomicLong countSessions = new AtomicLong(0);

    private final BlockingQueue<Session> idleSessions = new LinkedBlockingDeque<>();

    IaikP11Slot(
            final String moduleName,
            final P11SlotIdentifier slotId,
            final Slot slot,
            final long userType,
            final List<char[]> password,
            final int maxMessageSize,
            final P11MechanismFilter mechanismFilter)
    throws P11TokenException {
        super(moduleName, slotId, mechanismFilter);
        this.slot = ParamUtil.requireNonNull("slot", slot);
        this.maxMessageSize = ParamUtil.requireMin("maxMessageSize", maxMessageSize, 1);
        this.userType = ParamUtil.requireMin("userType", userType, 0);
        this.password = password;

        Session session;
        try {
            session = openSession();
        } catch (P11TokenException ex) {
            final String message = "openSession";
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
            close();
            throw ex;
        }

        try {
            firstLogin(session, password);
        } catch (P11TokenException ex) {
            final String message = "firstLogin";
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
            close();
            throw ex;
        }

        Token token;
        try {
            token = this.slot.getToken();
        } catch (TokenException ex) {
            throw new P11TokenException("could not getToken: " + ex.getMessage(), ex);
        }

        Mechanism[] mechanisms;
        try {
            mechanisms = token.getMechanismList();
        } catch (TokenException ex) {
            throw new P11TokenException("could not getMechanismList: " + ex.getMessage(), ex);
        }

        if (mechanisms != null) {
            for (Mechanism mech : mechanisms) {
                addMechanism(mech.getMechanismCode());
            }
        }

        long maxSessionCount2;
        try {
            maxSessionCount2 = token.getTokenInfo().getMaxSessionCount();
        } catch (TokenException ex) {
            throw new P11TokenException("could not get tokenInfo: " + ex.getMessage(), ex);
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

    @Override
    public void refresh()
    throws P11TokenException {
        Set<P11Identity> currentIdentifies = new HashSet<>();
        List<PrivateKey> signatureKeys = getAllPrivateObjects(Boolean.TRUE, null);

        for (PrivateKey signatureKey : signatureKeys) {
            byte[] keyId = signatureKey.getId().getByteArrayValue();
            if (keyId == null || keyId.length == 0) {
                return;
            }

            try {
                analyseSingleKey(signatureKey, currentIdentifies);
            } catch (SecurityException ex) {
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

        setIdentities(currentIdentifies);
    } // method refresh

    private void analyseSingleKey(
            PrivateKey privKey,
            Set<P11Identity> currentIdentifies)
    throws P11TokenException, SecurityException, CertificateException, IOException {
        byte[] keyId = privKey.getId().getByteArrayValue();
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
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                            ex.getMessage());
                }
                LOG.debug(message, ex);
                return;
            }
            signaturePublicKey = signatureCert.getPublicKey();
        } else {
            signatureCert = null;
            PublicKey publicKeyObject = getPublicKeyObject(
                    Boolean.TRUE, null, keyId, null);
            if (publicKeyObject == null) {
                String msg = "neither certificate nor public key for signing is available";
                LOG.info(msg);
                return;
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

                    if (CollectionUtil.isNonEmpty(issuerCerts)) {
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
                    } catch (Exception ex) { // CHECKSTYLE:SKIP
                    }
                }
            } // end while (true)
        } // end if (signatureCert != null)

        P11KeyIdentifier keyIdObj = new P11KeyIdentifier(
                privKey.getId().getByteArrayValue(),
                new String(privKey.getLabel().getCharArrayValue()));

        IaikP11Identity identity = new IaikP11Identity(moduleName,
                new P11EntityIdentifier(slotId, keyIdObj), privKey,
                certChain.toArray(new X509Certificate[0]), signaturePublicKey);
        currentIdentifies.add(identity);
    }

    byte[] sign(
            final long mechanism,
            final P11Params parameters,
            final byte[] content,
            final P11KeyIdentifier keyId)
    throws P11TokenException {
        ParamUtil.requireNonNull("content", content);
        assertMechanismSupported(mechanism);

        int len = content.length;
        if (len <= maxMessageSize) {
            return singleSign(mechanism, parameters, content, keyId);
        }

        PrivateKey signingKey = ((IaikP11Identity) getIdentity(keyId)).getPrivateKey();
        Mechanism mechanismObj = getMechanism(mechanism, parameters);
        if (LOG.isTraceEnabled()) {
            LOG.debug("sign (init, update, then finish) with private key:\n{}", signingKey);
        }

        Session session = borrowIdleSession();
        if (session == null) {
            throw new P11TokenException("no idle session available");
        }

        try {
            synchronized (session) {
                login(session);
                session.signInit(mechanismObj, signingKey);
                for (int i = 0; i < len; i += maxMessageSize) {
                    int blockLen = Math.min(maxMessageSize, len - i);
                    byte[] block = new byte[blockLen];
                    System.arraycopy(content, i, block, 0, blockLen);
                    session.signUpdate(block);
                }

                byte[] signature = session.signFinal();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("signature:\n{}", Hex.toHexString(signature));
                }
                return signature;
            }
        } catch (TokenException e) {
            throw new P11TokenException(e);
        } finally {
            returnIdleSession(session);
        }
    }

    private byte[] singleSign(
            final long mechanism,
            final P11Params parameters,
            final byte[] hash,
            final P11KeyIdentifier keyId)
    throws P11TokenException {
        PrivateKey signingKey = ((IaikP11Identity) getIdentity(keyId)).getPrivateKey();
        Mechanism mechanismObj = getMechanism(mechanism, parameters);
        if (LOG.isTraceEnabled()) {
            LOG.debug("sign with private key:\n{}", signingKey);
        }

        Session session = borrowIdleSession();
        if (session == null) {
            throw new P11TokenException("no idle session available");
        }

        byte[] signature;
        try {
            synchronized (session) {
                login(session);
                session.signInit(mechanismObj, signingKey);
                signature = session.sign(hash);
            }
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        } finally {
            returnIdleSession(session);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("signature:\n{}", Hex.toHexString(signature));
        }
        return signature;
    }

    private static Mechanism getMechanism(
            final long mechanism,
            final P11Params parameters)
    throws P11TokenException {
        Mechanism ret = Mechanism.get(mechanism);
        if (parameters == null) {
            return ret;
        }

        if (parameters instanceof P11RSAPkcsPssParams) {
            P11RSAPkcsPssParams param = (P11RSAPkcsPssParams) parameters;
            RSAPkcsPssParameters paramObj = new RSAPkcsPssParameters(
                    Mechanism.get(param.getHashAlgorithm()), param.getMaskGenerationFunction(),
                    param.getSaltLength());
            ret.setParameters(paramObj);
        } else {
            throw new P11TokenException("unknown P11Parameters " + parameters.getClass().getName());
        }
        return ret;
    }

    private Session openSession()
    throws P11TokenException {
        return openSession(false);
    }

    protected Session openSession(
            final boolean rwSession)
    throws P11TokenException {
        Session session;
        try {
            session = slot.getToken().openSession(
                    Token.SessionType.SERIAL_SESSION, rwSession, null, null);
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }
        countSessions.incrementAndGet();
        return session;
    }

    private void closeSession(
            final Session session)
    throws P11TokenException {
        try {
            session.closeSession();
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        } finally {
            countSessions.decrementAndGet();
        }
    }

    protected Session borrowIdleSession()
    throws P11TokenException {
        if (countSessions.get() < maxSessionCount) {
            Session session = idleSessions.poll();
            if (session == null) {
                // create new session
                session = openSession();
            }

            if (session != null) {
                return session;
            }
        }

        try {
            return idleSessions.poll(timeOutWaitNewSession, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ex) { // CHECKSTYLE:SKIP
        }

        throw new P11TokenException("no idle session");
    }

    protected void returnIdleSession(
            final Session session) {
        if (session == null) {
            return;
        }

        for (int i = 0; i < 3; i++) {
            try {
                idleSessions.put(session);
                return;
            } catch (InterruptedException ex) { // CHECKSTYLE:SKIP
            }
        }

        try {
            closeSession(session);
        } catch (P11TokenException ex) {
            LOG.error("could not closeSession {}: {}", ex.getClass().getName(), ex.getMessage());
            LOG.debug("closeSession", ex);
        }
    }

    private void firstLogin(
            final Session session,
            final List<char[]> password)
    throws P11TokenException {
        try {
            boolean isProtectedAuthenticationPath =
                    session.getToken().getTokenInfo().isProtectedAuthenticationPath();

            if (isProtectedAuthenticationPath || CollectionUtil.isEmpty(password)) {
                LOG.info("verify on PKCS11Module with PROTECTED_AUTHENTICATION_PATH");
                login(session, null);
            } else {
                LOG.info("verify on PKCS11Module with PIN");

                for (char[] singlePwd : password) {
                    login(session, singlePwd);
                }
                this.password = password;
            }
        } catch (PKCS11Exception ex) {
            // 0x100: user already logged in
            if (ex.getErrorCode() != 0x100) {
                throw new P11TokenException(ex.getMessage(), ex);
            }
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }
    }

    private void login(
            final Session session)
    throws P11TokenException {
        boolean isSessionLoggedIn = checkSessionLoggedIn(session);
        if (isSessionLoggedIn) {
            return;
        }

        boolean loginRequired;
        try {
            loginRequired = session.getToken().getTokenInfo().isLoginRequired();
        } catch (TokenException ex) {
            String msg = "could not check whether LoginRequired of token";
            LOG.error(LogUtil.buildExceptionLogFormat(msg),
                    ex.getClass().getName(), ex.getMessage());
            LOG.debug(msg, ex);
            loginRequired = true;
        }

        LOG.debug("loginRequired: {}", loginRequired);
        if (!loginRequired) {
            return;
        }

        if (CollectionUtil.isEmpty(password)) {
            login(session, null);
        } else {
            for (char[] singlePwd : password) {
                login(session, singlePwd);
            }
        }
    }

    private void login(
            final Session session,
            final char[] pin)
    throws P11TokenException {
        char[] tmpPin = pin;
        // some driver does not accept null PIN
        if (pin == null) {
            tmpPin = new char[]{};
        }

        try {
            if (userType == P11Constants.CKU_USER) {
                session.login(Session.UserType.USER, tmpPin);
                return;
            } else if (userType == P11Constants.CKU_SO) {
                session.login(Session.UserType.SO, tmpPin);
                return;
            }

            final long handle = session.getSessionHandle();
            final boolean useUtf8Encoding = true;
            session.getModule().getPKCS11Module().C_Login(handle, userType, tmpPin,
                    useUtf8Encoding);
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }
    }

    @Override
    public void close() {
        if (slot != null) {
            try {
                LOG.info("close all sessions on token: {}", slot.getSlotID());
                slot.getToken().closeAllSessions();
            } catch (Throwable th) {
                final String message = "could not slot.getToken().closeAllSessions()";
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

    protected List<PrivateKey> getAllPrivateObjects(
            final Boolean forSigning,
            final Boolean forDecrypting)
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

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            if (CollectionUtil.isEmpty(tmpObjects)) {
                return Collections.emptyList();
            }

            final int n = tmpObjects.size();
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

    private PrivateKey cacheSigningKey(
            final PrivateKey privateKey) {
        Boolean bo = privateKey.getSign().getBooleanValue();
        byte[] id = privateKey.getId().getByteArrayValue();
        char[] tmpLabel = privateKey.getLabel().getCharArrayValue();
        if (tmpLabel == null) {
            LOG.warn("key (id = {}) does not have label", Hex.toHexString(id));
            return null;
        }

        String label = new String(tmpLabel);

        if (bo == null || !bo.booleanValue()) {
            LOG.warn("key {} is not for signing", new P11KeyIdentifier(id, label));
            return null;
        }

        return privateKey;
    }

    protected String listPrivateKeyObjects(
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
                msg.append(toString(label)).append("\n");
            }
            return msg.toString();
        } catch (Throwable th) {
            return "Exception while calling listPrivateKeyObjects(): " + th.getMessage();
        }
    } // method listPrivateKeyObjects

    protected PublicKey getPublicKeyObject(
            final Boolean forSignature,
            final Boolean forCipher,
            final byte[] keyId,
            final char[] keyLabel)
    throws P11TokenException {
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

    protected X509PublicKeyCertificate[] getCertificateObjects(
            final X500Principal subject)
    throws P11TokenException {
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
            final int n = (tmpObjects == null)
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

    protected X509PublicKeyCertificate[] getCertificateObjects(
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

    protected X509PublicKeyCertificate getCertificateObject(
            final byte[] keyId,
            final char[] keyLabel)
    throws P11TokenException {
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

    protected String listCertificateObjects(
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
                msg.append(toString(label)).append("\n");
            }
            return msg.toString();
        } catch (Throwable th) {
            return "Exception while calling listCertificateObjects(): " + th.getMessage();
        }
    } // method listCertificateObjects

    private static boolean checkSessionLoggedIn(
            final Session session)
    throws P11TokenException {
        SessionInfo info;
        try {
            info = session.getSessionInfo();
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
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

    protected static List<iaik.pkcs.pkcs11.objects.Object> getObjects(
            final Session session,
            final iaik.pkcs.pkcs11.objects.Object template)
    throws P11TokenException {
        return getObjects(session, template, 9999);
    }

    protected static List<iaik.pkcs.pkcs11.objects.Object> getObjects(
            final Session session,
            final iaik.pkcs.pkcs11.objects.Object template,
            final int maxNo)
    throws P11TokenException {
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
            throw new P11TokenException(ex.getMessage(), ex);
        } finally {
            try {
                session.findObjectsFinal();
            } catch (Exception ex) { // CHECKSTYLE:SKIP
            }
        }

        return objList;
    } // method getObjects

    private static java.security.PublicKey generatePublicKey(
            final PublicKey p11Key)
    throws SecurityException {
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
                throw new SecurityException(ex.getMessage(), ex);
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
                throw new SecurityException(ex.getMessage(), ex);
            }
        } else if (p11Key instanceof ECDSAPublicKey) {
            ECDSAPublicKey ecP11Key = (ECDSAPublicKey) p11Key;
            byte[] encodedAlgorithmIdParameters = ecP11Key.getEcdsaParams().getByteArrayValue();
            byte[] encodedPoint = ecP11Key.getEcPoint().getByteArrayValue();
            try {
                return KeyUtil.createECPublicKey(encodedAlgorithmIdParameters, encodedPoint);
            } catch (InvalidKeySpecException ex) {
                throw new SecurityException(ex.getMessage(), ex);
            }
        } else {
            throw new SecurityException("unknown publicKey class " + p11Key.getClass().getName());
        }
    } // method generatePublicKey

    private static String toString(
            final CharArrayAttribute charArrayAttr) {
        String labelStr = null;
        if (charArrayAttr != null) {
            char[] chars = charArrayAttr.getCharArrayValue();
            if (chars != null) {
                labelStr = new String(chars);
            }
        }
        return labelStr;
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
                msg.append(toString(label)).append("\n");
            } // end for
            return msg.toString();
        } catch (Throwable th) {
            return "Exception while calling listPublicKeyObjects(): " + th.getMessage();
        }
    } // method listPublicKeyObjects

}
