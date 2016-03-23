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
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
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
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
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
import org.xipki.commons.security.api.HashAlgoType;
import org.xipki.commons.security.api.HashCalculator;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.p11.AbstractP11Slot;
import org.xipki.commons.security.api.p11.P11Constants;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11Identity;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11MechanismFilter;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.p11.P11UnknownEntityException;
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

    private final SecurityFactory securityFactory;

    private boolean writableSessionInUse;

    private Session writableSession;

    IaikP11Slot(
            final String moduleName,
            final P11SlotIdentifier slotId,
            final Slot slot,
            final long userType,
            final List<char[]> password,
            final int maxMessageSize,
            final SecurityFactory securityFactory,
            final P11MechanismFilter mechanismFilter)
    throws P11TokenException {
        super(moduleName, slotId, mechanismFilter);
        this.slot = ParamUtil.requireNonNull("slot", slot);
        this.maxMessageSize = ParamUtil.requireMin("maxMessageSize", maxMessageSize, 1);
        this.userType = ParamUtil.requireMin("userType", userType, 0);
        this.securityFactory = ParamUtil.requireNonNull("securityFactory", securityFactory);
        this.password = password;

        Session session;
        try {
            session = openSession(false);
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

    private void analyseSingleKey(
            PrivateKey privKey,
            Set<P11Identity> currentIdentifies)
    throws P11TokenException, SecurityException, CertificateException, IOException {
        byte[] keyId = privKey.getId().getByteArrayValue();
        X509PublicKeyCertificate certificateObject = getCertificateObject(keyId, null);
        X509Certificate signatureCert = null;
        java.security.PublicKey signaturePublicKey = null;

        if (certificateObject != null) {
            try {
                signatureCert = parseCert(certificateObject);
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
            PublicKey publicKeyObject = getPublicKeyObject(Boolean.TRUE, null, keyId, null);
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
                            issuerCerts.add(parseCert(certObject));
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

        P11KeyIdentifier keyIdObj = new P11KeyIdentifier(privKey.getId().getByteArrayValue(),
                new String(privKey.getLabel().getCharArrayValue()));

        IaikP11Identity identity = new IaikP11Identity(moduleName,
                new P11EntityIdentifier(slotId, keyIdObj), privKey,
                certChain.toArray(new X509Certificate[0]), signaturePublicKey);
        currentIdentifies.add(identity);
    }

    @Override
    public byte[] sign(
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

    private Session openSession(
            final boolean rwSession)
    throws P11TokenException {
        Session session;
        try {
            session = slot.getToken().openSession(Token.SessionType.SERIAL_SESSION, rwSession,
                    null, null);
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

    private Session borrowIdleSession()
    throws P11TokenException {
        if (countSessions.get() < maxSessionCount) {
            Session session = idleSessions.poll();
            if (session == null) {
                // create new session
                session = openSession(false);
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

    private void returnIdleSession(
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
                singleLogin(session, null);
            } else {
                LOG.info("verify on PKCS11Module with PIN");
                for (char[] singlePwd : password) {
                    singleLogin(session, singlePwd);
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
            singleLogin(session, null);
        } else {
            for (char[] singlePwd : password) {
                singleLogin(session, singlePwd);
            }
        }
    }

    private void singleLogin(
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

    private List<PrivateKey> getAllPrivateObjects(
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
                msg.append("------------------------PrivateKey ").append(i + 1);
                msg.append("-------------------------\n");

                msg.append("\tid(hex): ");
                PrivateKey privKey = (PrivateKey) tmpObjects.get(i);
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

    private PublicKey getPublicKeyObject(
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

            PublicKey template = new PublicKey();
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

            return (PublicKey) tmpObjects.get(0);
        } finally {
            returnIdleSession(session);
        }
    } // method getPublicKeyObject

    private X509PublicKeyCertificate[] getCertificateObjects(
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
                LOG.warn("found no certificate with subject {}", X509Util.getRfc4519Name(subject));
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

    private X509PublicKeyCertificate[] getCertificateObjects(
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
                LOG.info("found no certificate identified by {}", getDescription(keyId, keyLabel));
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

    private X509PublicKeyCertificate getCertificateObject(
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
                msg.append("------------------------Certificate ").append(i + 1);
                msg.append("-------------------------\n");
                msg.append("\tid(hex): ");
                X509PublicKeyCertificate cert = (X509PublicKeyCertificate) tmpObjects.get(i);
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
                msg.append("\n\tlabel: ").append(toString(cert.getLabel())).append("\n");
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

    private static List<iaik.pkcs.pkcs11.objects.Object> getObjects(
            final Session session,
            final iaik.pkcs.pkcs11.objects.Object template)
    throws P11TokenException {
        return getObjects(session, template, 9999);
    }

    private static List<iaik.pkcs.pkcs11.objects.Object> getObjects(
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

    private static X509Certificate parseCert(
            final X509PublicKeyCertificate p11Cert)
    throws CertificateException, IOException {
        return X509Util.parseCert(p11Cert.getValue().getByteArrayValue());
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

            PublicKey template = new PublicKey();
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
                msg.append("------------------------Public Key ").append(i + 1);
                msg.append("-------------------------\n");
                msg.append("\tid(hex): ");
                PublicKey pubKey = (PublicKey) tmpObjects.get(i);
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
                msg.append("\n\tlabel: ").append(toString(pubKey.getLabel())).append("\n");
            } // end for
            return msg.toString();
        } catch (Throwable th) {
            return "Exception while calling listPublicKeyObjects(): " + th.getMessage();
        }
    } // method listPublicKeyObjects

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
            final P11KeyIdentifier keyId)
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

            template.getId().setByteArrayValue(keyId.getId());
            template.getLabel().setCharArrayValue(keyId.getLabel().toCharArray());

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            if (CollectionUtil.isEmpty(tmpObjects)) {
                return null;
            }

            int size = tmpObjects.size();
            if (size > 1) {
                LOG.warn("found {} private key identified by {}, use the first one", size, keyId);
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
            final P11KeyIdentifier keyId,
            final X509Certificate newCert,
            final Set<X509Certificate> caCerts,
            final HashAlgoType hashAlgoForVerification)
    throws SecurityException, P11TokenException {
        ParamUtil.requireNonNull("keyId", keyId);
        ParamUtil.requireNonNull("newCert", newCert);
        ParamUtil.requireNonNull("hashAlgoForVerification", hashAlgoForVerification);

        PrivateKey privKey = getPrivateObject(null, null, keyId);

        if (privKey == null) {
            throw new P11UnknownEntityException("could not find private key " + keyId);
        }

        byte[] id = privKey.getId().getByteArrayValue();
        X509PublicKeyCertificate[] existingCerts = getCertificateObjects(id, null);

        assertMatch(newCert, keyId, hashAlgoForVerification);

        X509Certificate[] certChain = X509Util.buildCertPath(newCert, caCerts);

        Session session = borrowWritableSession();
        try {
            X509PublicKeyCertificate newCertTemp = createPkcs11Template(newCert, null, id,
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
            certificateUpdated(keyId, newCert);

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
                    certificateAdded(keyId, caCert);
                }
            } // end if(certChain.length)
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        } finally {
            returnWritableSession(session);
        }
    } // method updateCertificate

    @Override
    public boolean removeKeyAndCerts(
            final P11KeyIdentifier keyId)
    throws SecurityException, P11TokenException {
        ParamUtil.requireNonNull("keyId", keyId);

        PrivateKey privKey = getPrivateObject(null, null, keyId);
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

            keyRemoved(keyId);
            certificateRemoved(keyId);

            X509PublicKeyCertificate[] certs = getCertificateObjects(
                    privKey.getId().getByteArrayValue(), null);
            if (certs != null && certs.length > 0) {
                for (int i = 0; i < certs.length; i++) {
                    try {
                        session.destroyObject(certs[i]);
                    } catch (TokenException ex) {
                        msgBuilder.append("could not delete certificate at index ");
                        msgBuilder.append(i).append(", ");
                    }
                } // end for
            } // end if (certs)
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
            final P11KeyIdentifier keyId)
    throws SecurityException, P11TokenException {
        ParamUtil.requireNonNull("keyId", keyId);

        String keyLabel = keyId.getLabel();
        char[] keyLabelChars = (keyLabel == null)
                ? null
                : keyLabel.toCharArray();

        X509PublicKeyCertificate[] existingCerts = getCertificateObjects(keyId.getId(),
                keyLabelChars);

        if (existingCerts == null || existingCerts.length == 0) {
            throw new SecurityException("could not find certificates with id " + keyId);
        }

        Session session = borrowWritableSession();
        try {
            for (X509PublicKeyCertificate cert : existingCerts) {
                session.destroyObject(cert);
                certificateRemoved(keyId);
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
            final HashAlgoType hashAlgoForVerification)
    throws SecurityException {
        ConfPairs pairs = new ConfPairs("slot-id", Long.toString(slot.getSlotID()));
        pairs.putPair("key-id", Hex.toHexString(keyId.getId()));
        securityFactory.createSigner("PKCS11", pairs.getEncoded(),
                hashAlgoForVerification.getName(), null, cert);
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
            certificateAdded(p11KeyId, cert);
            return p11KeyId;
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        } catch (CertificateEncodingException ex) {
            throw new SecurityException(ex.getMessage(), ex);
        } finally {
            returnWritableSession(session);
        }
    }

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

        final long mech = P11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;
        assertMechanismSupported(mech);

        BigInteger tmpPublicExponent = publicExponent;
        if (tmpPublicExponent == null) {
            tmpPublicExponent = BigInteger.valueOf(65537);
        }

        RSAPrivateKey privateKey = new RSAPrivateKey();
        RSAPublicKey publicKey = new RSAPublicKey();
        setKeyAttributes(label, P11Constants.CKK_RSA, publicKey, privateKey);

        publicKey.getModulusBits().setLongValue((long) keySize);
        publicKey.getPublicExponent().setByteArrayValue(tmpPublicExponent.toByteArray());
        return generateKeyPair(mech, privateKey, publicKey);

    }

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

        final long mech = P11Constants.CKM_DSA_KEY_PAIR_GEN;
        assertMechanismSupported(mech);

        DSAParametersGenerator paramGen = new DSAParametersGenerator(new SHA512Digest());
        DSAParameterGenerationParameters genParams = new DSAParameterGenerationParameters(
                plength, qlength, 80, new SecureRandom());
        paramGen.init(genParams);
        DSAParameters dsaParams = paramGen.generateParameters();

        DSAPrivateKey privateKey = new DSAPrivateKey();
        DSAPublicKey publicKey = new DSAPublicKey();
        setKeyAttributes(label, P11Constants.CKK_DSA, publicKey, privateKey);

        publicKey.getPrime().setByteArrayValue(dsaParams.getP().toByteArray());
        publicKey.getSubprime().setByteArrayValue(dsaParams.getQ().toByteArray());
        publicKey.getBase().setByteArrayValue(dsaParams.getG().toByteArray());
        return generateKeyPair(mech, privateKey, publicKey);
    }

    @Override
    public P11KeyIdentifier generateECKeypair(
            final String curveNameOrOid,
            final String label)
    throws SecurityException, P11TokenException {
        ParamUtil.requireNonBlank("curveNameOrOid", curveNameOrOid);
        ParamUtil.requireNonBlank("label", label);

        ASN1ObjectIdentifier curveId = KeyUtil.getCurveOidForCurveNameOrOid(curveNameOrOid);
        if (curveId == null) {
            throw new IllegalArgumentException("unknown curve " + curveNameOrOid);
        }

        X9ECParameters ecParams = ECNamedCurveTable.getByOID(curveId);
        if (ecParams == null) {
            throw new IllegalArgumentException("unknown curve " + curveNameOrOid);
        }

        final long mech = P11Constants.CKM_EC_KEY_PAIR_GEN;
        assertMechanismSupported(mech);

        ECDSAPrivateKey privateKey = new ECDSAPrivateKey();
        ECDSAPublicKey publicKey = new ECDSAPublicKey();
        setKeyAttributes(label, P11Constants.CKK_EC, publicKey, privateKey);

        byte[] encodedCurveId;
        try {
            encodedCurveId = curveId.getEncoded();
        } catch (IOException ex) {
            throw new SecurityException(ex.getMessage(), ex);
        }
        try {
            publicKey.getEcdsaParams().setByteArrayValue(encodedCurveId);
            return generateKeyPair(mech, privateKey, publicKey);
        } catch (P11TokenException ex) {
            try {
                publicKey.getEcdsaParams().setByteArrayValue(ecParams.getEncoded());
            } catch (IOException ex2) {
                throw new SecurityException(ex.getMessage(), ex);
            }
            return generateKeyPair(mech, privateKey, publicKey);
        }
    } // method generateECKeypair

    private P11KeyIdentifier generateKeyPair(
            final long mech,
            final PrivateKey privateKey,
            final PublicKey publicKey)
    throws P11TokenException {
        final String label = new String(privateKey.getLabel().getCharArrayValue());
        Session session = borrowWritableSession();
        try {
            if (IaikP11Util.labelExists(session, label)) {
                throw new IllegalArgumentException(
                        "label " + label + " exists, please specify another one");
            }

            byte[] id = IaikP11Util.generateKeyId(session);
            privateKey.getId().setByteArrayValue(id);
            publicKey.getId().setByteArrayValue(id);
            KeyPair keypair;
            try {
                keypair = session.generateKeyPair(Mechanism.get(mech), publicKey, privateKey);
            } catch (TokenException ex) {
                throw new P11TokenException(
                        "could not generate keypair " + P11Constants.getMechanismName(mech), ex);
            }

            P11KeyIdentifier keyId = new P11KeyIdentifier(id, label);
            P11EntityIdentifier entityId = new P11EntityIdentifier(slotId, keyId);
            java.security.PublicKey jcePublicKey;
            try {
                jcePublicKey = generatePublicKey(keypair.getPublicKey());
            } catch (SecurityException ex) {
                throw new P11TokenException("could not generate public key " + keyId, ex);
            }

            P11Identity identity = new IaikP11Identity(moduleName, entityId, privateKey, null,
                    jcePublicKey);
            keyAdded(identity);
            return keyId;
        } finally {
            returnWritableSession(session);
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

        X509PublicKeyCertificate cert = getCertificateObject(keyId.getId(), null);
        if (cert == null) {
            throw new P11UnknownEntityException(slotId, keyId);
        }
        try {
            return parseCert(cert);
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
            final String label,
            final long keyType,
            final PublicKey publicKey,
            final PrivateKey privateKey) {
        if (privateKey != null) {
            privateKey.getToken().setBooleanValue(true);
            privateKey.getLabel().setCharArrayValue(label.toCharArray());
            privateKey.getKeyType().setLongValue(keyType);
            privateKey.getSign().setBooleanValue(true);
            privateKey.getPrivate().setBooleanValue(true);
            privateKey.getSensitive().setBooleanValue(true);
        }

        if (publicKey != null) {
            publicKey.getToken().setBooleanValue(true);
            publicKey.getLabel().setCharArrayValue(label.toCharArray());
            publicKey.getKeyType().setLongValue(keyType);
            publicKey.getVerify().setBooleanValue(true);
            publicKey.getModifiable().setBooleanValue(Boolean.TRUE);
        }
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
            sb.append("\t").append(i + 1).append(". ").append(privKey.getKeyLabelAsText());
            sb.append(" (").append("id: ");
            sb.append(Hex.toHexString(privKey.getKeyId()).toUpperCase()).append(")\n");
            sb.append("\t\tAlgorithm: ").append(getKeyAlgorithm(pubKey)).append("\n");

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
            sb.append("\tCert-").append(i + 1).append(". ");
            sb.append(certObj.getLabel().getCharArrayValue()).append(" (").append("id: ");
            sb.append(Hex.toHexString(certObj.getId().getByteArrayValue()).toUpperCase());
            sb.append(")\n");

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
            if (keyId != null && !Arrays.equals(keyId, certObj.getId().getByteArrayValue())) {
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
        sb.append("\t\t\tSubject: ").append(subject).append("\n");

        bytes = cert.getIssuer().getByteArrayValue();
        String issuer;
        try {
            X500Principal x500Prin = new X500Principal(bytes);
            issuer = X509Util.getRfc4519Name(x500Prin);
        } catch (Exception ex) {
            issuer = new String(bytes);
        }
        sb.append("\t\t\tIssuer: ").append(issuer).append("\n");

        byte[] certBytes = cert.getValue().getByteArrayValue();

        X509Certificate x509Cert = null;
        try {
            x509Cert = X509Util.parseCert(certBytes);
        } catch (Exception ex) {
            sb.append("\t\t\tError: " + ex.getMessage());
            return;
        }

        sb.append("\t\t\tSerial: ").append(x509Cert.getSerialNumber()).append("\n");
        sb.append("\t\t\tStart time: ").append(x509Cert.getNotBefore()).append("\n");
        sb.append("\t\t\tEnd time: ").append(x509Cert.getNotAfter()).append("\n");
        sb.append("\t\t\tSHA1 Sum: ").append(HashCalculator.hexSha1(certBytes)).append("\n");
    }

}
