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

package org.xipki.commons.security.pkcs11.internal.iaik;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import javax.annotation.Nonnull;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.X509Cert;
import org.xipki.commons.security.api.exception.SecurityException;
import org.xipki.commons.security.api.p11.AbstractP11Slot;
import org.xipki.commons.security.api.p11.P11Constants;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11Identity;
import org.xipki.commons.security.api.p11.P11MechanismFilter;
import org.xipki.commons.security.api.p11.P11ObjectIdentifier;
import org.xipki.commons.security.api.p11.P11Params;
import org.xipki.commons.security.api.p11.P11RSAPkcsPssParams;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11SlotRefreshResult;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.util.KeyUtil;
import org.xipki.commons.security.api.util.X509Util;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.SessionInfo;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.State;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Certificate.CertificateType;
import iaik.pkcs.pkcs11.objects.CharArrayAttribute;
import iaik.pkcs.pkcs11.objects.DSAPrivateKey;
import iaik.pkcs.pkcs11.objects.DSAPublicKey;
import iaik.pkcs.pkcs11.objects.ECDSAPrivateKey;
import iaik.pkcs.pkcs11.objects.ECDSAPublicKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.objects.Storage;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.parameters.RSAPkcsPssParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
class IaikP11Slot extends AbstractP11Slot {

    private static final Logger LOG = LoggerFactory.getLogger(IaikP11Slot.class);

    private static final long DEFAULT_MAX_COUNT_SESSION = 32;

    private final int maxMessageSize;

    private Slot slot;

    private final long userType;

    private List<char[]> password;

    private int maxSessionCount;

    private long timeOutWaitNewSession = 10000; // maximal wait for 10 second

    private final AtomicLong countSessions = new AtomicLong(0);

    private final BlockingDeque<Session> idleSessions = new LinkedBlockingDeque<>();

    private final BlockingDeque<Session> busySessions = new LinkedBlockingDeque<>();

    private boolean writableSessionInUse;

    private Session writableSession;

    IaikP11Slot(
            final String moduleName,
            final P11SlotIdentifier slotId,
            final Slot slot,
            final boolean readOnly,
            final long userType,
            final List<char[]> password,
            final int maxMessageSize,
            final P11MechanismFilter mechanismFilter)
    throws P11TokenException {
        super(moduleName, slotId, readOnly, mechanismFilter);
        this.slot = ParamUtil.requireNonNull("slot", slot);
        this.maxMessageSize = ParamUtil.requireMin("maxMessageSize", maxMessageSize, 1);
        this.userType = ParamUtil.requireMin("userType", userType, 0);
        this.password = password;

        Session session;
        try {
            session = openSession(false);
        } catch (P11TokenException ex) {
            LogUtil.error(LOG, ex, "openSession");
            close();
            throw ex;
        }

        try {
            firstLogin(session, password);
        } catch (P11TokenException ex) {
            LogUtil.error(LOG, ex, "firstLogin");
            close();
            throw ex;
        }

        Token token;
        try {
            token = this.slot.getToken();
        } catch (TokenException ex) {
            throw new P11TokenException("could not getToken: " + ex.getMessage(), ex);
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

        idleSessions.addLast(session);
        refresh();
    } // constructor

    Slot getSlot() {
        return slot;
    }

    @Override
    protected P11SlotRefreshResult doRefresh(
            final P11MechanismFilter mechanismFilter)
    throws P11TokenException {
        Mechanism[] mechanisms;
        try {
            mechanisms = slot.getToken().getMechanismList();
        } catch (TokenException ex) {
            throw new P11TokenException("could not getMechanismList: " + ex.getMessage(), ex);
        }

        P11SlotRefreshResult ret = new P11SlotRefreshResult();
        if (mechanisms != null) {
            for (Mechanism mech : mechanisms) {
                long code = mech.getMechanismCode();
                if (mechanismFilter.isMechanismPermitted(slotId, code)) {
                    ret.addMechanism(code);
                }
            }
        }

        // first get the list of all CA certificates
        List<X509PublicKeyCertificate> p11Certs = getAllCertificateObjects();
        for (X509PublicKeyCertificate p11Cert : p11Certs) {
            P11ObjectIdentifier objId = new P11ObjectIdentifier(p11Cert.getId().getByteArrayValue(),
                    toString(p11Cert.getLabel()));
            ret.addCertificate(objId, parseCert(p11Cert));
        }

        List<PrivateKey> privKeys = getAllPrivateObjects();

        for (PrivateKey privKey : privKeys) {
            byte[] keyId = privKey.getId().getByteArrayValue();
            if (keyId == null || keyId.length == 0) {
                break;
            }

            try {
                analyseSingleKey(privKey, ret);
            } catch (SecurityException ex) {
                LogUtil.error(LOG, ex,
                        "SecurityException while initializing key with id " + hex(keyId));
                continue;
            } catch (Throwable th) {
                LogUtil.error(LOG, th,
                        "unexpected exception while initializing key with id " + hex(keyId));
                continue;
            }
        } // end for (PrivateKey signatureKey : signatureKeys)

        return ret;
    } // method refresh

    @Override
    public void close() {
        if (slot != null) {
            try {
                LOG.info("close all sessions on token: {}", slot.getSlotID());

                if (writableSession != null) {
                    writableSession.closeSession();
                }

                for (Session session : idleSessions) {
                    session.closeSession();
                }
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not slot.getToken().closeAllSessions()");
            }

            slot = null;
        }

        // clear the session pool
        idleSessions.clear();
        countSessions.lazySet(0);
    }

    private void analyseSingleKey(
            final PrivateKey privKey,
            final P11SlotRefreshResult refreshResult)
    throws P11TokenException, SecurityException {
        byte[] id = privKey.getId().getByteArrayValue();
        java.security.PublicKey pubKey = null;
        X509Cert cert = refreshResult.getCertForId(id);
        if (cert != null) {
            pubKey = cert.getCert().getPublicKey();
        } else {
            cert = null;
            PublicKey p11PublicKey = getPublicKeyObject(id, null);
            if (p11PublicKey == null) {
                LOG.info("neither certificate nor public key for the key (" + Hex.toHexString(id)
                        + " is available");
                return;
            }

            pubKey = generatePublicKey(p11PublicKey);
        }

        P11ObjectIdentifier objectId = new P11ObjectIdentifier(privKey.getId().getByteArrayValue(),
                toString(privKey.getLabel()));

        X509Certificate[] certs = (cert == null)
                ? null
                : new X509Certificate[]{cert.getCert()};
        IaikP11Identity identity = new IaikP11Identity(this,
                new P11EntityIdentifier(slotId, objectId), privKey, pubKey, certs);
        refreshResult.addIdentity(identity);
    }

    byte[] sign(
            final long mechanism,
            final P11Params parameters,
            final byte[] content,
            final IaikP11Identity identity)
    throws P11TokenException {
        ParamUtil.requireNonNull("content", content);
        assertMechanismSupported(mechanism);

        int len = content.length;
        if (len <= maxMessageSize) {
            return singleSign(mechanism, parameters, content, identity);
        }

        PrivateKey signingKey = identity.getPrivateKey();
        Mechanism mechanismObj = getMechanism(mechanism, parameters);
        if (LOG.isTraceEnabled()) {
            LOG.debug("sign (init, update, then finish) with private key:\n{}", signingKey);
        }

        Session session = borrowIdleSession();
        if (session == null) {
            throw new P11TokenException("no idle session available");
        }

        try {
            session.signInit(mechanismObj, signingKey);
            for (int i = 0; i < len; i += maxMessageSize) {
                int blockLen = Math.min(maxMessageSize, len - i);
                //byte[] block = new byte[blockLen];
                //System.arraycopy(content, i, block, 0, blockLen);
                session.signUpdate(content, i, blockLen);
            }

            return session.signFinal(identity.getExpectedSignatureLen());
        } catch (TokenException e) {
            throw new P11TokenException(e);
        } finally {
            returnIdleSession(session);
        }
    }

    private byte[] singleSign(
            final long mechanism,
            final P11Params parameters,
            final byte[] content,
            final IaikP11Identity identity)
    throws P11TokenException {
        PrivateKey signingKey = identity.getPrivateKey();
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
                session.signInit(mechanismObj, signingKey);
                signature = session.sign(content);
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

    private Session borrowIdleSession()
    throws P11TokenException {
        Session session = null;
        if (countSessions.get() < maxSessionCount) {
            session = idleSessions.poll();
            if (session == null) {
                // create new session
                session = openSession(false);
            }
        }

        if (session == null) {
            try {
                session = idleSessions.poll(timeOutWaitNewSession, TimeUnit.MILLISECONDS);
            } catch (InterruptedException ex) { // CHECKSTYLE:SKIP
            }
        }

        if (session == null) {
            throw new P11TokenException("no idle session");
        }
        busySessions.addLast(session);
        login(session);
        return session;
    }

    private void returnIdleSession(
            final Session session) {
        if (session == null) {
            return;
        }

        boolean isBusySession = busySessions.remove(session);
        if (isBusySession) {
            idleSessions.addLast(session);
        } else {
            final String msg =
                    "session has not been borrowed before or has been returned more than once: "
                    + session;
            LOG.error(msg);
            throw new IllegalStateException(msg);
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
            LogUtil.error(LOG, ex, "could not check whether LoginRequired of token");
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
            } else if (userType == P11Constants.CKU_SO) {
                session.login(Session.UserType.SO, tmpPin);
            } else {
                session.login(userType, tmpPin);
            }
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }
    }

    private List<PrivateKey> getAllPrivateObjects()
    throws P11TokenException {
        Session session = borrowIdleSession();

        try {
            PrivateKey template = new PrivateKey();
            List<Storage> tmpObjects = getObjects(session, template);
            if (CollectionUtil.isEmpty(tmpObjects)) {
                return Collections.emptyList();
            }

            final int n = tmpObjects.size();
            LOG.info("found {} private keys", n);

            List<PrivateKey> privateKeys = new ArrayList<>(n);
            for (Storage tmpObject : tmpObjects) {
                PrivateKey privateKey = (PrivateKey) tmpObject;
                privateKeys.add(privateKey);
            }

            return privateKeys;
        } finally {
            returnIdleSession(session);
        }
    }

    private PrivateKey getPrivateKeyObject(
            final byte[] keyId,
            final char[] keyLabel)
    throws P11TokenException {
        return (PrivateKey) getKeyObject(new PrivateKey(), keyId, keyLabel);
    }

    private PublicKey getPublicKeyObject(
            final byte[] keyId,
            final char[] keyLabel)
    throws P11TokenException {
        return (PublicKey) getKeyObject(new PublicKey(), keyId, keyLabel);
    }

    private Key getKeyObject(
            final Key template,
            final byte[] keyId,
            final char[] keyLabel)
    throws P11TokenException {
        Session session = borrowIdleSession();

        try {
            if (keyId != null) {
                template.getId().setByteArrayValue(keyId);
            }
            if (keyLabel != null) {
                template.getLabel().setCharArrayValue(keyLabel);
            }

            List<Storage> tmpObjects = getObjects(session, template, 2);
            if (CollectionUtil.isEmpty(tmpObjects)) {
                return null;
            }
            int size = tmpObjects.size();
            if (size > 1) {
                LOG.warn("found {} public key identified by {}, use the first one",
                        size, getDescription(keyId, keyLabel));
            }

            return (Key) tmpObjects.get(0);
        } finally {
            returnIdleSession(session);
        }
    }

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

    private static List<Storage> getObjects(
            final Session session,
            final Storage template)
    throws P11TokenException {
        return getObjects(session, template, 9999);
    }

    private static List<Storage> getObjects(
            final Session session,
            final Storage template,
            final int maxNo)
    throws P11TokenException {
        List<Storage> objList = new LinkedList<>();

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
                    objList.add((Storage) object);
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
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
            try {
                return KeyUtil.generateRSAPublicKey(keySpec);
            } catch (InvalidKeySpecException ex) {
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
                return KeyUtil.generateDSAPublicKey(keySpec);
            } catch (InvalidKeySpecException ex) {
                throw new SecurityException(ex.getMessage(), ex);
            }
        } else if (p11Key instanceof ECDSAPublicKey) {
            ECDSAPublicKey ecP11Key = (ECDSAPublicKey) p11Key;
            byte[] encodedAlgorithmIdParameters = ecP11Key.getEcdsaParams().getByteArrayValue();
            byte[] encodedPoint = DEROctetString.getInstance(
                    ecP11Key.getEcPoint().getByteArrayValue()).getOctets();
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
        String labelStr = "";
        if (charArrayAttr != null) {
            char[] chars = charArrayAttr.getCharArrayValue();
            if (chars != null) {
                labelStr = new String(chars);
            }
        }
        return labelStr;
    }

    private static X509Cert parseCert(
            final X509PublicKeyCertificate p11Cert)
    throws P11TokenException {
        try {
            byte[] encoded = p11Cert.getValue().getByteArrayValue();
            return new X509Cert(X509Util.parseCert(encoded), encoded);
        } catch (CertificateException | IOException ex) {
            throw new P11TokenException("could not parse certificate: " + ex.getMessage(), ex);
        }
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
        login(writableSession);
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
        X509PublicKeyCertificate template = new X509PublicKeyCertificate();
        Session session = borrowIdleSession();
        List<Storage> tmpObjects;
        try {
            tmpObjects = getObjects(session, template);
        } finally {
            returnIdleSession(session);
        }

        List<X509PublicKeyCertificate> certs = new ArrayList<>(tmpObjects.size());
        for (iaik.pkcs.pkcs11.objects.Object tmpObject : tmpObjects) {
            X509PublicKeyCertificate cert = (X509PublicKeyCertificate) tmpObject;
            certs.add(cert);
        }
        return certs;
    }

    @Override
    public int removeObjects(
            final String label)
    throws P11TokenException {
        ParamUtil.requireNonBlank("label", label);
        Storage template = new Storage();
        template.getLabel().setCharArrayValue(label.toCharArray());
        Session session = borrowWritableSession();
        try {
            List<Storage> objects = getObjects(session, template);
            for (Storage obj : objects) {
                session.destroyObject(obj);
            }
            return objects.size();
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        } finally {
            returnWritableSession(session);
        }
    }

    @Override
    protected void doRemoveCerts(
            final P11ObjectIdentifier objectId)
    throws P11TokenException {
        X509PublicKeyCertificate[] existingCerts = getCertificateObjects(objectId.getId(),
                objectId.getLabelChars());
        if (existingCerts == null || existingCerts.length == 0) {
            LOG.warn("could not find certificates " + objectId);
            return;
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

    @Override
    protected void doAddCert(
            final P11ObjectIdentifier objectId,
            final X509Certificate cert)
    throws P11TokenException, SecurityException {
        X509PublicKeyCertificate newCaCertTemp = createPkcs11Template(
                new X509Cert(cert), objectId.getId(), objectId.getLabelChars());
        Session session = borrowWritableSession();
        try {
            session.createObject(newCaCertTemp);
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        } finally {
            returnWritableSession(session);
        }
    }

    @Override
    protected P11Identity doGenerateRSAKeypair(
            final int keysize,
            final BigInteger publicExponent,
            final String label)
    throws P11TokenException {
        RSAPrivateKey privateKey = new RSAPrivateKey();
        RSAPublicKey publicKey = new RSAPublicKey();
        setKeyAttributes(label, P11Constants.CKK_RSA, publicKey, privateKey);

        publicKey.getModulusBits().setLongValue((long) keysize);
        if (publicExponent != null) {
            publicKey.getPublicExponent().setByteArrayValue(publicExponent.toByteArray());
        }

        return generateKeyPair(P11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN, privateKey, publicKey);
    }

    @Override
    protected P11Identity doGenerateDSAKeypair(
            final BigInteger p, // CHECKSTYLE:SKIP
            final BigInteger q, // CHECKSTYLE:SKIP
            final BigInteger g, // CHECKSTYLE:SKIP
            final String label)
    throws P11TokenException {
        DSAPrivateKey privateKey = new DSAPrivateKey();
        DSAPublicKey publicKey = new DSAPublicKey();
        setKeyAttributes(label, P11Constants.CKK_DSA, publicKey, privateKey);

        publicKey.getPrime().setByteArrayValue(p.toByteArray());
        publicKey.getSubprime().setByteArrayValue(q.toByteArray());
        publicKey.getBase().setByteArrayValue(g.toByteArray());
        return generateKeyPair(P11Constants.CKM_DSA_KEY_PAIR_GEN, privateKey, publicKey);
    }

    @Override
    protected P11Identity doGenerateECKeypair(
            final ASN1ObjectIdentifier curveId,
            final String label)
    throws P11TokenException {
        ECDSAPrivateKey privateKey = new ECDSAPrivateKey();
        ECDSAPublicKey publicKey = new ECDSAPublicKey();
        setKeyAttributes(label, P11Constants.CKK_EC, publicKey, privateKey);
        byte[] encodedCurveId;
        try {
            encodedCurveId = curveId.getEncoded();
        } catch (IOException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }
        try {
            publicKey.getEcdsaParams().setByteArrayValue(encodedCurveId);
            return generateKeyPair(P11Constants.CKM_EC_KEY_PAIR_GEN, privateKey, publicKey);
        } catch (P11TokenException ex) {
            X9ECParameters ecParams = ECNamedCurveTable.getByOID(curveId);
            if (ecParams == null) {
                throw new IllegalArgumentException("could not ge X9ECParameters for curve "
                        + curveId.getId());
            }

            try {
                publicKey.getEcdsaParams().setByteArrayValue(ecParams.getEncoded());
            } catch (IOException ex2) {
                throw new P11TokenException(ex.getMessage(), ex);
            }
            return generateKeyPair(P11Constants.CKM_EC_KEY_PAIR_GEN, privateKey, publicKey);
        }
    }

    private P11Identity generateKeyPair(
            final long mech,
            final PrivateKey privateKey,
            final PublicKey publicKey)
    throws P11TokenException {
        final String label = toString(privateKey.getLabel());
        KeyPair keypair;
        byte[] id;

        Session session = borrowWritableSession();
        try {
            if (labelExists(session, label)) {
                throw new IllegalArgumentException(
                        "label " + label + " exists, please specify another one");
            }

            id = generateKeyId(session);
            privateKey.getId().setByteArrayValue(id);
            publicKey.getId().setByteArrayValue(id);
            try {
                keypair = session.generateKeyPair(Mechanism.get(mech), publicKey, privateKey);
            } catch (TokenException ex) {
                throw new P11TokenException(
                        "could not generate keypair " + P11Constants.getMechanismName(mech), ex);
            }
        } finally {
            returnWritableSession(session);
        }

        P11ObjectIdentifier objId = new P11ObjectIdentifier(id, label);
        P11EntityIdentifier entityId = new P11EntityIdentifier(slotId, objId);
        java.security.PublicKey jcePublicKey;
        try {
            jcePublicKey = generatePublicKey(keypair.getPublicKey());
        } catch (SecurityException ex) {
            throw new P11TokenException("could not generate public key " + objId, ex);
        }

        PrivateKey privateKey2 = getPrivateKeyObject(id, label.toCharArray());
        if (privateKey2 == null) {
            throw new P11TokenException("could not read the generated privateKey");
        }
        return new IaikP11Identity(this, entityId, privateKey2, jcePublicKey, null);
    }

    private static X509PublicKeyCertificate createPkcs11Template(
            final X509Cert cert,
            final byte[] keyId,
            final char[] label) {
        if (label == null || label.length == 0) {
            throw new IllegalArgumentException("label must not be null or empty");
        }

        X509PublicKeyCertificate newCertTemp = new X509PublicKeyCertificate();
        newCertTemp.getId().setByteArrayValue(keyId);
        newCertTemp.getLabel().setCharArrayValue(label);
        newCertTemp.getToken().setBooleanValue(true);
        newCertTemp.getCertificateType().setLongValue(CertificateType.X_509_PUBLIC_KEY);
        newCertTemp.getSubject().setByteArrayValue(
                cert.getCert().getSubjectX500Principal().getEncoded());
        newCertTemp.getIssuer().setByteArrayValue(
                cert.getCert().getIssuerX500Principal().getEncoded());
        newCertTemp.getSerialNumber().setByteArrayValue(
                cert.getCert().getSerialNumber().toByteArray());
        newCertTemp.getValue().setByteArrayValue(cert.getEncodedCert());
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
    protected void doUpdateCertificate(
            final P11ObjectIdentifier objectId,
            final X509Certificate newCert)
    throws SecurityException, P11TokenException {
        removeCerts(objectId);
        try {
            Thread.sleep(1000);
        } catch (InterruptedException ex) {
            // CHECKSTYLE:SKIP
        }

        X509PublicKeyCertificate newCertTemp = createPkcs11Template(new X509Cert(newCert),
                objectId.getId(), objectId.getLabelChars());

        Session session = borrowWritableSession();
        try {
            session.createObject(newCertTemp);
        } catch (TokenException ex) {
            throw new P11TokenException("could not createObject: " + ex.getMessage(), ex);
        } finally {
            returnWritableSession(session);
        }
    }

    private X509PublicKeyCertificate[] getCertificateObjects(
            final byte[] keyId,
            final char[] keyLabel)
    throws P11TokenException {
        X509PublicKeyCertificate template = new X509PublicKeyCertificate();
        if (keyId != null) {
            template.getId().setByteArrayValue(keyId);
        }
        if (keyLabel != null) {
            template.getLabel().setCharArrayValue(keyLabel);
        }

        List<Storage> tmpObjects;
        Session session = borrowIdleSession();
        try {
            tmpObjects = getObjects(session, template);
        } finally {
            returnIdleSession(session);
        }

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
    }

    @Override
    protected void doRemoveIdentity(
            P11ObjectIdentifier objectId)
    throws P11TokenException {
        PrivateKey privKey = getPrivateKeyObject(objectId.getId(), objectId.getLabelChars());
        PublicKey pubKey = getPublicKeyObject(objectId.getId(), objectId.getLabelChars());
        X509PublicKeyCertificate[] certs = getCertificateObjects(objectId.getId(),
                objectId.getLabelChars());

        Session session = borrowWritableSession();
        try {
            if (privKey != null) {
                try {
                    session.destroyObject(privKey);
                } catch (TokenException ex) {
                    throw new P11TokenException("could not delete private key " + objectId);
                }
            }

            if (pubKey != null) {
                try {
                    session.destroyObject(pubKey);
                } catch (TokenException ex) {
                    throw new P11TokenException("could not delete public key " + objectId);
                }
            }

            if (certs != null && certs.length > 0) {
                for (int i = 0; i < certs.length; i++) {
                    try {
                        session.destroyObject(certs[i]);
                    } catch (TokenException ex) {
                        throw new P11TokenException("could not delete certificate " + objectId);
                    }
                }
            }
        } finally {
            returnWritableSession(session);
        }
    }

    private static byte[] generateKeyId(
            @Nonnull final Session session)
    throws P11TokenException {
        SecureRandom random = new SecureRandom();
        byte[] keyId = null;
        do {
            keyId = new byte[8];
            random.nextBytes(keyId);
        } while (idExists(session, keyId));

        return keyId;
    }

    private static boolean idExists(
            @Nonnull final Session session,
            @Nonnull final byte[] keyId)
    throws P11TokenException {
        Key key = new Key();
        key.getId().setByteArrayValue(keyId);

        Object[] objects;
        try {
            session.findObjectsInit(key);
            objects = session.findObjects(1);
            session.findObjectsFinal();
            if (objects.length > 0) {
                return true;
            }

            X509PublicKeyCertificate cert = new X509PublicKeyCertificate();
            cert.getId().setByteArrayValue(keyId);

            session.findObjectsInit(cert);
            objects = session.findObjects(1);
            session.findObjectsFinal();
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }

        return objects.length > 0;
    }

    private static boolean labelExists(
            @Nonnull final Session session,
            @Nonnull final String keyLabel)
    throws P11TokenException {
        ParamUtil.requireNonBlank("keyLabel", keyLabel);
        Key key = new Key();
        key.getLabel().setCharArrayValue(keyLabel.toCharArray());

        Object[] objects;
        try {
            session.findObjectsInit(key);
            objects = session.findObjects(1);
            session.findObjectsFinal();
            if (objects.length > 0) {
                return true;
            }

            X509PublicKeyCertificate cert = new X509PublicKeyCertificate();
            cert.getLabel().setCharArrayValue(keyLabel.toCharArray());

            session.findObjectsInit(cert);
            objects = session.findObjects(1);
            session.findObjectsFinal();
        } catch (TokenException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }

        return objects.length > 0;
    }

}
