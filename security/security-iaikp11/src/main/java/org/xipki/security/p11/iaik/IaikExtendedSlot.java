/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.security.p11.iaik;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.SessionInfo;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.State;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.ByteArrayAttribute;
import iaik.pkcs.pkcs11.objects.CharArrayAttribute;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.objects.Certificate.CertificateType;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.LogUtil;

/**
 * @author Lijun Liao
 */

public class IaikExtendedSlot
{
    private static final Logger LOG = LoggerFactory.getLogger(IaikExtendedSlot.class);

    private final static long DEFAULT_MAX_COUNT_SESSION = 20;
    private Slot slot;
    private final int maxSessionCount;
    private char[] password;

    private long timeOutWaitNewSession = 10000; // maximal wait for 10 second
    private AtomicLong countSessions = new AtomicLong(0);
    private BlockingQueue<Session> idleSessions = new LinkedBlockingDeque<>();

    private ConcurrentHashMap<String, PrivateKey> signingKeysById = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, PrivateKey> signingKeysByLabel = new ConcurrentHashMap<>();

    private boolean writableSessionInUse = false;
    private Session writableSession;

    IaikExtendedSlot(Slot slot, char[] password)
    throws SignerException
    {
        this.slot = slot;
        this.password = password;

        Session session;
        try
        {
            session = openSession();
        } catch (TokenException e)
        {
            LogUtil.logWarnThrowable(LOG, "openSession", e);
            close();
            throw new SignerException(e);
        }

        try
        {
            firstLogin(session, password);
        } catch (TokenException e)
        {
            LogUtil.logWarnThrowable(LOG, "firstLogin", e);
            close();
            throw new SignerException(e);
        }

        long maxSessionCount2 = 1;
        try
        {
            maxSessionCount2 = this.slot.getToken().getTokenInfo().getMaxSessionCount();
        } catch (TokenException e)
        {
            LogUtil.logWarnThrowable(LOG, "getToken", e);
        }

        if(maxSessionCount2 == 0)
        {
            maxSessionCount2 = DEFAULT_MAX_COUNT_SESSION;
        }
        else
        {
            // 2 sessions as buffer, they may be used elsewhere.
            maxSessionCount2 = maxSessionCount2 < 3 ? 1 : maxSessionCount2 - 2;
        }

        this.maxSessionCount = (int) maxSessionCount2;

        LOG.info("maxSessionCount: {}", this.maxSessionCount);

        returnIdleSession(session);
    }

    public byte[] CKM_ECDSA(byte[] hash, Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        PrivateKey signatureKey = getSigningKey(keyId);
        if(signatureKey == null)
        {
            throw new SignerException("No key for signing is available");
        }

        Session session = borrowIdleSession();
        if(session == null)
        {
            throw new SignerException("No idle session available");
        }

        try
        {
            Mechanism algorithmId = Mechanism.get(PKCS11Constants.CKM_ECDSA);

            if(LOG.isTraceEnabled())
            {
                LOG.debug("sign with private key:\n{}", signatureKey);
            }

            synchronized (session)
            {
                login(session);
                session.signInit(algorithmId, signatureKey);
                byte[] signature = session.sign(hash);
                if (LOG.isDebugEnabled())
                {
                    LOG.debug("signature:\n{}", Hex.toHexString(signature));
                }
                return signature;
            }
        } catch (TokenException e)
        {
            throw new SignerException(e);
        }finally
        {
            returnIdleSession(session);
        }
    }

    public byte[] CKM_RSA_PKCS(byte[] encodedDigestInfo, Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        PrivateKey signatureKey = getSigningKey(keyId);

        if(signatureKey == null)
        {
            throw new SignerException("No key for signing is available");
        }

        Session session = borrowIdleSession();
        if(session == null)
        {
            throw new SignerException("No idle session available");
        }

        try
        {
            Mechanism algorithmId = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS);

            if(LOG.isTraceEnabled())
            {
                LOG.debug("sign with private key:\n{}", signatureKey);
            }

            synchronized (session)
            {
                login(session);
                session.signInit(algorithmId, signatureKey);
                byte[] signature = session.sign(encodedDigestInfo);
                if (LOG.isDebugEnabled())
                {
                    LOG.debug("signature:\n{}", Hex.toHexString(signature));
                }
                return signature;
            }
        } catch (TokenException e)
        {
            throw new SignerException(e);
        }finally
        {
            returnIdleSession(session);
        }
    }

    public byte[] CKM_RSA_X509(byte[] hash, Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        PrivateKey signatureKey = getSigningKey(keyId);

        if(signatureKey == null)
        {
            throw new SignerException("No key for signing is available");
        }

        Session session = borrowIdleSession();
        if(session == null)
        {
            throw new SignerException("No idle session available");
        }

        try
        {
            Mechanism algorithmId = Mechanism.get(PKCS11Constants.CKM_RSA_X_509);

            if(LOG.isTraceEnabled())
            {
                LOG.debug("sign with private key:\n{}", signatureKey);
            }

            synchronized (session)
            {
                login(session);
                session.signInit(algorithmId, signatureKey);
                byte[] signature = session.sign(hash);
                if (LOG.isTraceEnabled())
                {
                    LOG.debug("signature:\n{}", Hex.toHexString(signature));
                }
                return signature;
            }
        } catch (TokenException e)
        {
            throw new SignerException(e);
        }finally
        {
            returnIdleSession(session);
        }
    }

    private PrivateKey getSigningKey(Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        synchronized (keyId)
        {
            PrivateKey signingKey;
            if(keyId.getKeyId() != null)
            {
                signingKey = signingKeysById.get(keyId.getKeyIdHex());
            }
            else
            {
                signingKey = signingKeysByLabel.get(keyId.getKeyLabel());
            }

            if(signingKey == null)
            {
                LOG.info("Try to retieve private key " + keyId);
                String label = keyId.getKeyLabel();
                signingKey = getPrivateObject(Boolean.TRUE, null, keyId.getKeyId(),
                        (label == null) ? null : label.toCharArray());

                if(signingKey != null)
                {
                    LOG.info("Found private key " + keyId);
                    cacheSigningKey(signingKey);
                }
                else
                {
                    LOG.warn("Could not find private key " + keyId);
                }
            }

            return signingKey;
        }
    }

    private Session openSession()
    throws TokenException
    {
        return openSession(false);
    }

    private Session openSession(boolean rwSession)
    throws TokenException
    {
        Session session = slot.getToken().openSession(
                Token.SessionType.SERIAL_SESSION, rwSession, null, null);
        countSessions.incrementAndGet();
        return session;
    }

    private void closeSession(Session session)
    throws TokenException
    {
        try
        {
            session.closeSession();
        } finally
        {
            countSessions.decrementAndGet();
        }
    }

    public synchronized Session borrowWritableSession()
    throws SignerException
    {
        if(writableSession == null)
        {
            try
            {
                writableSession = openSession(true);
            } catch (TokenException e)
            {
                throw new SignerException("Could not open writable session", e);
            }
        }

        if(writableSessionInUse)
        {
            throw new SignerException("No idle writable session available");
        }

        writableSessionInUse = true;
        return writableSession;
    }

    public synchronized void returnWritableSession(Session session)
    throws SignerException
    {
        if(session != writableSession)
        {
            throw new SignerException("The returned session does not belong to me");
        }
        this.writableSessionInUse = false;
    }

    public Session borrowIdleSession()
    throws SignerException
    {
        if(countSessions.get() < maxSessionCount)
        {
            Session session = idleSessions.poll();
            if(session == null)
            {
                // create new session
                try
                {
                    session = openSession();
                } catch (TokenException e)
                {
                    LOG.error("openSession(), TokenException: {}", e.getMessage());
                    LOG.debug("openSession()", e);
                }
            }

            if(session != null) return session;
        }

        try
        {
            return idleSessions.poll(timeOutWaitNewSession, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e)
        {
        }

        throw new SignerException("No idle session");
    }

    public void returnIdleSession(Session session)
    {
        if(session == null) return;

        for(int i = 0; i < 3; i++)
        {
            try
            {
                idleSessions.put(session);
                return;
            } catch (InterruptedException e)
            {
            }
        }

        try
        {
            closeSession(session);
        }catch(TokenException e)
        {
            LOG.error("closeSession.{}: {}", e.getClass().getName(), e.getMessage());
            LOG.debug("closeSession", e);
        }
    }

    private void firstLogin(Session session, char[] password)
    throws TokenException
    {
           boolean isProtectedAuthenticationPath =
                   session.getToken().getTokenInfo().isProtectedAuthenticationPath();

           try
           {
            if (isProtectedAuthenticationPath)
            {
                LOG.info("verify on PKCS11Module with PROTECTED_AUTHENTICATION_PATH");
                session.login(Session.UserType.USER, null);
                this.password = null;
            }
            else
            {
                LOG.info("verify on PKCS11Module with PIN");

                session.login( Session.UserType.USER, password);
                this.password = password;
            }
           }
        catch (PKCS11Exception p11e)
        {
            if(p11e.getErrorCode() != 0x100)// user already logged in
            {
                throw p11e;
            }
        }
    }

    public void login()
    throws SignerException
    {
        Session session = borrowIdleSession();
        try
        {
            login(session);
        }finally
        {
            returnIdleSession(session);
        }
    }

    private void login(Session session)
    throws SignerException
    {
        try
        {
            boolean isSessionLoggedIn = checkSessionLoggedIn(session);
            if (isSessionLoggedIn)
            {
                return;
            }
            boolean loginRequired = session.getToken().getTokenInfo().isLoginRequired();

            LOG.debug("loginRequired: {}", loginRequired);
            if (loginRequired == false)
            {
                return;
            }

            session.login( Session.UserType.USER, password);
        } catch (TokenException e)
        {
            throw new SignerException(e);
        }
    }

    private static boolean checkSessionLoggedIn(Session session)
    throws SignerException
    {
        SessionInfo info;
        try
        {
            info = session.getSessionInfo();
        } catch (TokenException e)
        {
            throw new SignerException(e);
        }
        if(LOG.isTraceEnabled())
        {
            LOG.debug("SessionInfo: {}", info);
        }

        State state = info.getState();
        long deviceError = info.getDeviceError();

        LOG.debug("to be verified PKCS11Module: state = {}, deviceError: {}", state, deviceError);

        boolean isRwSessionLoggedIn = state.equals(State.RW_USER_FUNCTIONS);
        boolean isRoSessionLoggedIn = state.equals(State.RO_USER_FUNCTIONS);

        boolean sessionSessionLoggedIn = ((isRoSessionLoggedIn || isRwSessionLoggedIn) && deviceError == 0);
        LOG.debug("sessionSessionLoggedIn: {}", sessionSessionLoggedIn);
        return sessionSessionLoggedIn;
    }

    public void close()
    {
        if(slot != null)
        {
            try
            {
                LOG.info("close all sessions on token: {}", slot.getSlotID());
                slot.getToken().closeAllSessions();
            }
            catch (Throwable t)
            {
                LogUtil.logErrorThrowable(LOG, "error while slot.getToken().closeAllSessions()", t);
            }

            slot = null;
        }

        // clear the session pool
        idleSessions.clear();
        countSessions.lazySet(0);
    }

    public List<PrivateKey> getAllPrivateObjects(
            Boolean forSigning, Boolean forDecrypting)
    throws SignerException
    {
        Session session = borrowIdleSession();

        try
        {
            if(LOG.isTraceEnabled())
            {
                String info = listPrivateKeyObjects(session, forSigning, forDecrypting);
                LOG.debug(info);
            }

            PrivateKey template = new PrivateKey();
            if(forSigning != null)
            {
                template.getSign().setBooleanValue(forSigning);
            }
            if(forDecrypting != null)
            {
                template.getDecrypt().setBooleanValue(forDecrypting);
            }

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            if(tmpObjects == null || tmpObjects.isEmpty())
            {
                return Collections.emptyList();
            }

            int n = tmpObjects.size();
            LOG.info("found {} private keys", n);

            List<PrivateKey> privateKeys = new ArrayList<>(n);
            for(iaik.pkcs.pkcs11.objects.Object tmpObject : tmpObjects)
            {
                PrivateKey privateKey = (PrivateKey) tmpObject;
                privateKeys.add(privateKey);
                cacheSigningKey(privateKey);
            }

            return privateKeys;
        }finally
        {
            returnIdleSession(session);
        }
    }

    public List<X509PublicKeyCertificate> getAllCertificateObjects()
    throws SignerException
    {
        Session session = borrowIdleSession();

        try
        {
            if(LOG.isTraceEnabled())
            {
                String info = listCertificateObjects(session);
                LOG.debug(info);
            }

            X509PublicKeyCertificate template = new X509PublicKeyCertificate();
            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            int n = tmpObjects.size();

            List<X509PublicKeyCertificate> certs = new ArrayList<>(n);
            for(iaik.pkcs.pkcs11.objects.Object tmpObject : tmpObjects)
            {
                X509PublicKeyCertificate cert = (X509PublicKeyCertificate) tmpObject;
                certs.add(cert);
            }

            return certs;
        }finally
        {
            returnIdleSession(session);
        }

    }

    private void cacheSigningKey(PrivateKey privateKey)
    {
        Boolean b = privateKey.getSign().getBooleanValue();
        byte[] id = privateKey.getId().getByteArrayValue();
        char[] _label = privateKey.getLabel().getCharArrayValue();
        String label = (_label == null) ? null : new String(_label);

        if(b == null || b.booleanValue() == false)
        {
            LOG.warn("key {} is not for signing", new Pkcs11KeyIdentifier(id, label));
            return;
        }

        if(b != null && b.booleanValue())
        {
            if(id != null)
            {
                signingKeysById.put(Hex.toHexString(id).toUpperCase(), privateKey);
            }
            if(label != null)
            {
                signingKeysByLabel.put(label, privateKey);
            }
        }
    }

    public PrivateKey getPrivateObject(
            Boolean forSigning, Boolean forDecrypting, byte[] keyId, char[] keyLabel)
    throws SignerException
    {
        Session session = borrowIdleSession();

        try
        {
            if(LOG.isTraceEnabled())
            {
                String info = listPrivateKeyObjects(session, forSigning, forDecrypting);
                LOG.debug(info);
            }

            PrivateKey template = new PrivateKey();
            if(forSigning != null)
            {
                template.getSign().setBooleanValue(forSigning);
            }
            if(forDecrypting != null)
            {
                template.getDecrypt().setBooleanValue(forDecrypting);
            }
            if(keyId != null)
            {
                template.getId().setByteArrayValue(keyId);
            }
            if(keyLabel != null)
            {
                template.getLabel().setCharArrayValue(keyLabel);
            }

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            if(tmpObjects == null || tmpObjects.isEmpty())
            {
                return null;
            }

            int size = tmpObjects.size();
            if(size > 1)
            {
                LOG.warn("found {} private key identified by {}, use the first one",
                        size, getDescription(keyId, keyLabel));
            }
            return (PrivateKey) tmpObjects.get(0);
        }finally
        {
            returnIdleSession(session);
        }
    }

    public String listPrivateKeyObjects()
    {
        Session session;
        try
        {
            session = borrowIdleSession();
        } catch (SignerException e)
        {
            return "Exception: " + e.getMessage();
        }

        try
        {
            return listPrivateKeyObjects(session, null, null);
        }
        finally
        {
            returnIdleSession(session);
        }
    }

    private String listPrivateKeyObjects(Session session, Boolean forSigning, Boolean forDecrypting)
    {
        try
        {
            StringBuilder msg = new StringBuilder();
            msg.append("Available private keys: ");
            msg.append("forSigning: ").append(forSigning);
            msg.append(", forDecrypting: ").append(forDecrypting).append("\n");

            PrivateKey template = new PrivateKey();
            if(forSigning != null)
            {
                template.getSign().setBooleanValue(forSigning);
            }
            if(forDecrypting != null)
            {
                template.getDecrypt().setBooleanValue(forDecrypting);
            }
            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            if(tmpObjects == null || tmpObjects.isEmpty())
            {
                msg.append(" empty");
            }
            for(int i = 0; i < tmpObjects.size(); i++)
            {
                PrivateKey privKey = (PrivateKey) tmpObjects.get(i);
                msg.append("------------------------PrivateKey ")
                    .append(i + 1).append("-------------------------\n");

                msg.append("\tid(hex): ");
                ByteArrayAttribute id = privKey.getId();
                byte[] bytes = null;
                if(id != null)
                {
                    bytes = id.getByteArrayValue();
                }
                msg.append(bytes == null ? "null" : Hex.toHexString(bytes)).append("\n");

                msg.append("\tlabel:   ");
                CharArrayAttribute label = privKey.getLabel();
                char[] chars = null;
                if(label != null)
                {
                    chars = label.getCharArrayValue();
                }
                msg.append(chars).append("\n");
            }
            return msg.toString();
        }catch(Throwable t)
        {
            return "Exception while calling listPrivateKeyObjects(): " + t.getMessage();
        }
    }

    public PublicKey getPublicKeyObject(Boolean forSignature,
            Boolean forCipher, byte[] keyId, char[] keyLabel)
    throws SignerException
    {
        Session session = borrowIdleSession();

        try
        {
            if(LOG.isTraceEnabled())
            {
                String info = listPublicKeyObjects(session, forSignature, forCipher);
                LOG.debug(info);
            }

            iaik.pkcs.pkcs11.objects.PublicKey template = new iaik.pkcs.pkcs11.objects.PublicKey();
            if(keyId != null)
            {
                template.getId().setByteArrayValue(keyId);
            }
            if(keyLabel != null)
            {
                template.getLabel().setCharArrayValue(keyLabel);
            }

            if(forSignature != null)
            {
                template.getVerify().setBooleanValue(forSignature);
            }
            if(forCipher != null)
            {
                template.getEncrypt().setBooleanValue(forCipher);
            }

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            if(tmpObjects == null || tmpObjects.isEmpty())
            {
                return null;
            }

            int size = tmpObjects.size();
            if(size > 1)
            {
                LOG.warn("found {} public key identified by {}, use the first one",
                        size, getDescription(keyId, keyLabel));
            }

            iaik.pkcs.pkcs11.objects.PublicKey p11Key =
                    (iaik.pkcs.pkcs11.objects.PublicKey) tmpObjects.get(0);
            return p11Key;
        }finally
        {
            returnIdleSession(session);
        }
    }

    private static List<iaik.pkcs.pkcs11.objects.Object> getObjects(
            Session session,
            iaik.pkcs.pkcs11.objects.Object template)
    throws SignerException
    {
        List<iaik.pkcs.pkcs11.objects.Object> objList = new LinkedList<>();

        try
        {
            session.findObjectsInit(template);

            while(true)
            {
                iaik.pkcs.pkcs11.objects.Object[] foundObjects = session.findObjects(1);
                if(foundObjects == null || foundObjects.length == 0)
                {
                    break;
                }

                for (iaik.pkcs.pkcs11.objects.Object object : foundObjects)
                {
                    if(LOG.isTraceEnabled())
                    {
                        LOG.debug("foundObject: {}", object);
                    }
                    objList.add(object);
                }
            }
        } catch (TokenException e)
        {
            throw new SignerException(e);
        }
        finally
        {
            try
            {
                session.findObjectsFinal();
            }catch(Exception e){}
        }

        return objList;
    }

    public X509PublicKeyCertificate[] getCertificateObjects(X500Principal subject)
    throws SignerException
    {
        Session session = borrowIdleSession();

        try
        {
            if(LOG.isTraceEnabled())
            {
                String info = listCertificateObjects(session);
                LOG.debug(info);
            }

            X509PublicKeyCertificate template = new X509PublicKeyCertificate();
            template.getCertificateType().setLongValue(CertificateType.X_509_PUBLIC_KEY);
            template.getSubject().setByteArrayValue(subject.getEncoded());

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            int n = tmpObjects == null ? 0 : tmpObjects.size();
            if(n == 0)
            {
                LOG.warn("found no certificate with subject {}", IoCertUtil.canonicalizeName(subject));
                return null;
            }

            X509PublicKeyCertificate[] certs = new X509PublicKeyCertificate[n];
            for(int i = 0; i < n; i++)
            {
                certs[i] = (X509PublicKeyCertificate) tmpObjects.get(i);
            }
            return certs;
        }finally
        {
            returnIdleSession(session);
        }
    }

    public X509PublicKeyCertificate getCertificateObject(byte[] keyId, char[] keyLabel)
    throws SignerException
    {
        X509PublicKeyCertificate[] certs = getCertificateObjects(keyId, keyLabel);
        if(certs == null)
        {
            return null;
        }
        if(certs.length > 1)
        {
            LOG.warn("found {} public key identified by {}, use the first one",
                    certs.length, getDescription(keyId, keyLabel));
        }
        return certs[0];
    }

    public X509PublicKeyCertificate[] getCertificateObjects(byte[] keyId, char[] keyLabel)
    throws SignerException
    {
        Session session = borrowIdleSession();

        try
        {
            if(LOG.isTraceEnabled())
            {
                String info = listCertificateObjects(session);
                LOG.debug(info);
            }

            X509PublicKeyCertificate template = new X509PublicKeyCertificate();
            if(keyId != null)
            {
                template.getId().setByteArrayValue(keyId);
            }
            if(keyLabel != null)
            {
                template.getLabel().setCharArrayValue(keyLabel);
            }

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            if(tmpObjects == null || tmpObjects.isEmpty())
            {
                LOG.warn("found no certificate identified by {}", getDescription(keyId, keyLabel));
                return null;
            }

            int size = tmpObjects.size();
            X509PublicKeyCertificate[] certs = new X509PublicKeyCertificate[size];
            for(int i = 0; i < size; i++)
            {
                certs[i] = (X509PublicKeyCertificate) tmpObjects.get(i);
            }
            return certs;
        }finally
        {
            returnIdleSession(session);
        }
    }

    public String listCertificateObjects()
    {
        Session session;
        try
        {
            session = borrowIdleSession();
        } catch (SignerException e)
        {
            return "Exception: " + e.getMessage();
        }

        try
        {
            return listCertificateObjects(session);
        }
        finally
        {
            returnIdleSession(session);
        }
    }

    private String listCertificateObjects(Session session)
    {
        try
        {
            StringBuilder msg = new StringBuilder();
            msg.append("Available certificates: ");

            X509PublicKeyCertificate template = new X509PublicKeyCertificate();

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            if(tmpObjects == null || tmpObjects.isEmpty())
            {
                msg.append(" empty");
            }
            for(int i = 0; i<tmpObjects.size(); i++)
            {
                X509PublicKeyCertificate cert = (X509PublicKeyCertificate) tmpObjects.get(i);
                msg.append("------------------------Certificate ").append(i + 1).append("-------------------------\n");

                msg.append("\tid(hex): ");
                ByteArrayAttribute id = cert.getId();
                byte[] bytes = null;
                if(id != null)
                {
                    bytes = id.getByteArrayValue();
                }
                msg.append(bytes == null ? "null" : Hex.toHexString(bytes)).append("\n");

                msg.append("\tlabel:   ");
                CharArrayAttribute label = cert.getLabel();
                char[] chars = null;
                if(label != null)
                {
                    chars = label.getCharArrayValue();
                }
                msg.append(chars).append("\n");
            }
            return msg.toString();
        }catch(Throwable t)
        {
            return "Exception while calling listCertificateObjects(): " + t.getMessage();
        }
    }

    public String listPublicKeyObjects()
    {
        Session session;
        try
        {
            session = borrowIdleSession();
        } catch (SignerException e)
        {
            return "Exception: " + e.getMessage();
        }

        try
        {
            return listPublicKeyObjects(session, null, null);
        }
        finally
        {
            returnIdleSession(session);
        }
    }

    private String listPublicKeyObjects(Session session, Boolean forSignature, Boolean forCipher)
    {
        try
        {
            StringBuilder msg = new StringBuilder();
            msg.append("Available public keys: ");
            msg.append("forSignature: ").append(forSignature);
            msg.append(", forCipher: ").append(forCipher).append("\n");

            iaik.pkcs.pkcs11.objects.PublicKey template = new iaik.pkcs.pkcs11.objects.PublicKey();
            if(forSignature != null)
            {
                template.getVerify().setBooleanValue(forSignature);
            }
            if(forCipher != null)
            {
                template.getEncrypt().setBooleanValue(forCipher);
            }

            List<iaik.pkcs.pkcs11.objects.Object> tmpObjects = getObjects(session, template);
            if(tmpObjects == null || tmpObjects.isEmpty())
            {
                msg.append(" empty");
            }
            for(int i = 0; i < tmpObjects.size(); i++)
            {
                iaik.pkcs.pkcs11.objects.PublicKey pubKey =
                        (iaik.pkcs.pkcs11.objects.PublicKey) tmpObjects.get(i);
                msg.append("------------------------Public Key ").append(i + 1).append("-------------------------\n");
                msg.append("\tid(hex): ");
                ByteArrayAttribute id = pubKey.getId();
                byte[] bytes = null;
                if(id != null)
                {
                    bytes = id.getByteArrayValue();
                }
                msg.append(bytes == null ? "null" : Hex.toHexString(bytes)).append("\n");

                msg.append("\tlabel:   ");
                CharArrayAttribute label = pubKey.getLabel();
                char[] chars = null;
                if(label != null)
                {
                    chars = label.getCharArrayValue();
                }
                msg.append(chars).append("\n");
            }
            return msg.toString();
        }catch(Throwable t)
        {
            return "Exception while calling listPublicKeyObjects(): " + t.getMessage();
        }
    }

    private static String getDescription(byte[] keyId, char[] keyLabel)
    {
        StringBuilder sb = new StringBuilder("identified by ");
        sb.append("id ");
        sb.append(keyId == null ? "null" : Hex.toHexString(keyId));
        sb.append(" and label ");
        sb.append(keyLabel == null ? "null" : new String(keyLabel));
        return sb.toString();
    }
}
