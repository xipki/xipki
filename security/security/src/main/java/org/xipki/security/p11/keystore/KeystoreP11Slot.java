/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.security.p11.keystore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.naming.OperationNotSupportedException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.security.CmpUtf8Pairs;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.SecurityUtil;
import org.xipki.common.util.X509Util;
import org.xipki.password.api.PasswordResolverException;
import org.xipki.security.P12KeypairGenerator;
import org.xipki.security.P12KeypairGenerator.ECDSAIdentityGenerator;
import org.xipki.security.api.P12KeypairGenerationResult;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11Identity;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11KeypairGenerationResult;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.api.p11.P11WritableSlot;

/**
 * @author Lijun Liao
 */

public class KeystoreP11Slot implements P11WritableSlot
{
    private static Logger LOG = LoggerFactory.getLogger(KeystoreP11Slot.class);

    private final File slotDir;

    private final P11SlotIdentifier slotId;
    private final List<KeystoreP11Identity> identities = new LinkedList<>();
    private final char[] password;

    public static byte[] deriveKeyIdFromLabel(
            final String keyLabel)
    {
        byte[] keyLabelBytes;
        try
        {
            keyLabelBytes = keyLabel.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e)
        {
            keyLabelBytes = keyLabel.getBytes();
        }

        String sha1Fp = SecurityUtil.sha1sum(keyLabelBytes);
        return Hex.decode(sha1Fp.substring(0, 16));
    }

    public KeystoreP11Slot(
            final File slotDir,
            final P11SlotIdentifier slotId,
            final List<char[]> password)
    {
        ParamUtil.assertNotNull("slotDir", slotDir);
        ParamUtil.assertNotNull("slotId", slotId);
        if(password == null)
        {
            throw new IllegalArgumentException("no password is configured");
        }
        else if(password.size() != 1)
        {
            throw new IllegalArgumentException("exactly 1 password must be specified, but not " + password.size());
        }

        this.slotDir = slotDir;
        this.slotId = slotId;
        this.password = password.get(0);

        refresh();
    }

    public synchronized void refresh()
    {
        File[] keystoreFiles = slotDir.listFiles(new FilenameFilter()
        {
            @Override
            public boolean accept(
                    final File dir,
                    final String name)
            {
                return name.endsWith(".p12");
            }
        });

        if(keystoreFiles == null || keystoreFiles.length == 0)
        {
            LOG.info("no key found in directory {}", slotDir);
            return;
        }

        Set<KeystoreP11Identity> currentIdentifies = new HashSet<>();

        for(File file : keystoreFiles)
        {
            try
            {
                LOG.info("parsing file {}", file.getPath());
                String fn = file.getName();
                String keyLabel = fn.substring(0, fn.length() - ".p12".length());

                P11KeyIdentifier keyId = new P11KeyIdentifier(deriveKeyIdFromLabel(keyLabel), keyLabel);
                KeystoreP11Identity existingP11Identify = getIdentity(keyId);

                byte[] contentBytes = IoUtil.read(file);
                String sha1sum = SecurityUtil.sha1sum(contentBytes);
                if(existingP11Identify != null && existingP11Identify.getSha1Sum().equals(sha1sum))
                {
                    currentIdentifies.add(existingP11Identify);
                    continue;
                }

                KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
                ks.load(new FileInputStream(file), password);

                String keyname = null;
                Enumeration<String> aliases = ks.aliases();
                while(aliases.hasMoreElements())
                {
                    String alias = aliases.nextElement();
                    if(ks.isKeyEntry(alias))
                    {
                        keyname = alias;
                        break;
                    }
                }

                if(keyname == null)
                {
                    LOG.info("no key is contained in file {}, ignore it", fn);
                    continue;
                }

                PrivateKey privKey = (PrivateKey) ks.getKey(keyname, password);

                if( (privKey instanceof RSAPrivateKey || privKey instanceof DSAPrivateKey ||
                        privKey instanceof ECPrivateKey) == false)
                {
                    throw new SignerException("unsupported key " + privKey.getClass().getName());
                }

                Set<Certificate> caCerts = new HashSet<>();

                X509Certificate cert = (X509Certificate) ks.getCertificate(keyname);
                Certificate[] certsInKeystore = ks.getCertificateChain(keyname);
                if(certsInKeystore.length > 1)
                {
                    for(int i = 1; i < certsInKeystore.length; i++)
                    {
                        caCerts.add(certsInKeystore[i]);
                    }
                }

                X509Certificate[] certificateChain = X509Util.buildCertPath(cert, caCerts);
                KeystoreP11Identity p11Identity = new KeystoreP11Identity(
                        sha1sum, slotId,
                        keyId, privKey, certificateChain, 20);
                currentIdentifies.add(p11Identity);
            }catch(Throwable t)
            {
                final String message = "could not initialize key " + file.getPath();
                if(LOG.isWarnEnabled())
                {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
                }
                LOG.debug(message, t);
            }
        }

        this.identities.clear();
        this.identities.addAll(currentIdentifies);
        currentIdentifies.clear();
    }

    public File getSlotDir()
    {
        return slotDir;
    }

    public P11SlotIdentifier getSlotId()
    {
        return slotId;
    }

    @Override
    public List<? extends P11Identity> getP11Identities()
    {
        return Collections.unmodifiableList(identities);
    }

    public boolean labelExists(String label)
    {
        for(KeystoreP11Identity id : identities)
        {
            if(id.getKeyId().getKeyLabel().equals(label))
            {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean removeKeyAndCerts(
            final P11KeyIdentifier keyIdentifier)
    throws SignerException
    {
        ParamUtil.assertNotNull("keyIdentifier", keyIdentifier);

        KeystoreP11Identity identity = getIdentity(keyIdentifier);
        if(identity == null)
        {
            return false;
        }
        File file = new File(slotDir, identity.getKeyId().getKeyLabel() + ".p12");
        file.delete();
        return true;
    }

    @Override
    public void updateCertificate(
            final P11KeyIdentifier keyIdentifier,
            final X509Certificate newCert,
            final Set<X509Certificate> caCerts,
            final SecurityFactory securityFactory)
    throws Exception
    {
        ParamUtil.assertNotNull("keyIdentifier", keyIdentifier);
        ParamUtil.assertNotNull("newCert", newCert);

        KeystoreP11Identity identity = getIdentity(keyIdentifier);
        if(identity == null)
        {
            throw new SignerException("could not find identity " + keyIdentifier);
        }

        assertMatch(newCert, keyIdentifier, securityFactory);

        File file = new File(slotDir, identity.getKeyId().getKeyLabel() + ".p12");
        KeyStore ks;

        FileInputStream fIn = null;
        try
        {
            fIn = new FileInputStream(file);
            ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(fIn, password);
        }finally
        {
            if(fIn != null)
            {
                fIn.close();
            }
        }

        String keyname = null;
        Enumeration<String> aliases = ks.aliases();
        while(aliases.hasMoreElements())
        {
            String alias = aliases.nextElement();
            if(ks.isKeyEntry(alias))
            {
                keyname = alias;
                break;
            }
        }

        if(keyname == null)
        {
            throw new SignerException("could not find private key");
        }

        Key key = ks.getKey(keyname, password);
        X509Certificate[] certChain = X509Util.buildCertPath(newCert, caCerts);

        ks.setKeyEntry(keyname, key, password, certChain);

        FileOutputStream fOut = null;
        try
        {
            fOut = new FileOutputStream(file);
            ks.store(fOut, password);
        }finally
        {
            if(fOut != null)
            {
                fOut.close();
            }
        }
    }

    @Override
    public void removeCerts(
            final P11KeyIdentifier keyIdentifier)
    throws Exception
    {
        throw new OperationNotSupportedException("removeCerts(P11KeyIdentifier) is unsupported");
    }

    @Override
    public P11KeyIdentifier addCert(
            final X509Certificate cert)
    throws Exception
    {
        throw new OperationNotSupportedException("addCert(X509Certificate) is unsupported");
    }

    @Override
    public P11KeypairGenerationResult generateRSAKeypairAndCert(
            final int keySize,
            final BigInteger publicExponent,
            final String label,
            final String subject,
            final Integer keyUsage,
            final List<ASN1ObjectIdentifier> extendedKeyusage)
    throws Exception
    {
        ParamUtil.assertNotBlank("label", label);

        if (keySize < 1024)
        {
            throw new IllegalArgumentException("keysize not allowed: " + keySize);
        }

        if(keySize % 1024 != 0)
        {
            throw new IllegalArgumentException("key size is not multiple of 1024: " + keySize);
        }

        if(labelExists(label))
        {
            throw new IllegalArgumentException("label " + label + " exists, please specify another one");
        }

        P12KeypairGenerator gen = new P12KeypairGenerator.RSAIdentityGenerator(
                keySize, publicExponent, password, subject,
                keyUsage, extendedKeyusage);

        P12KeypairGenerationResult keyAndCert = gen.generateIdentity();

        File file = new File(slotDir, label + ".p12");
        IoUtil.save(file, keyAndCert.getKeystore());

        return new P11KeypairGenerationResult(KeystoreP11Slot.deriveKeyIdFromLabel(label), label,
                keyAndCert.getCertificate());
    }

    @Override
    public P11KeypairGenerationResult generateDSAKeypairAndCert(
            final int pLength,
            final int qLength,
            final String label,
            final String subject,
            final Integer keyUsage,
            final List<ASN1ObjectIdentifier> extendedKeyusage)
    throws Exception
    {
        ParamUtil.assertNotBlank("label", label);

        if (pLength < 1024)
        {
            throw new IllegalArgumentException("keysize not allowed: " + pLength);
        }

        if(pLength % 1024 != 0)
        {
            throw new IllegalArgumentException("key size is not multiple of 1024: " + pLength);
        }

        if(labelExists(label))
        {
            throw new IllegalArgumentException("label " + label + " exists, please specify another one");
        }

        P12KeypairGenerator gen = new P12KeypairGenerator.DSAIdentityGenerator(
                pLength, qLength, password, subject,
                keyUsage, extendedKeyusage);

        P12KeypairGenerationResult keyAndCert = gen.generateIdentity();

        File file = new File(slotDir, label + ".p12");
        IoUtil.save(file, keyAndCert.getKeystore());

        return new P11KeypairGenerationResult(KeystoreP11Slot.deriveKeyIdFromLabel(label), label,
                keyAndCert.getCertificate());
    }

    @Override
    public P11KeypairGenerationResult generateECDSAKeypairAndCert(
            final String curveNameOrOid,
            final String label,
            final String subject,
            final Integer keyUsage,
            final List<ASN1ObjectIdentifier> extendedKeyusage)
    throws Exception
    {
        ParamUtil.assertNotBlank("curveNameOrOid", curveNameOrOid);
        ParamUtil.assertNotBlank("label", label);

        if(labelExists(label))
        {
            throw new IllegalArgumentException("label " + label + " exists, please specify another one");
        }

        ECDSAIdentityGenerator gen = new P12KeypairGenerator.ECDSAIdentityGenerator(
                curveNameOrOid, password, subject, keyUsage, extendedKeyusage);
        P12KeypairGenerationResult keyAndCert = gen.generateIdentity();

        File file = new File(slotDir, label + ".p12");
        IoUtil.save(file, keyAndCert.getKeystore());

        return new P11KeypairGenerationResult(KeystoreP11Slot.deriveKeyIdFromLabel(label), label,
                keyAndCert.getCertificate());
    }

    private KeystoreP11Identity getIdentity(
            final P11KeyIdentifier keyIdentifier)
    {
        byte[] keyId = keyIdentifier.getKeyId();
        String keyLabel = keyIdentifier.getKeyLabel();

        if(keyId == null)
        {
            for(KeystoreP11Identity p11Identity : identities)
            {
                if(p11Identity.getKeyId().getKeyLabel().equals(keyLabel))
                {
                    return p11Identity;
                }
            }
        }else if(keyLabel == null)
        {
            for(KeystoreP11Identity p11Identity : identities)
            {
                if(Arrays.equals(p11Identity.getKeyId().getKeyId(), keyId))
                {
                    return p11Identity;
                }
            }
        }
        else
        {
            for(KeystoreP11Identity p11Identity : identities)
            {
                if(p11Identity.getKeyId().getKeyLabel().equals(keyLabel))
                {
                    if(Arrays.equals(p11Identity.getKeyId().getKeyId(), keyId))
                    {
                        return p11Identity;
                    }
                }
            }
        }

        return null;
    }

    private void assertMatch(
            final X509Certificate cert,
            final P11KeyIdentifier keyId,
            final SecurityFactory securityFactory)
    throws SignerException, PasswordResolverException
    {
        CmpUtf8Pairs pairs = new CmpUtf8Pairs("slot", Integer.toString(slotId.getSlotIndex()));
        if(keyId.getKeyId() != null)
        {
            pairs.putUtf8Pair("key-id", Hex.toHexString(keyId.getKeyId()));
        }
        if(keyId.getKeyLabel() != null)
        {
            pairs.putUtf8Pair("key-label", keyId.getKeyLabel());
        }

        securityFactory.createSigner("PKCS11", pairs.getEncoded(), "SHA1", null, cert);
    }

    @Override
    public X509Certificate exportCert(
            final P11KeyIdentifier keyIdentifier)
    throws Exception
    {
        KeystoreP11Identity identity = getIdentity(keyIdentifier);
        return identity == null ? null : identity.getCertificate();
    }
}
