/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.IoCertUtil;
import org.xipki.common.LogUtil;
import org.xipki.common.ParamChecker;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 */

public class KeystoreP11Slot
{
    private static Logger LOG = LoggerFactory.getLogger(KeystoreP11Slot.class);

    private final File slotDir;

    private final P11SlotIdentifier slotId;
    private final List<KeystoreP11Identity> identities = new LinkedList<>();

    public KeystoreP11Slot(File slotDir, P11SlotIdentifier slotId, List<char[]> password)
    {
        ParamChecker.assertNotNull("slotDir", slotDir);
        ParamChecker.assertNotNull("slotId", slotId);
        if(password == null)
        {
            throw new IllegalArgumentException("No password is configured");
        }
        else if(password.size() != 1)
        {
            throw new IllegalArgumentException("Exactly 1 password must be specified, but not " + password.size());
        }

        this.slotDir = slotDir;
        this.slotId = slotId;

        File[] keystoreFiles = slotDir.listFiles();
        if(keystoreFiles == null || keystoreFiles.length == 0)
        {
            LOG.info("No key found in directory", slotDir);
            return;
        }

        for(File file : keystoreFiles)
        {
            try
            {
                String fn = file.getName();
                String keyLabel;
                KeyStore ks;
                if(fn.endsWith(".p12") || fn.endsWith(".P12"))
                {
                    ks = KeyStore.getInstance("PKCS12", "BC");
                    keyLabel= fn.substring(0, fn.length() - ".p12".length());
                }
                else
                {
                    LOG.info("Ignore none keystore file {}", file.getPath());
                    continue;
                }

                String sha1Fp = IoCertUtil.sha1sum(keyLabel.getBytes("UTF-8"));
                P11KeyIdentifier keyId = new P11KeyIdentifier(Hex.decode(sha1Fp.substring(0, 16)), keyLabel);
                ks.load(new FileInputStream(file), password.get(0));

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
                    LOG.info("No key is contained in file {}, ignore it", fn);
                    continue;
                }

                PrivateKey privKey = (PrivateKey) ks.getKey(keyname, password.get(0));

                if( (privKey instanceof RSAPrivateKey || privKey instanceof DSAPrivateKey ||
                        privKey instanceof ECPrivateKey) == false)
                {
                    throw new SignerException("Unsupported key " + privKey.getClass().getName());
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

                X509Certificate[] certificateChain = IoCertUtil.buildCertPath(cert, caCerts);
                KeystoreP11Identity p11Identity = new KeystoreP11Identity(slotId,
                        keyId, privKey, certificateChain, 20);
                identities.add(p11Identity);
            }catch(Throwable t)
            {
                final String message = "Could not initialize key " + file.getPath();
                if(LOG.isWarnEnabled())
                {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
                }
                LOG.debug(message, t);
            }
        }
    }

    public File getSlotDir()
    {
        return slotDir;
    }

    public P11SlotIdentifier getSlotId()
    {
        return slotId;
    }

    public List<KeystoreP11Identity> getIdentities()
    {
        return Collections.unmodifiableList(identities);
    }

}
