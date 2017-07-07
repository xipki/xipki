/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.security.pkcs12;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.DefaultConcurrentContentSigner;
import org.xipki.security.HashAlgoType;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.KeyUtil;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class SoftTokenMacContentSignerBuilder {

    private final SecretKey key;

    public SoftTokenMacContentSignerBuilder(final SecretKey key)
            throws XiSecurityException {
        this.key = ParamUtil.requireNonNull("key", key);
    }

    public SoftTokenMacContentSignerBuilder(final String keystoreType,
            final InputStream keystoreStream, final char[] keystorePassword,
            final String keyname, final char[] keyPassword)
            throws XiSecurityException {
        if (!"JCEKS".equalsIgnoreCase(keystoreType)) {
            throw new IllegalArgumentException("unsupported keystore type: " + keystoreType);
        }
        ParamUtil.requireNonNull("keystoreStream", keystoreStream);
        ParamUtil.requireNonNull("keystorePassword", keystorePassword);
        ParamUtil.requireNonNull("keyPassword", keyPassword);

        try {
            KeyStore ks = KeyUtil.getKeyStore(keystoreType);
            ks.load(keystoreStream, keystorePassword);

            String tmpKeyname = keyname;
            if (tmpKeyname == null) {
                Enumeration<String> aliases = ks.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (ks.isKeyEntry(alias)) {
                        tmpKeyname = alias;
                        break;
                    }
                }
            } else {
                if (!ks.isKeyEntry(tmpKeyname)) {
                    throw new XiSecurityException("unknown key named " + tmpKeyname);
                }
            }

            this.key = (SecretKey) ks.getKey(tmpKeyname, keyPassword);
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException
                | CertificateException | IOException | UnrecoverableKeyException
                | ClassCastException ex) {
            throw new XiSecurityException(ex.getMessage(), ex);
        }
    }

    public ConcurrentContentSigner createSigner(final AlgorithmIdentifier signatureAlgId,
            final int parallelism, final SecureRandom random)
            throws XiSecurityException {
        ParamUtil.requireNonNull("signatureAlgId", signatureAlgId);
        ParamUtil.requireMin("parallelism", parallelism, 1);

        List<ContentSigner> signers = new ArrayList<>(parallelism);

        boolean gmac = false;
        ASN1ObjectIdentifier oid = signatureAlgId.getAlgorithm();
        if (oid.equals(NISTObjectIdentifiers.id_aes128_GCM)
                || oid.equals(NISTObjectIdentifiers.id_aes192_GCM)
                || oid.equals(NISTObjectIdentifiers.id_aes256_GCM)) {
            gmac = true;
        }

        for (int i = 0; i < parallelism; i++) {
            ContentSigner signer;
            if (gmac) {
                signer = new AESGmacContentSigner(oid, key);
            } else {
                signer = new HmacContentSigner(signatureAlgId, key);
            }
            signers.add(signer);
        }

        final boolean mac = true;
        DefaultConcurrentContentSigner concurrentSigner;
        try {
            concurrentSigner = new DefaultConcurrentContentSigner(mac, signers, key);
        } catch (NoSuchAlgorithmException ex) {
            throw new XiSecurityException(ex.getMessage(), ex);
        }
        concurrentSigner.setSha1DigestOfMacKey(HashAlgoType.SHA1.hash(key.getEncoded()));

        return concurrentSigner;
    } // createSigner

    public SecretKey key() {
        return key;
    }

}
