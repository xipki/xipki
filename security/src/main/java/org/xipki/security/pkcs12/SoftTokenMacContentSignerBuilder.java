/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
import org.xipki.common.util.ParamUtil;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.DefaultConcurrentContentSigner;
import org.xipki.security.HashAlgoType;
import org.xipki.security.bc.XiContentSigner;
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

        List<XiContentSigner> signers = new ArrayList<>(parallelism);

        boolean gmac = false;
        ASN1ObjectIdentifier oid = signatureAlgId.getAlgorithm();
        if (oid.equals(NISTObjectIdentifiers.id_aes128_GCM)
                || oid.equals(NISTObjectIdentifiers.id_aes192_GCM)
                || oid.equals(NISTObjectIdentifiers.id_aes256_GCM)) {
            gmac = true;
        }

        for (int i = 0; i < parallelism; i++) {
            XiContentSigner signer;
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
