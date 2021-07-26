/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.security.jce;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.xipki.security.SignAlgo;
import org.xipki.security.XiContentSigner;
import org.xipki.security.XiSecurityException;

import java.io.IOException;
import java.io.OutputStream;
import java.security.*;

/**
 * JCE signer
 * @author Lijun Liao
 */
public class JceSigner implements XiContentSigner {

    private final PrivateKey signKey;

    private final SignAlgo signAlgo;

    private final Signature signature;

    private final SignerOutputStream stream;

    private final byte[] encodedAlgId;

    private class SignerOutputStream extends OutputStream {

        @Override
        public void write(int oneByte)
                throws IOException {
            try {
                signature.update((byte) oneByte);
            } catch (SignatureException e) {
                throw new IOException(e);
            }
        }

        @Override
        public void write(byte[] bytes)
                throws IOException {
            try {
                signature.update(bytes);
            } catch (SignatureException e) {
                throw new IOException(e);
            }
        }

        @Override
        public void write(byte[] bytes, int off, int len)
                throws IOException {
            try {
                signature.update(bytes, off, len);
            } catch (SignatureException e) {
                throw new IOException(e);
            }
        }

        public void reset() {
        }

        @Override
        public void flush()
                throws IOException {
        }

        @Override
        public void close()
                throws IOException {
        }

    } // class SignerOutputStream

    public JceSigner(PrivateKey signKey, SignAlgo signAlgo, String providerName,
                      Provider provider)
            throws XiSecurityException {
        this.signKey = signKey;
        this.signAlgo = signAlgo;
        String jceName = signAlgo.getJceName();
        try {
            if (providerName == null && provider == null) {
                this.signature = Signature.getInstance(jceName);
            } else if (provider != null) {
                this.signature = Signature.getInstance(jceName, provider);
            } else {
                this.signature = Signature.getInstance(signAlgo.getJceName(), providerName);
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException exception) {
            throw new XiSecurityException(exception);
        }
        this.stream = new SignerOutputStream();

        try {
            this.encodedAlgId = signAlgo.getAlgorithmIdentifier().getEncoded();
        } catch (IOException e) {
            throw new XiSecurityException(e);
        }
    }

    @Override
    public byte[] getEncodedAlgorithmIdentifier() {
        return encodedAlgId.clone();
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return signAlgo.getAlgorithmIdentifier();
    }

    @Override
    public OutputStream getOutputStream() {
        try {
            signature.initSign(signKey);
        } catch (InvalidKeyException e) {
            throw new RuntimeCryptoException(e.getMessage());
        }
        return stream;
    }

    @Override
    public byte[] getSignature() {
        try {
            return signature.sign();
        } catch (SignatureException ex) {
            throw new RuntimeCryptoException(ex.getMessage());
        }
    }
}
