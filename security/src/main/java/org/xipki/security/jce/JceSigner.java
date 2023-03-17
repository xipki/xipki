// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

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
 * @author Lijun Liao (xipki)
 */
public class JceSigner implements XiContentSigner {

    private final PrivateKey signKey;

    private final SignAlgo signAlgo;

    private final Signature signature;

    private final SignerOutputStream stream;

    private final byte[] encodedAlgId;

    private class SignerOutputStream extends OutputStream {

        @Override
        public void write(int oneByte) throws IOException {
            try {
                signature.update((byte) oneByte);
            } catch (SignatureException e) {
                throw new IOException(e);
            }
        }

        @Override
        public void write(byte[] bytes) throws IOException {
            try {
                signature.update(bytes);
            } catch (SignatureException e) {
                throw new IOException(e);
            }
        }

        @Override
        public void write(byte[] bytes, int off, int len) throws IOException {
            try {
                signature.update(bytes, off, len);
            } catch (SignatureException e) {
                throw new IOException(e);
            }
        }

        @Override
        public void flush() throws IOException {
        }

        @Override
        public void close() throws IOException {
        }

    } // class SignerOutputStream

    public JceSigner(PrivateKey signKey, SignAlgo signAlgo, String providerName, Provider provider)
            throws XiSecurityException {
        this.signKey = signKey;
        this.signAlgo = signAlgo;
        String jceName = signAlgo.getJceName();
        try {
            this.signature = (providerName == null && provider == null) ? Signature.getInstance(jceName)
                : (provider != null) ? Signature.getInstance(jceName, provider)
                : Signature.getInstance(signAlgo.getJceName(), providerName);
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
