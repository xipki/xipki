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

package org.xipki.security;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.bc.XiContentSigner;
import org.xipki.security.exception.XiSecurityException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignatureSigner implements XiContentSigner {

    private class SignatureStream extends OutputStream {

        public byte[] getSignature() throws SignatureException {
            return signer.sign();
        }

        @Override
        public void write(final int singleByte) throws IOException {
            try {
                signer.update((byte) singleByte);
            } catch (SignatureException ex) {
                throw new IOException(ex.getMessage(), ex);
            }
        }

        @Override
        public void write(final byte[] bytes) throws IOException {
            try {
                signer.update(bytes);
            } catch (SignatureException ex) {
                throw new IOException(ex.getMessage(), ex);
            }
        }

        @Override
        public void write(final byte[] bytes, final int off, final int len) throws IOException {
            try {
                signer.update(bytes, off, len);
            } catch (SignatureException ex) {
                throw new IOException(ex.getMessage(), ex);
            }
        }

    } // class SignatureStream

    private final AlgorithmIdentifier sigAlgId;

    private final byte[] encodedSigAlgId;

    private final Signature signer;

    private final SignatureStream stream = new SignatureStream();

    private final PrivateKey key;

    public SignatureSigner(final AlgorithmIdentifier sigAlgId, final Signature signer,
            final PrivateKey key) throws XiSecurityException {
        this.sigAlgId = ParamUtil.requireNonNull("sigAlgId", sigAlgId);
        this.signer = ParamUtil.requireNonNull("signer", signer);
        this.key = ParamUtil.requireNonNull("key", key);
        try {
            this.encodedSigAlgId = sigAlgId.getEncoded();
        } catch (IOException ex) {
            throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
        }
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return sigAlgId;
    }

    @Override
    public byte[] getEncodedAlgorithmIdentifier() {
        return Arrays.copyOf(encodedSigAlgId, encodedSigAlgId.length);
    }

    @Override
    public OutputStream getOutputStream() {
        try {
            signer.initSign(key);
        } catch (InvalidKeyException ex) {
            throw new RuntimeOperatorException("could not initSign", ex);
        }
        return stream;
    }

    @Override
    public byte[] getSignature() {
        try {
            return stream.getSignature();
        } catch (SignatureException ex) {
            throw new RuntimeOperatorException("exception obtaining signature: " + ex.getMessage(),
                    ex);
        }
    }

}
