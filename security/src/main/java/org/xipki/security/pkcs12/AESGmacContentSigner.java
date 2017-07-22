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
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.bc.XiContentSigner;
import org.xipki.security.exception.XiSecurityException;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

// CHECKSTYLE:SKIP
public class AESGmacContentSigner implements XiContentSigner {

    // CHECKSTYLE:SKIP
    private class AESGmacOutputStream extends OutputStream {

        @Override
        public void write(int bb) throws IOException {
            cipher.updateAAD(new byte[]{(byte) bb});
        }

        @Override
        public void write(byte[] bytes) throws IOException {
            cipher.updateAAD(bytes);
        }

        @Override
        public void write(byte[] bytes, int off, int len) throws IOException {
            cipher.updateAAD(bytes, off, len);
        }

    }

    private static final int tagByteLen = 16;

    private static final int nonceLen = 12;

    private final byte[] nonce = new byte[nonceLen];

    private final SecureRandom random;

    private final ASN1ObjectIdentifier oid;

    private final Cipher cipher;

    private final SecretKey signingKey;

    private final OutputStream outputStream;

    private final byte[] sigAlgIdTemplate;

    private final int nonceOffset;

    public AESGmacContentSigner(ASN1ObjectIdentifier oid, SecretKey signingKey)
            throws XiSecurityException {
        this.oid = ParamUtil.requireNonNull("oid", oid);
        this.signingKey = ParamUtil.requireNonNull("signingKey", signingKey);

        Cipher cipher0;
        try {
            cipher0 = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
        } catch (NoSuchProviderException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            try {
                cipher0 = Cipher.getInstance("AES/GCM/NoPadding");
            } catch (NoSuchAlgorithmException | NoSuchPaddingException ex2) {
                throw new XiSecurityException(ex2);
            }
        }
        this.cipher = cipher0;

        this.random = new SecureRandom();
        this.outputStream = new AESGmacOutputStream();

        GCMParameters params = new GCMParameters(nonce, tagByteLen);
        try {
            this.sigAlgIdTemplate = new AlgorithmIdentifier(oid, params).getEncoded();
        } catch (IOException ex) {
            throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
        }
        this.nonceOffset = IoUtil.getIndex(sigAlgIdTemplate, nonce);

        int keyLen = signingKey.getEncoded().length;
        if (keyLen == 16) {
            if (!oid.equals(NISTObjectIdentifiers.id_aes128_GCM)) {
                throw new XiSecurityException("oid and singingKey do not match");
            }
        } else if (keyLen == 24) {
            if (!oid.equals(NISTObjectIdentifiers.id_aes192_GCM)) {
                throw new XiSecurityException("oid and singingKey do not match");
            }
        } else if (keyLen == 32) {
            if (!oid.equals(NISTObjectIdentifiers.id_aes256_GCM)) {
                throw new XiSecurityException("oid and singingKey do not match");
            }
        } else {
            throw new XiSecurityException("invalid AES key length: " + keyLen);
        }

        // check the key.
        try {
            cipher.init(Cipher.ENCRYPT_MODE, signingKey,
                    new GCMParameterSpec(tagByteLen << 3, nonce));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
            throw new XiSecurityException(ex);
        }
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        GCMParameters params = new GCMParameters(nonce, tagByteLen);
        return new AlgorithmIdentifier(oid, params);
    }

    @Override
    public byte[] getEncodedAlgorithmIdentifier() {
        byte[] bytes = Arrays.copyOf(sigAlgIdTemplate, sigAlgIdTemplate.length);
        System.arraycopy(nonce, 0, bytes, nonceOffset, nonceLen);
        return bytes;
    }

    @Override
    public OutputStream getOutputStream() {
        random.nextBytes(nonce);
        try {
            cipher.init(Cipher.ENCRYPT_MODE, signingKey,
                    new GCMParameterSpec(tagByteLen << 3, nonce));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
            throw new IllegalStateException(ex);
        }
        return outputStream;
    }

    @Override
    public byte[] getSignature() {
        try {
            return cipher.doFinal();
        } catch (IllegalBlockSizeException ex) {
            throw new IllegalStateException("IllegalBlockSizeException: " + ex.getMessage());
        } catch (BadPaddingException ex) {
            throw new IllegalStateException("BadPaddingException: " + ex.getMessage());
        }
    }

}
