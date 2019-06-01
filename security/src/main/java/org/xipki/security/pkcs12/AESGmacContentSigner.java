/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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
import org.xipki.security.XiContentSigner;
import org.xipki.security.XiSecurityException;
import org.xipki.util.Args;
import org.xipki.util.IoUtil;

/**
 * AES GMAC signer.
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
    this.oid = Args.notNull(oid, "oid");
    this.signingKey = Args.notNull(signingKey, "signingKey");

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
      cipher.init(Cipher.ENCRYPT_MODE, signingKey, new GCMParameterSpec(tagByteLen << 3, nonce));
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
      cipher.init(Cipher.ENCRYPT_MODE, signingKey, new GCMParameterSpec(tagByteLen << 3, nonce));
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
