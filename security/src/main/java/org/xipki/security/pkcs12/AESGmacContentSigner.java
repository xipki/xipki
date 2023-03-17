// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;
import org.xipki.security.SignAlgo;
import org.xipki.security.XiContentSigner;
import org.xipki.security.XiSecurityException;
import org.xipki.util.IoUtil;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;

import static org.xipki.util.Args.notNull;

/**
 * AES GMAC signer.
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public class AESGmacContentSigner implements XiContentSigner {

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

  } // class AESGmacOutputStream

  private static final int tagByteLen = 12;

  private static final int nonceLen = 12;

  private final byte[] nonce = new byte[nonceLen];

  private final SecureRandom random;

  private final SignAlgo signAlgo;

  private final Cipher cipher;

  private final SecretKey signingKey;

  private final OutputStream outputStream;

  private final byte[] sigAlgIdTemplate;

  private final int nonceOffset;

  public AESGmacContentSigner(SignAlgo signAlgo, SecretKey signingKey) throws XiSecurityException {
    this.signAlgo = notNull(signAlgo, "signAlgo");
    this.signingKey = notNull(signingKey, "signingKey");

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
      this.sigAlgIdTemplate = new AlgorithmIdentifier(signAlgo.getOid(), params).getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }
    this.nonceOffset = IoUtil.getIndex(sigAlgIdTemplate, nonce);

    int keyLen = signingKey.getEncoded().length;
    if (keyLen == 16) {
      if (SignAlgo.GMAC_AES128 != signAlgo) {
        throw new XiSecurityException("oid and singingKey do not match");
      }
    } else if (keyLen == 24) {
      if (SignAlgo.GMAC_AES192 != signAlgo) {
        throw new XiSecurityException("oid and singingKey do not match");
      }
    } else if (keyLen == 32) {
      if (SignAlgo.GMAC_AES256 != signAlgo) {
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
  } // method AESGmacContentSigner

  @Override
  public AlgorithmIdentifier getAlgorithmIdentifier() {
    GCMParameters params = new GCMParameters(nonce, tagByteLen);
    return new AlgorithmIdentifier(signAlgo.getOid(), params);
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
