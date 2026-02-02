// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.util.Arrays;
import org.xipki.security.SignAlgo;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.sign.Signer;
import org.xipki.util.codec.Args;
import org.xipki.util.io.IoUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

/**
 * AES GMAC signer.
 * @author Lijun Liao (xipki)
 */
public class AESGmacContentSigner implements Signer {

  private static class AESGmacOutputStream extends OutputStream {

    private final Cipher cipher;

    AESGmacOutputStream(Cipher cipher) {
      this.cipher = cipher;
    }

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

  public static final int tagByteLen = 16;

  public static final int nonceLen = 12;

  private final byte[] nonce = new byte[nonceLen];

  private final SecureRandom random;

  private final SignAlgo signAlgo;

  private final Cipher cipher;

  private final SecretKey signingKey;

  private final byte[] x509SigAlgIdTemplate;

  private final int nonceOffset;

  private final MyX509Signer x509Signer;

  public AESGmacContentSigner(SignAlgo signAlgo, SecretKey signingKey)
      throws XiSecurityException {
    this.signAlgo = Args.notNull(signAlgo, "signAlgo");
    this.signingKey = Args.notNull(signingKey, "signingKey");

    Cipher cipher0;
    try {
      cipher0 = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
    } catch (GeneralSecurityException ex) {
      try {
        cipher0 = Cipher.getInstance("AES/GCM/NoPadding");
      } catch (GeneralSecurityException ex2) {
        throw new XiSecurityException(ex2);
      }
    }

    this.cipher = cipher0;
    this.random = new SecureRandom();

    final GCMParameters params = new GCMParameters(nonce, tagByteLen);
    try {
      this.x509SigAlgIdTemplate =
          new AlgorithmIdentifier(signAlgo.oid(), params).getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }
    this.nonceOffset = IoUtil.getIndex(x509SigAlgIdTemplate, nonce);

    String message = "oid and singingKey do not match";
    int keyLen = signingKey.getEncoded().length;
    if (keyLen == 16) {
      if (SignAlgo.GMAC_AES128 != signAlgo) {
        throw new XiSecurityException(message);
      }
    } else if (keyLen == 24) {
      if (SignAlgo.GMAC_AES192 != signAlgo) {
        throw new XiSecurityException(message);
      }
    } else if (keyLen == 32) {
      if (SignAlgo.GMAC_AES256 != signAlgo) {
        throw new XiSecurityException(message);
      }
    } else {
      throw new XiSecurityException("invalid AES key length: " + keyLen);
    }

    // check the key.
    try {
      cipher0.init(Cipher.ENCRYPT_MODE, signingKey,
          new GCMParameterSpec(tagByteLen << 3, nonce));
    } catch (GeneralSecurityException ex) {
      throw new XiSecurityException(ex);
    }

    this.x509Signer = new MyX509Signer();
  } // method AESGmacContentSigner

  private void initCipher() {
    random.nextBytes(nonce);
    try {
      cipher.init(Cipher.ENCRYPT_MODE, signingKey,
          new GCMParameterSpec(tagByteLen << 3, nonce));
    } catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
      throw new IllegalStateException(ex);
    }
  }

  @Override
  public ContentSigner x509Signer() {
    return x509Signer;
  }

  @Override
  public byte[] getEncodedX509AlgId() {
    byte[] bytes = Arrays.copyOf(x509SigAlgIdTemplate,
                      x509SigAlgIdTemplate.length);
    System.arraycopy(nonce, 0, bytes, nonceOffset, nonceLen);
    return bytes;
  }

  public byte[] nonce() {
    return nonce.clone();
  }

  private class MyX509Signer implements ContentSigner {

    final AESGmacOutputStream outputStream = new AESGmacOutputStream(cipher);

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return new AlgorithmIdentifier(signAlgo.oid(),
          new GCMParameters(nonce, tagByteLen));
    }

    @Override
    public OutputStream getOutputStream() {
      initCipher();
      return outputStream;
    }

    @Override
    public byte[] getSignature() {
      try {
        return cipher.doFinal();
      } catch (IllegalBlockSizeException ex) {
        throw new IllegalStateException(
            "IllegalBlockSizeException: " + ex.getMessage());
      } catch (BadPaddingException ex) {
        throw new IllegalStateException(
            "BadPaddingException: " + ex.getMessage());
      }
    }
  }

}
