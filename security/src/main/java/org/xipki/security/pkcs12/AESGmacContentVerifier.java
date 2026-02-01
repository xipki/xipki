// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentVerifier;
import org.xipki.security.SignAlgo;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.util.codec.Args;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

/**
 * AES GMAC signer.
 * @author Lijun Liao (xipki)
 */
public class AESGmacContentVerifier implements ContentVerifier {

  private class AESGmacOutputStream extends OutputStream {

    @Override
    public void write(int bb) throws IOException {
      mac.update((byte) bb);
    }

    @Override
    public void write(byte[] bytes) throws IOException {
      mac.update(bytes);
    }

    @Override
    public void write(byte[] bytes, int off, int len) throws IOException {
      mac.update(bytes, off, len);
    }

  } // class AESGmacOutputStream

  private final SignAlgo signAlgo;

  private final Mac mac;

  private final SecretKey verifyingKey;

  private final OutputStream outputStream;

  private final byte[] nonce;

  private final int tagByteLen;

  public AESGmacContentVerifier(SignAlgo signAlgo, SecretKey verifyingKey,
                                byte[] nonce, int tagByteLen)
      throws XiSecurityException {
    this.signAlgo = Args.notNull(signAlgo, "signAlgo");
    this.verifyingKey = Args.notNull(verifyingKey, "verifyingKey");
    this.nonce = Args.notNull(nonce, "nonce");
    this.tagByteLen = tagByteLen;

    try {
      this.mac = Mac.getInstance("AES-GMAC", "BC");
    } catch (NoSuchProviderException | NoSuchAlgorithmException ex) {
      throw new XiSecurityException(ex);
    }
    this.outputStream = new AESGmacOutputStream();

    int keyLen = verifyingKey.getEncoded().length;
    if (keyLen == 16) {
      if (SignAlgo.GMAC_AES128 != signAlgo) {
        throw new XiSecurityException("oid and signingKey do not match");
      }
    } else if (keyLen == 24) {
      if (SignAlgo.GMAC_AES192 != signAlgo) {
        throw new XiSecurityException("oid and signingKey do not match");
      }
    } else if (keyLen == 32) {
      if (SignAlgo.GMAC_AES256 != signAlgo) {
        throw new XiSecurityException("oid and signingKey do not match");
      }
    } else {
      throw new XiSecurityException("invalid AES key length: " + keyLen);
    }
  } // method AESGmacContentSigner

  @Override
  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return new AlgorithmIdentifier(signAlgo.oid(),
        new GCMParameters(nonce, tagByteLen));
  }

  @Override
  public OutputStream getOutputStream() {
    try {
      mac.init(verifyingKey, new IvParameterSpec(nonce));
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException(ex);
    }
    return outputStream;
  }

  @Override
  public boolean verify(byte[] expected) {
    byte[] computed = mac.doFinal();
    return Arrays.equals(expected, 0, tagByteLen, computed, 0, tagByteLen);
  }

}
