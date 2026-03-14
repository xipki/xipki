// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.sign;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.security.SignAlgo;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.util.codec.Args;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * HMAC signer.
 *
 * @author Lijun Liao (xipki)
 */
public class HmacSigner implements Signer {

  private final SignAlgo algorithm;

  private final byte[] encodedX509AlgId;

  private final Mac hmac;

  private final MyX509Signer x509Signer;

  public HmacSigner(SignAlgo algorithm, SecretKey signingKey) throws XiSecurityException {
    this.algorithm = Args.notNull(algorithm, "algorithm");
    Args.notNull(signingKey, "signingKey");
    try {
      this.encodedX509AlgId = algorithm.algorithmIdentifier().getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }

    String algName = "HMAC-" + algorithm.hashAlgo().jceName();
    try {
      this.hmac = Mac.getInstance(algName);
      byte[] keyBytes = signingKey.getEncoded();
      hmac.init(new SecretKeySpec(keyBytes, algName));
    } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
      throw new XiSecurityException("could not initialize HMAC", ex);
    }
    this.x509Signer = new MyX509Signer();
  }

  public SignAlgo getAlgorithm() {
    return algorithm;
  }

  @Override
  public ContentSigner x509Signer() {
    return x509Signer;
  }

  @Override
  public byte[] getEncodedX509AlgId() {
    return Arrays.copyOf(encodedX509AlgId, encodedX509AlgId.length);
  }

  private final class MyX509Signer implements ContentSigner {

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algorithm.algorithmIdentifier();
    }

    @Override
    public OutputStream getOutputStream() {
      hmac.reset();
      return new HmacOutputStream(hmac);
    }

    @Override
    public byte[] getSignature() {
      return hmac.doFinal();
    }

  }

  private static class HmacOutputStream extends OutputStream {

    private final Mac hmac;

    HmacOutputStream(Mac hmac) {
      this.hmac = hmac;
    }

    @Override
    public void write(int bb) throws IOException {
      hmac.update((byte) bb);
    }

    @Override
    public void write(byte[] bytes) throws IOException {
      hmac.update(bytes, 0, bytes.length);
    }

    @Override
    public void write(byte[] bytes, int off, int len) throws IOException {
      hmac.update(bytes, off, len);
    }

  } // method HmacOutputStream
}
