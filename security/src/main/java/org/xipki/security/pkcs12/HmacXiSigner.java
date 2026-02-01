// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.security.SignAlgo;
import org.xipki.security.XiSigner;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.util.codec.Args;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

/**
 * HMAC signer.
 *
 * @author Lijun Liao (xipki)
 */
public class HmacXiSigner implements XiSigner {

  private final SignAlgo algorithm;

  private final byte[] encodedX509AlgId;

  private final HMac hmac;

  private final int outLen;

  private final MyX509Signer x509Signer;

  public HmacXiSigner(SignAlgo algorithm, SecretKey signingKey)
      throws XiSecurityException {
    this.algorithm = Args.notNull(algorithm, "algorithm");
    Args.notNull(signingKey, "signingKey");
    try {
      this.encodedX509AlgId = algorithm.algorithmIdentifier().getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }

    this.hmac = new HMac(algorithm.hashAlgo().createDigest());
    byte[] keyBytes = signingKey.getEncoded();
    hmac.init(new KeyParameter(keyBytes, 0, keyBytes.length));
    this.outLen = hmac.getMacSize();
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
      byte[] signature = new byte[outLen];
      hmac.doFinal(signature, 0);
      return signature;
    }

  }

  private static class HmacOutputStream extends OutputStream {

    private final HMac hmac;

    HmacOutputStream(HMac hmac) {
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
