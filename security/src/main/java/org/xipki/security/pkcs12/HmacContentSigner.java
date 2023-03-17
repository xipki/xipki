// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.xipki.security.SignAlgo;
import org.xipki.security.XiContentSigner;
import org.xipki.security.XiSecurityException;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

import static org.xipki.util.Args.notNull;

/**
 * HMAC signer.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public class HmacContentSigner implements XiContentSigner {

  private class HmacOutputStream extends OutputStream {

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

  private final SignAlgo algorithm;

  private final byte[] encodedAlgorithmIdentifier;

  private final HmacOutputStream outputStream;

  private final HMac hmac;

  private final int outLen;

  public HmacContentSigner(SignAlgo algorithm, SecretKey signingKey) throws XiSecurityException {
    this.algorithm = notNull(algorithm, "algorithm");
    notNull(signingKey, "signingKey");
    try {
      this.encodedAlgorithmIdentifier = algorithm.getAlgorithmIdentifier().getEncoded();
    } catch (IOException ex) {
      throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
    }

    this.hmac = new HMac(algorithm.getHashAlgo().createDigest());
    byte[] keyBytes = signingKey.getEncoded();
    this.hmac.init(new KeyParameter(keyBytes, 0, keyBytes.length));
    this.outLen = hmac.getMacSize();
    this.outputStream = new HmacOutputStream();
  }

  @Override
  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return algorithm.getAlgorithmIdentifier();
  }

  @Override
  public byte[] getEncodedAlgorithmIdentifier() {
    return Arrays.copyOf(encodedAlgorithmIdentifier, encodedAlgorithmIdentifier.length);
  }

  @Override
  public OutputStream getOutputStream() {
    hmac.reset();
    return outputStream;
  }

  @Override
  public byte[] getSignature() {
    byte[] signature = new byte[outLen];
    hmac.doFinal(signature, 0);
    return signature;
  }

}
