// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.scep.util;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.DigestOutputStream;

import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;

/**
 * Xi Digest Calculator Provider.
 *
 * @author Lijun Liao (xipki)
 */
public class XiDigestCalculatorProvider implements DigestCalculatorProvider {

  @Override
  public DigestCalculator get(final AlgorithmIdentifier algorithm)
      throws OperatorCreationException {
    HashAlgo ha;
    try {
      ha = HashAlgo.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new OperatorCreationException(e.getMessage());
    }

    DigestOutputStream stream = new DigestOutputStream(ha.createDigest());

    return new DigestCalculator() {

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithm;
      }

      @Override
      public OutputStream getOutputStream() {
        return stream;
      }

      @Override
      public byte[] getDigest() {
        return stream.digest();
      }
    };

  }

}
