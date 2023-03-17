// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;

import java.io.IOException;
import java.io.OutputStream;

import static org.xipki.util.Args.notNull;

/**
 * An implementation of {@link XiContentSigner}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public class XiWrappedContentSigner implements XiContentSigner {

  private byte[] encodedAlgorithmIdentifier;
  private final ContentSigner signer;

  public XiWrappedContentSigner(ContentSigner signer, boolean fixedAlgorithmIdentifier)
      throws XiSecurityException {
    this.signer = notNull(signer, "signer");
    if (fixedAlgorithmIdentifier) {
      try {
        this.encodedAlgorithmIdentifier = signer.getAlgorithmIdentifier().getEncoded();
      } catch (IOException ex) {
        throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
      }
    }
  }

  @Override
  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return signer.getAlgorithmIdentifier();
  }

  @Override
  public byte[] getEncodedAlgorithmIdentifier() {
    if (encodedAlgorithmIdentifier != null) {
      return encodedAlgorithmIdentifier;
    }

    try {
      return signer.getAlgorithmIdentifier().getEncoded();
    } catch (IOException ex) {
      throw new IllegalStateException("error encoding AlgorithmIdentifier", ex);
    }
  }

  @Override
  public OutputStream getOutputStream() {
    return signer.getOutputStream();
  }

  @Override
  public byte[] getSignature() {
    return signer.getSignature();
  }

}
