/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.security;

import static org.xipki.util.Args.notNull;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;

/**
 * An implementation of {@link XiContentSigner}.
 *
 * @author Lijun Liao
 * @since 2.2.0
 */

public class XiWrappedContentSigner implements XiContentSigner {

  private byte[] encodedAlgorithmIdentifier;
  private ContentSigner signer;

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
