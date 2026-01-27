// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bc;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.security.OIDs;
import org.xipki.util.extra.misc.NopOutputStream;

import java.io.OutputStream;

/**
 * This signer implements the alg-unsigned algorithm, and returns new byte[0]
 * as signature value.
 * @author Lijun Liao (xipki)
 */
public class XiUnsignedSigner implements ContentSigner {

  public static XiUnsignedSigner INSTANCE = new XiUnsignedSigner();

  private static final AlgorithmIdentifier algId =
      new AlgorithmIdentifier(OIDs.Algo.id_alg_unsigned);

  private XiUnsignedSigner() {
  }

  @Override
  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return algId;
  }

  @Override
  public OutputStream getOutputStream() {
    return new NopOutputStream();
  }

  @Override
  public byte[] getSignature() {
    return new byte[0];
  }

}
