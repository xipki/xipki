// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.security.OIDs;
import org.xipki.security.XiSigner;
import org.xipki.util.codec.Hex;
import org.xipki.util.extra.misc.NopOutputStream;

import java.io.OutputStream;

/**
 * This signer implements the alg-unsigned algorithm, and returns new byte[0]
 * as signature value.
 *
 * @author Lijun Liao (xipki)
 */
public class XiUnsignedSigner implements XiSigner {

  public static final XiUnsignedSigner INSTANCE = new XiUnsignedSigner();

  private static final AlgorithmIdentifier x509AlgId =
      new AlgorithmIdentifier(OIDs.Algo.id_alg_unsigned);

  private static final byte[] encodedX509AlgId =
      Hex.decode("300a06082b06010505070624");

  private final ContentSigner x509Signer;

  private XiUnsignedSigner() {

    this.x509Signer = new ContentSigner() {
      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return x509AlgId;
      }

      @Override
      public OutputStream getOutputStream() {
        return NopOutputStream.INSTANCE;
      }

      @Override
      public byte[] getSignature() {
        return new byte[0];
      }
    };
  }

  @Override
  public ContentSigner x509Signer() {
    return x509Signer;
  }

  @Override
  public byte[] getEncodedX509AlgId() {
    return encodedX509AlgId.clone();
  }

}
