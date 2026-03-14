// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.sign;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.xipki.security.OIDs;
import org.xipki.security.SignAlgo;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.util.codec.Args;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.OutputStream;

/**
 * XiPKI component.
 *
 * @author Lijun Liao (xipki)
 */
public class KemHmacSigner implements Signer {

  private final static AlgorithmIdentifier ALG_ID =
      new AlgorithmIdentifier(OIDs.Xipki.id_alg_KEM_HMAC_SHA256);
  private static final byte[] ENCODED_ALG_ID;

  private final String id;
  private final HmacSigner macSigner;

  static {
    try {
      ENCODED_ALG_ID = ALG_ID.getEncoded();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public KemHmacSigner(String id, SecretKey macKey) throws XiSecurityException {
    this.id = Args.notNull(id, "id");
    Args.notNull(macKey, "macKey");
    this.macSigner = new HmacSigner(SignAlgo.HMAC_SHA256, macKey);
  }

  @Override
  public ContentSigner x509Signer() {
    return new ContentSigner() {
      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return ALG_ID;
      }

      @Override
      public OutputStream getOutputStream() {
        return macSigner.x509Signer().getOutputStream();
      }

      @Override
      public byte[] getSignature() {
        byte[] rawSignature = macSigner.x509Signer().getSignature();
        return new KemHmacSignature(id, rawSignature).getEncoded();
      }
    };
  }

  @Override
  public byte[] getEncodedX509AlgId() {
    return ENCODED_ALG_ID.clone();
  }
}
