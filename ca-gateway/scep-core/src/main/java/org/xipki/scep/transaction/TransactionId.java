// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.transaction;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.xipki.util.Args;
import org.xipki.util.Hex;

import java.io.IOException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * Transaction ID.
 *
 * @author Lijun Liao (xipki)
 */

public class TransactionId {

  private static final SecureRandom RANDOM = new SecureRandom();

  private final String id;

  public TransactionId(String id) {
    this.id = Args.notBlank(id, "id");
  }

  private TransactionId(byte[] bytes) {
    if (bytes == null || bytes.length == 0) {
      throw new IllegalArgumentException("bytes must not be empty");
    }
    this.id = Hex.encode(bytes);
  }

  public String getId() {
    return id;
  }

  public static TransactionId randomTransactionId() {
    byte[] bytes = new byte[20];
    RANDOM.nextBytes(bytes);
    return new TransactionId(bytes);
  }

  public static TransactionId sha1TransactionId(SubjectPublicKeyInfo spki) throws InvalidKeySpecException {
    Args.notNull(spki, "spki");

    byte[] encoded;
    try {
      encoded = spki.getEncoded();
    } catch (IOException ex) {
      throw new InvalidKeySpecException("IOException while ");
    }

    return sha1TransactionId(encoded);
  }

  public static TransactionId sha1TransactionId(byte[] content) {
    Args.notNull(content, "content");

    SHA1Digest dgst = new SHA1Digest();
    dgst.update(content, 0, content.length);
    byte[] digest = new byte[20];
    dgst.doFinal(digest, 0);
    return new TransactionId(digest);
  }

}
