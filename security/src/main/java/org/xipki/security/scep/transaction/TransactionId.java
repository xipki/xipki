// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.scep.transaction;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.security.HashAlgo;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Hex;
import org.xipki.util.extra.misc.RandomUtil;

import java.io.IOException;
import java.security.spec.InvalidKeySpecException;

/**
 * Transaction ID.
 *
 * @author Lijun Liao (xipki)
 */

public class TransactionId {

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
    return new TransactionId(RandomUtil.nextBytes(20));
  }

  public static TransactionId sha1TransactionId(SubjectPublicKeyInfo spki)
      throws InvalidKeySpecException {
    try {
      return sha1TransactionId(
              Args.notNull(spki, "spki").getEncoded());
    } catch (IOException ex) {
      throw new InvalidKeySpecException("IOException while ");
    }
  }

  public static TransactionId sha1TransactionId(byte[] content) {
    return new TransactionId(
        HashAlgo.SHA1.hash(
            Args.notNull(content, "content")));
  }

}
