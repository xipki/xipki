// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.scep.transaction;

import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.util.Args;
import org.xipki.codec.Hex;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.util.misc.RandomUtil;

/**
 * Transaction Id.
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

  public String id() {
    return id;
  }

  public static TransactionId randomTransactionId() {
    return new TransactionId(RandomUtil.nextBytes(20));
  }

  public static TransactionId sha1TransactionId(SubjectPublicKeyInfo spki) {
    return sha1TransactionId(Args.notNull(spki, "spki").getEncoded());
  }

  public static TransactionId sha1TransactionId(byte[] content) {
    return new TransactionId(HashAlgo.SHA1.hash(Args.notNull(content, "content")));
  }

}
