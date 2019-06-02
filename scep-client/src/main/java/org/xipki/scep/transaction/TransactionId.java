/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.scep.transaction;

import java.io.IOException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.scep.util.ScepUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public class TransactionId {

  private static final SecureRandom RANDOM = new SecureRandom();

  private final String id;

  public TransactionId(String id) {
    this.id = ScepUtil.requireNonBlank("id", id);
  }

  private TransactionId(byte[] bytes) {
    if (bytes == null || bytes.length == 0) {
      throw new IllegalArgumentException("bytes must not be empty");
    }
    this.id = Hex.toHexString(bytes);
  }

  public String getId() {
    return id;
  }

  public static TransactionId randomTransactionId() {
    byte[] bytes = new byte[20];
    RANDOM.nextBytes(bytes);
    return new TransactionId(bytes);
  }

  public static TransactionId sha1TransactionId(SubjectPublicKeyInfo spki)
      throws InvalidKeySpecException {
    ScepUtil.requireNonNull("spki", spki);

    byte[] encoded;
    try {
      encoded = spki.getEncoded();
    } catch (IOException ex) {
      throw new InvalidKeySpecException("IOException while ");
    }

    return sha1TransactionId(encoded);
  }

  public static TransactionId sha1TransactionId(byte[] content) {
    ScepUtil.requireNonNull("content", content);

    SHA1Digest dgst = new SHA1Digest();
    dgst.update(content, 0, content.length);
    byte[] digest = new byte[20];
    dgst.doFinal(digest, 0);
    return new TransactionId(digest);
  }

}
