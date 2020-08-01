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
import static org.xipki.util.Args.range;

import java.io.IOException;
import java.util.Arrays;

/**
 * Contains issuerNameHash and issuerKeyHash as specified in the OCSP standard RFC 6960.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class IssuerHash {
  private final HashAlgo hashAlgo;

  private final byte[] issuerNameHash;

  private final byte[] issuerKeyHash;

  public IssuerHash(HashAlgo hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash) {
    this.hashAlgo = notNull(hashAlgo, "hashAlgo");
    this.issuerNameHash = notNull(issuerNameHash, "issuerNameHash");
    this.issuerKeyHash = notNull(issuerKeyHash, "issuerKeyHash");

    final int len = hashAlgo.getLength();
    range(issuerNameHash.length, "issuerNameHash.length", len, len);
    range(issuerKeyHash.length, "issuerKeyHash.length", len, len);
  }

  public IssuerHash(HashAlgo hashAlgo, X509Cert issuerCert) throws IOException {
    this.hashAlgo = notNull(hashAlgo, "hashAlgo");
    notNull(issuerCert, "issuerCert");

    byte[] encodedName = issuerCert.getSubject().getEncoded();
    byte[] encodedKey = issuerCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
    this.issuerNameHash = HashCalculator.hash(hashAlgo, encodedName);
    this.issuerKeyHash = HashCalculator.hash(hashAlgo, encodedKey);
  }

  public HashAlgo getHashAlgo() {
    return hashAlgo;
  }

  public byte[] getIssuerNameHash() {
    return Arrays.copyOf(issuerNameHash, issuerNameHash.length);
  }

  public byte[] getIssuerKeyHash() {
    return Arrays.copyOf(issuerKeyHash, issuerKeyHash.length);
  }

  public boolean match(HashAlgo hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash) {
    notNull(hashAlgo, "hashAlgo");
    notNull(issuerNameHash, "issuerNameHash");
    notNull(issuerKeyHash, "issuerKeyHash");

    return this.hashAlgo == hashAlgo
        && Arrays.equals(this.issuerNameHash, issuerNameHash)
        && Arrays.equals(this.issuerKeyHash, issuerKeyHash);
  }

}
