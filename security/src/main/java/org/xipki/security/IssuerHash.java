// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import java.io.IOException;
import java.util.Arrays;

import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.range;

/**
 * Contains issuerNameHash and issuerKeyHash as specified in the OCSP standard RFC 6960.
 *
 * @author Lijun Liao (xipki)
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

    return this.hashAlgo == hashAlgo && Arrays.equals(this.issuerNameHash, issuerNameHash)
        && Arrays.equals(this.issuerKeyHash, issuerKeyHash);
  }

}
