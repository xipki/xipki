// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.xipki.util.Args;

import java.io.IOException;
import java.util.Arrays;

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
    this.hashAlgo = Args.notNull(hashAlgo, "hashAlgo");
    this.issuerNameHash = Args.notNull(issuerNameHash, "issuerNameHash");
    this.issuerKeyHash = Args.notNull(issuerKeyHash, "issuerKeyHash");

    final int len = hashAlgo.getLength();
    Args.range(issuerNameHash.length, "issuerNameHash.length", len, len);
    Args.range(issuerKeyHash.length, "issuerKeyHash.length", len, len);
  }

  public IssuerHash(HashAlgo hashAlgo, X509Cert issuerCert) throws IOException {
    this.hashAlgo = Args.notNull(hashAlgo, "hashAlgo");
    byte[] encodedName = Args.notNull(issuerCert, "issuerCert").getSubject().getEncoded();
    byte[] encodedKey = issuerCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
    this.issuerNameHash = hashAlgo.hash(encodedName);
    this.issuerKeyHash = hashAlgo.hash(encodedKey);
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
    return this.hashAlgo == Args.notNull(hashAlgo, "hashAlgo")
        && Arrays.equals(this.issuerNameHash, Args.notNull(issuerNameHash, "issuerNameHash"))
        && Arrays.equals(this.issuerKeyHash, Args.notNull(issuerKeyHash, "issuerKeyHash"));
  }

}
