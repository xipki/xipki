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

package org.xipki.security;

import java.io.IOException;
import java.util.Arrays;

import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.common.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class IssuerHash {
  private final HashAlgo hashAlgo;

  private final byte[] issuerNameHash;

  private final byte[] issuerKeyHash;

  public IssuerHash(HashAlgo hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash) {
    this.hashAlgo = ParamUtil.requireNonNull("hashAlgo", hashAlgo);
    this.issuerNameHash = ParamUtil.requireNonNull("issuerNameHash", issuerNameHash);
    this.issuerKeyHash = ParamUtil.requireNonNull("issuerKeyHash", issuerKeyHash);

    final int len = hashAlgo.length();
    ParamUtil.requireRange("issuerNameHash.length", issuerNameHash.length, len, len);
    ParamUtil.requireRange("issuerKeyHash.length", issuerKeyHash.length, len, len);
  }

  public IssuerHash(HashAlgo hashAlgo, Certificate issuerCert) throws IOException {
    this.hashAlgo = ParamUtil.requireNonNull("hashAlgo", hashAlgo);
    ParamUtil.requireNonNull("issuerCert", issuerCert);

    byte[] encodedName = issuerCert.getSubject().getEncoded();
    byte[] encodedKey = issuerCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
    this.issuerNameHash = HashCalculator.hash(hashAlgo, encodedName);
    this.issuerKeyHash = HashCalculator.hash(hashAlgo, encodedKey);
  }

  public HashAlgo hashAlgo() {
    return hashAlgo;
  }

  public byte[] issuerNameHash() {
    return Arrays.copyOf(issuerNameHash, issuerNameHash.length);
  }

  public byte[] issuerKeyHash() {
    return Arrays.copyOf(issuerKeyHash, issuerKeyHash.length);
  }

  public boolean match(HashAlgo hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash) {
    ParamUtil.requireNonNull("hashAlgo", hashAlgo);
    ParamUtil.requireNonNull("issuerNameHash", issuerNameHash);
    ParamUtil.requireNonNull("issuerKeyHash", issuerKeyHash);

    return this.hashAlgo == hashAlgo
        && Arrays.equals(this.issuerNameHash, issuerNameHash)
        && Arrays.equals(this.issuerKeyHash, issuerKeyHash);
  }

}
