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

import org.bouncycastle.asn1.x500.X500Name;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Arrays;

import static org.xipki.util.Args.notNull;

/**
 * Specifies private key and certificate pair for the DHSig-static defined in RFC 6955.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DHSigStaticKeyCertPair {

  private final PrivateKey privateKey;

  private final X500Name issuer;

  private final X500Name subject;

  private final BigInteger serialNumber;

  private final byte[] encodedIssuer;

  private final byte[] encodedSubject;

  public DHSigStaticKeyCertPair(PrivateKey privateKey, X509Cert certificate) {
    this.privateKey = notNull(privateKey, "privateKey");
    notNull(certificate, "certificate");
    this.serialNumber = certificate.getSerialNumber();
    try {
      this.encodedIssuer = certificate.getIssuer().getEncoded();
      this.encodedSubject = certificate.getSubject().getEncoded();
    } catch (Exception ex) {
      throw new IllegalArgumentException("error encoding certificate", ex);
    }
    this.issuer = X500Name.getInstance(this.encodedIssuer);
    this.subject = X500Name.getInstance(this.encodedSubject);
  }

  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  public X500Name getIssuer() {
    return issuer;
  }

  public X500Name getSubject() {
    return subject;
  }

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public byte[] getEncodedIssuer() {
    return Arrays.copyOf(encodedIssuer, encodedIssuer.length);
  }

  public byte[] getEncodedSubject() {
    return Arrays.copyOf(encodedSubject, encodedSubject.length);
  }

}
