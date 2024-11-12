// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.util.Args;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Arrays;

/**
 * Specifies private key and certificate pair for the DHSig-static defined in RFC 6955.
 *
 * @author Lijun Liao (xipki)
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
    this.privateKey = Args.notNull(privateKey, "privateKey");
    this.serialNumber = Args.notNull(certificate, "certificate").getSerialNumber();
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
