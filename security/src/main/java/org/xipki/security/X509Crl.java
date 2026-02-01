// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.xipki.util.codec.Args;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;

/**
 * Wrapper to an {@link X509Certificate}.
 *
 * @author Lijun Liao (xipki)
 */

public class X509Crl {

  private final Object sync = new Object();

  private final X509CRLHolder x509;

  private byte[] encoded;

  public X509Crl(X509CRLHolder crl) {
    this(crl, null);
  }

  public X509Crl(X509CRLHolder crl, byte[] encoded) {
    this.x509 = Args.notNull(crl, "crl");
    this.encoded = encoded;
  }

  public byte[] getEncoded() {
    if (encoded != null) {
      return encoded;
    }

    synchronized (sync) {
      try {
        encoded = x509.getEncoded();
      } catch (Exception ex) {
        throw new IllegalStateException("error encoding CRL", ex);
      }
      return encoded;
    }
  }

  public BigInteger crlNumber() {
    Extension extn = x509.getExtension(OIDs.Extn.cRLNumber);
    return extn == null ? null
        : ((ASN1Integer) extn.getParsedValue()).getValue();
  }

  public BigInteger baseCrlNumber() {
    Extension extn = x509.getExtension(OIDs.Extn.deltaCRLIndicator);
    return extn == null ? null
        : ((ASN1Integer) extn.getParsedValue()).getValue();
  }

  public Instant thisUpdate() {
    return x509.getThisUpdate().toInstant();
  }

  public Instant nextUpdate() {
    Date date = x509.getNextUpdate();
    return date == null ? null : date.toInstant();
  }

  public Extensions extensions() {
    return x509.getExtensions();
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(getEncoded());
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) return true;

    if (!(obj instanceof X509Crl)) return false;

    return Arrays.equals(getEncoded(), ((X509Crl) obj).getEncoded());
  }

  @Override
  public String toString() {
    return x509.toString();
  }

}
