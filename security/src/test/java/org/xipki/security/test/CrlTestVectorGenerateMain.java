// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.test;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.Securities;
import org.xipki.security.SignatureAlgoControl;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.security.XiContentSigner;
import org.xipki.util.ConfPairs;
import org.xipki.util.IoUtil;

import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * Generate CRL test vectors.
 *
 * @author Lijun Liao (xipki)
 */
public class CrlTestVectorGenerateMain {

  public static void main(String[] args) {
    try {
      genTestVectors();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  private static void genTestVectors() throws Exception {
    try (Securities securities = new Securities()) {
      securities.init();

      ConfPairs conf = new ConfPairs()
          .putPair("parallelism", Integer.toString(1))
          .putPair("password", "1234")
          .putPair("keystore", "file:src/test/resources/crls/ca.p12");

      SignerConf sconf = new SignerConf(conf.getEncoded(), new SignatureAlgoControl());

      ConcurrentContentSigner csigner = securities.getSecurityFactory().createSigner(
          "PKCS12", sconf, (X509Cert) null);
      X509Cert caCert = csigner.getCertificate();

      XiContentSigner signer = csigner.borrowSigner();
      // no revoked certs
      X509v2CRLBuilder builder = getBuilder(caCert, true, true);
      buildCrl(builder, signer, "no-revoked-certs.crl");

      Instant now = Instant.now();
      Date revokedDate = Date.from(now.minus(1, ChronoUnit.DAYS));
      Date invalidityDate = Date.from(now.minus(2, ChronoUnit.DAYS));

      // with revoked certs
      builder = getBuilder(caCert, true, true);
      builder.addCRLEntry(BigInteger.valueOf(254), revokedDate, CRLReason.unspecified);
      builder.addCRLEntry(BigInteger.valueOf(255), revokedDate, CRLReason.keyCompromise);
      buildCrl(builder, signer, "revoked-certs.crl");

      // with invalidity date
      builder = getBuilder(caCert, true, true);
      builder.addCRLEntry(BigInteger.valueOf(255), revokedDate, CRLReason.keyCompromise, invalidityDate);
      buildCrl(builder, signer, "invaliditydate.crl");

      // no crlnumber
      builder = getBuilder(caCert, false, true);
      builder.addCRLEntry(BigInteger.valueOf(254), revokedDate, CRLReason.unspecified);
      builder.addCRLEntry(BigInteger.valueOf(255), revokedDate, CRLReason.keyCompromise);
      buildCrl(builder, signer, "no-crlnumber.crl");

      // no extension
      builder = getBuilder(caCert, false, false);
      builder.addCRLEntry(BigInteger.valueOf(254), revokedDate, CRLReason.unspecified);
      builder.addCRLEntry(BigInteger.valueOf(255), revokedDate, CRLReason.keyCompromise);
      buildCrl(builder, signer, "no-extensions.crl");
    }
  }

  private static void buildCrl(X509v2CRLBuilder builder, XiContentSigner signer, String fn)
      throws Exception {
    byte[] encoded = builder.build(signer).getEncoded();
    IoUtil.save("output/" + fn, encoded);
  }

  private static X509v2CRLBuilder getBuilder(X509Cert caCert, boolean addCrlNumber, boolean addAki)
      throws Exception {
    Instant thisUpdate = Instant.now();
    X509v2CRLBuilder builder = new X509v2CRLBuilder(caCert.getSubject(), Date.from(thisUpdate));
    builder.setNextUpdate(Date.from(thisUpdate.plus(50 * 365, ChronoUnit.DAYS)));
    if (addCrlNumber) {
      builder.addExtension(Extension.cRLNumber, false, new ASN1Integer(BigInteger.ONE));
    }

    if (addAki) {
      builder.addExtension(Extension.authorityKeyIdentifier, false,
          new AuthorityKeyIdentifier(caCert.getSubjectKeyId()));
    }

    return builder;
  }

}
