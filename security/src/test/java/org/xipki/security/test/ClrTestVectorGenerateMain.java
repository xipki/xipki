// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.test;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.xipki.security.*;
import org.xipki.util.ConfPairs;
import org.xipki.util.IoUtil;

import java.math.BigInteger;
import java.util.Date;

/**
 * Generate CRL test vectors.
 *
 * @author Lijun Liao
 */
public class ClrTestVectorGenerateMain {

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

      SignerConf sconf = new SignerConf(conf.getEncoded(), null, new SignatureAlgoControl());

      ConcurrentContentSigner csigner = securities.getSecurityFactory().createSigner(
          "PKCS12", sconf, (X509Cert) null);
      X509Cert caCert = csigner.getCertificate();

      ConcurrentBagEntrySigner signer = csigner.borrowSigner();
      // no revoked certs
      X509v2CRLBuilder builder = getBuilder(caCert, true, true);
      buildCrl(builder, signer, "no-revoked-certs.crl");

      Date revokedDate = new Date(System.currentTimeMillis() - 24 * 2600 * 1000L);
      Date invalidityDate = new Date(System.currentTimeMillis() - 48 * 2600 * 1000L);

      // with revoked certs
      builder = getBuilder(caCert, true, true);
      builder.addCRLEntry(BigInteger.valueOf(254), revokedDate, CRLReason.unspecified);
      builder.addCRLEntry(BigInteger.valueOf(255), revokedDate, CRLReason.keyCompromise);
      buildCrl(builder, signer, "revoked-certs.crl");

      // with invalidity date
      builder = getBuilder(caCert, true, true);
      builder.addCRLEntry(BigInteger.valueOf(255), revokedDate, CRLReason.keyCompromise,
          invalidityDate);
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

  private static void buildCrl(X509v2CRLBuilder builder, ConcurrentBagEntrySigner signer, String fn)
      throws Exception {
    byte[] encoded = builder.build(signer.value()).getEncoded();
    IoUtil.save("output/" + fn, encoded);
  }

  private static X509v2CRLBuilder getBuilder(X509Cert caCert, boolean addCrlNumber, boolean addAki)
      throws Exception {
    Date thisUpdate = new Date();
    X509v2CRLBuilder builder = new X509v2CRLBuilder(caCert.getSubject(), thisUpdate);
    builder.setNextUpdate(new Date(thisUpdate.getTime() + 50L * 365 * 24 * 60 * 60 * 1000));
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
