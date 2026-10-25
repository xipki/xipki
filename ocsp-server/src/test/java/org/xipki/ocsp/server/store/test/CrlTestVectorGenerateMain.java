// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.store.test;

import org.xipki.pkix.asn1.x509.AuthorityKeyIdentifier;
import org.xipki.pkix.asn1.x509.CRLReason;
import org.xipki.pkix.asn1.x509.CertificateList;
import org.xipki.pkix.asn1.x509.Extension;
import org.xipki.pkix.Securities;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.Signer;
import org.xipki.pkix.sign.SignerConf;
import org.xipki.codec.util.IoUtil;

import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

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

      SignerConf conf = new SignerConf()
          .setParallelism(1)
          .setPassword("1234")
          .setKeystore("file:src/test/resources/crls/ca.p12");

      ConcurrentSigner csigner = securities.securityFactory()
          .createSigner("PKCS12", conf, (X509Cert) null);
      X509Cert caCert = csigner.x509Cert();

      Signer signer = csigner.borrowSigner();
      // no revoked certs
      CertificateList.V2CRLBuilder builder = getBuilder(caCert, true, true);
      buildCrl(builder, signer, "no-revoked-certs.crl");

      Instant now = Instant.now();
      Instant revokedDate = now.minus(1, ChronoUnit.DAYS);
      Instant invalidityDate = now.minus(2, ChronoUnit.DAYS);

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

  private static void buildCrl(CertificateList.V2CRLBuilder builder, Signer signer, String fn)
      throws Exception {
    byte[] encoded = builder.build(signer.x509Signer()).getEncoded();
    IoUtil.save("output/" + fn, encoded);
  }

  private static CertificateList.V2CRLBuilder getBuilder(
      X509Cert caCert, boolean addCrlNumber, boolean addAki)
      throws Exception {
    Instant thisUpdate = Instant.now();
    CertificateList.V2CRLBuilder builder =
        new CertificateList.V2CRLBuilder(caCert.subject(), thisUpdate);
    builder.setNextUpdate(thisUpdate.plus(50 * 365, ChronoUnit.DAYS));
    if (addCrlNumber) {
      builder.addExtension(Extension.ofCRLNumber(false, 1));
    }

    if (addAki) {
      builder.addExtension(Extension.ofAuthorityKeyIdentifier(false,
          new AuthorityKeyIdentifier(caCert.subjectKeyId())));
    }

    return builder;
  }

}
