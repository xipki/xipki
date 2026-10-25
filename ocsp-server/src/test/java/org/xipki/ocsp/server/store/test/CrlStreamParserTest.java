// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.store.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.codec.exception.CodecException;
import org.xipki.ocsp.server.store.CrlStreamParser;
import org.xipki.ocsp.server.store.CrlStreamParser.RevokedCertsIterator;
import org.xipki.pkix.util.X509Util;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

/**
 * CRL Stream Parser test.
 *
 * @author Lijun Liao (xipki)
 */
public class CrlStreamParserTest {

  private static final String baseDir = "src/test/resources/crls/";

  private static Certificate getIssuerSigner() throws CertificateEncodingException, IOException {
    return parseCert(baseDir + "ca.crt");
  }

  private static CrlStreamParser getParser(String crlFile) throws IOException, CodecException {
    return new CrlStreamParser(new File(baseDir + crlFile));
  }

  @Test
  public void parseCrlWithoutNextUpdate() throws Exception {
    // remove the nextUpdate from a CRL without revoked certificates but with extensions:
    // the crlExtensions follow directly the thisUpdate.
    Asn1Sequence crl = Asn1Sequence.fromEncoded(
        Files.readAllBytes(Paths.get(baseDir + "no-revoked-certs.crl")));
    Asn1Sequence tbs = crl.getSequenceAt(0);
    // version, signature, issuer, thisUpdate, nextUpdate, crlExtensions
    Assert.assertEquals("tbsCertList.size", 6, tbs.size());

    List<Asn1Primitive> tbsFields = new ArrayList<>(5);
    for (int i = 0; i < tbs.size(); i++) {
      if (i != 4) {
        tbsFields.add(tbs.getObjectAt(i));
      }
    }

    Asn1Sequence newCrl = new Asn1Sequence(
        new Asn1Sequence(tbsFields), crl.getObjectAt(1), crl.getObjectAt(2));
    Path crlFile = Files.createTempFile("crl-", ".crl");
    try {
      Files.write(crlFile, newCrl.getEncoded());
      CrlStreamParser parser = new CrlStreamParser(crlFile.toFile());
      Assert.assertNull("nextUpdate", parser.nextUpdate());
      Assert.assertEquals("CRL number", BigInteger.valueOf(1), parser.crlNumber());
      try (RevokedCertsIterator it = parser.revokedCertificates()) {
        Assert.assertFalse("has revoked certificates", it.hasNext());
      }
    } finally {
      Files.deleteIfExists(crlFile);
    }
  }

  @Test
  public void parseCrl_revoked() throws Exception {
    Certificate issuerSigner = getIssuerSigner();
    CrlStreamParser parser = getParser("revoked-certs.crl");

    Assert.assertEquals("version", 1, parser.version());
    Assert.assertEquals("CRL number", BigInteger.valueOf(1), parser.crlNumber());

    Assert.assertTrue("signature",
        parser.verifySignature(issuerSigner.getSubjectPublicKeyInfo()));

    int numRevokedCerts = 0;

    try (RevokedCertsIterator iterator = parser.revokedCertificates()) {
      while (iterator.hasNext()) {
        iterator.next();
        numRevokedCerts++;
      }
    }

    Assert.assertEquals("#revokedCertificates", 2, numRevokedCerts);
  }

  @Test
  public void parseCrlWithInvalidityDate() throws Exception {
    Certificate issuerSigner = getIssuerSigner();
    CrlStreamParser parser = getParser("invaliditydate.crl");

    Assert.assertEquals("version", 1, parser.version());
    Assert.assertEquals("CRL number", BigInteger.valueOf(1), parser.crlNumber());

    Assert.assertTrue("signature",
        parser.verifySignature(issuerSigner.getSubjectPublicKeyInfo()));

    int numRevokedCerts = 0;

    try (RevokedCertsIterator iterator = parser.revokedCertificates()) {
      while (iterator.hasNext()) {
        iterator.next();
        numRevokedCerts++;
      }
    }

    Assert.assertEquals("#revokedCertificates", 1, numRevokedCerts);
  }

  @Test
  public void parseCrlWithNoRevokedCerts() throws Exception {
    Certificate issuerSigner = getIssuerSigner();
    CrlStreamParser parser = getParser("no-revoked-certs.crl");

    Assert.assertEquals("version", 1, parser.version());
    Assert.assertEquals("CRL number", BigInteger.valueOf(1), parser.crlNumber());

    Assert.assertTrue("signature",
        parser.verifySignature(issuerSigner.getSubjectPublicKeyInfo()));

    int numRevokedCerts = 0;

    try (RevokedCertsIterator iterator = parser.revokedCertificates()) {
      while (iterator.hasNext()) {
        iterator.next();
        numRevokedCerts++;
      }
    }

    Assert.assertEquals("#revokedCertificates", 0, numRevokedCerts);
  }

  @Test
  public void parseCrlWithNoCrlNumber() throws Exception {
    Certificate issuerSigner = getIssuerSigner();
    CrlStreamParser parser = getParser("no-crlnumber.crl");

    Assert.assertEquals("version", 1, parser.version());
    Assert.assertNull("CRL number", parser.crlNumber());

    Assert.assertTrue("signature",
        parser.verifySignature(issuerSigner.getSubjectPublicKeyInfo()));

    int numRevokedCerts = 0;

    try (RevokedCertsIterator iterator = parser.revokedCertificates()) {
      while (iterator.hasNext()) {
        iterator.next();
        numRevokedCerts++;
      }
    }

    Assert.assertEquals("#revokedCertificates", 2, numRevokedCerts);
  }

  @Test
  public void parseCrlWithNoExtension() throws Exception {
    Certificate issuerSigner = getIssuerSigner();
    CrlStreamParser parser = getParser("no-extensions.crl");

    Assert.assertEquals("version", 1, parser.version());
    Assert.assertNull("CRL number", parser.crlNumber());

    Assert.assertTrue("signature",
        parser.verifySignature(issuerSigner.getSubjectPublicKeyInfo()));

    int numRevokedCerts = 0;

    try (RevokedCertsIterator iterator = parser.revokedCertificates()) {
      while (iterator.hasNext()) {
        iterator.next();
        numRevokedCerts++;
      }
    }

    Assert.assertEquals("#revokedCertificates", 2, numRevokedCerts);
  }

  private static Certificate parseCert(String fileName)
      throws IOException, CertificateEncodingException {
    try {
      return Certificate.fromEncoded(
          X509Util.toDerEncoded(Files.readAllBytes(Paths.get(fileName))));
    } catch (CodecException ex) {
      throw new CertificateEncodingException("error decoding certificate: " + ex.getMessage());
    }
  }
}
