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

package org.xipki.security.test;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;

import javax.security.cert.CertificateEncodingException;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.security.asn1.CrlStreamParser;
import org.xipki.security.asn1.CrlStreamParser.RevokedCertsIterator;
import org.xipki.security.util.X509Util;

import junit.framework.Assert;

/**
 * CRL Stream Parser test.
 *
 * @author Lijun Liao
 *
 */
public class CrlStreamParserTest {

  @BeforeClass
  public static void init() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void parseCrl1() throws Exception {
    File crlFile = new File("src/test/resources/crls/crl-1/subcawithcrl1.crl");
    Certificate issuerSigner = parseCert("src/test/resources/crls/crl-1/ca.crt");

    CrlStreamParser parser = new CrlStreamParser(crlFile);
    Assert.assertEquals("version", 1, parser.getVersion());
    Assert.assertEquals("CRL number", BigInteger.valueOf(3), parser.getCrlNumber());

    Assert.assertTrue("signature", parser.verifySignature(issuerSigner.getSubjectPublicKeyInfo()));

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
  public void parseCrl2() throws Exception {
    File crlFile = new File("src/test/resources/crls/crl-2/ca1-crl.crl");
    Certificate issuerSigner = parseCert("src/test/resources/crls/crl-2/ca1-cert.crt");

    CrlStreamParser parser = new CrlStreamParser(crlFile);
    Assert.assertEquals("version", 1, parser.getVersion());
    Assert.assertEquals("CRL number", BigInteger.valueOf(5), parser.getCrlNumber());

    Assert.assertTrue("signature", parser.verifySignature(issuerSigner.getSubjectPublicKeyInfo()));

    int numRevokedCerts = 0;

    try (RevokedCertsIterator iterator = parser.revokedCertificates()) {
      while (iterator.hasNext()) {
        iterator.next();
        numRevokedCerts++;
      }
    }

    Assert.assertEquals("#revokedCertificates", 6, numRevokedCerts);
  }

  @Test
  public void parseCrlWithInvalidityDate() throws Exception {
    File crlFile = new File("src/test/resources/crls/crl-3/subcawithcrl1.crl");
    Certificate issuerSigner = parseCert("src/test/resources/crls/crl-3/ca.crt");

    CrlStreamParser parser = new CrlStreamParser(crlFile);
    Assert.assertEquals("version", 1, parser.getVersion());
    Assert.assertEquals("CRL number", BigInteger.valueOf(5), parser.getCrlNumber());

    Assert.assertTrue("signature", parser.verifySignature(issuerSigner.getSubjectPublicKeyInfo()));

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
  public void parseCrlWithNoRevokedCerts() throws Exception {
    File crlFile = new File("src/test/resources/crls/crl-4/no-revoked-certs.crl");
    Certificate issuerSigner = parseCert("src/test/resources/crls/crl-4/ca.crt");

    CrlStreamParser parser = new CrlStreamParser(crlFile);
    Assert.assertEquals("version", 1, parser.getVersion());
    Assert.assertEquals("CRL number", BigInteger.valueOf(6), parser.getCrlNumber());

    Assert.assertTrue("signature", parser.verifySignature(issuerSigner.getSubjectPublicKeyInfo()));

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
    File crlFile = new File("src/test/resources/crls/crl-5/no-crlnumber.crl");
    Certificate issuerSigner = parseCert("src/test/resources/crls/crl-5/ca.crt");

    CrlStreamParser parser = new CrlStreamParser(crlFile);
    Assert.assertEquals("version", 1, parser.getVersion());
    Assert.assertEquals("CRL number", null, parser.getCrlNumber());

    Assert.assertTrue("signature", parser.verifySignature(issuerSigner.getSubjectPublicKeyInfo()));

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
  public void parseCrlWithNoExtension() throws Exception {
    File crlFile = new File("src/test/resources/crls/crl-6/no-extensions.crl");
    Certificate issuerSigner = parseCert("src/test/resources/crls/crl-6/ca.crt");

    CrlStreamParser parser = new CrlStreamParser(crlFile);
    Assert.assertEquals("version", 1, parser.getVersion());
    Assert.assertEquals("CRL number", null, parser.getCrlNumber());

    Assert.assertTrue("signature", parser.verifySignature(issuerSigner.getSubjectPublicKeyInfo()));

    int numRevokedCerts = 0;

    try (RevokedCertsIterator iterator = parser.revokedCertificates()) {
      while (iterator.hasNext()) {
        iterator.next();
        numRevokedCerts++;
      }
    }

    Assert.assertEquals("#revokedCertificates", 0, numRevokedCerts);
  }

  private static Certificate parseCert(String fileName)
      throws IOException, CertificateEncodingException {
    try {
      return Certificate.getInstance(
          X509Util.toDerEncoded(Files.readAllBytes(Paths.get(fileName))));
    } catch (RuntimeException ex) {
      throw new CertificateEncodingException("error decoding certificate: " + ex.getMessage());
    }
  }
}
