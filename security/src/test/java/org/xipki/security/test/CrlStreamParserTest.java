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

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.security.asn1.CrlStreamParser;
import org.xipki.security.asn1.CrlStreamParser.RevokedCertsIterator;
import org.xipki.security.util.X509Util;

import javax.security.cert.CertificateEncodingException;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;

/**
 * CRL Stream Parser test.
 *
 * @author Lijun Liao
 */
public class CrlStreamParserTest {

  private static final String baseDir = "src/test/resources/crls/";

  @BeforeClass
  public static void init() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

  }

  private static Certificate getIssuerSigner()
      throws CertificateEncodingException, IOException {
    return parseCert(baseDir + "ca.crt");
  }

  private static CrlStreamParser getParser(String crlFile)
      throws IOException {
    return new CrlStreamParser(new File(baseDir + crlFile));
  }

  @Test
  public void parseCrl_revoked()
      throws Exception {
    Certificate issuerSigner = getIssuerSigner();
    CrlStreamParser parser = getParser("revoked-certs.crl");

    Assert.assertEquals("version", 1, parser.getVersion());
    Assert.assertEquals("CRL number", BigInteger.valueOf(1), parser.getCrlNumber());

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
  public void parseCrlWithInvalidityDate()
      throws Exception {
    Certificate issuerSigner = getIssuerSigner();
    CrlStreamParser parser = getParser("invaliditydate.crl");

    Assert.assertEquals("version", 1, parser.getVersion());
    Assert.assertEquals("CRL number", BigInteger.valueOf(1), parser.getCrlNumber());

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
  public void parseCrlWithNoRevokedCerts()
      throws Exception {
    Certificate issuerSigner = getIssuerSigner();
    CrlStreamParser parser = getParser("no-revoked-certs.crl");

    Assert.assertEquals("version", 1, parser.getVersion());
    Assert.assertEquals("CRL number", BigInteger.valueOf(1), parser.getCrlNumber());

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
  public void parseCrlWithNoCrlNumber()
      throws Exception {
    Certificate issuerSigner = getIssuerSigner();
    CrlStreamParser parser = getParser("no-crlnumber.crl");

    Assert.assertEquals("version", 1, parser.getVersion());
    Assert.assertNull("CRL number", parser.getCrlNumber());

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
  public void parseCrlWithNoExtension()
      throws Exception {
    Certificate issuerSigner = getIssuerSigner();
    CrlStreamParser parser = getParser("no-extensions.crl");

    Assert.assertEquals("version", 1, parser.getVersion());
    Assert.assertNull("CRL number", parser.getCrlNumber());

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
