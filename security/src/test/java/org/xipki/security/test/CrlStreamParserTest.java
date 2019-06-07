/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.math.BigInteger;
import java.security.Security;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.asn1.CrlCertSetStreamParser;
import org.xipki.security.asn1.CrlCertSetStreamParser.CrlCertsIterator;
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
    Certificate issuerSigner = X509Util.parseBcCert(
        new File("src/test/resources/crls/crl-1/ca.crt"));

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
    Certificate issuerSigner = X509Util.parseBcCert(
        new File("src/test/resources/crls/crl-2/ca1-cert.crt"));

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
  public void parseCrlWithInvalidityDateAndXipkiSet() throws Exception {
    File crlFile = new File("src/test/resources/crls/crl-3/subcawithcrl1.crl");
    Certificate issuerSigner = X509Util.parseBcCert(
        new File("src/test/resources/crls/crl-3/ca.crt"));

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

    Assert.assertEquals("#revokedCertificates", 3, numRevokedCerts);

    Extensions extensions = parser.getCrlExtensions();
    Assert.assertNotNull("extensions", extensions);
    byte[] coreExtValue = X509Util.getCoreExtValue(
        extensions, ObjectIdentifiers.Xipki.id_xipki_ext_crlCertset);
    CrlCertSetStreamParser crlCertParser =
        new CrlCertSetStreamParser(new ByteArrayInputStream(coreExtValue));
    CrlCertsIterator crlCerts = crlCertParser.crlCerts();

    int numCrlCerts = 0;
    while (crlCerts.hasNext()) {
      crlCerts.next();
      numCrlCerts++;
    }

    Assert.assertEquals("#numCrlCerts", 15, numCrlCerts);
  }

}
