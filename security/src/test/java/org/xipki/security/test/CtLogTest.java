// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.test;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ctlog.CtLog.SignedCertificateTimestamp;
import org.xipki.security.ctlog.CtLog.SignedCertificateTimestampList;
import org.xipki.security.util.X509Util;
import org.xipki.util.IoUtil;

/**
 * CTLog test.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class CtLogTest {

  @Test
  public void parseCtLogInCerts() throws Exception {
    String[] certFiles = new String[]{"/ctlog-certs/githubcom.pem", "/ctlog-certs/cab-domain-validated1.crt"};

    for (String m : certFiles) {
      try {
        parseCtLogInCert(m);
      } catch (Exception ex) {
        throw new Exception("exception throw while parsing CT Log in file " + m, ex);
      }
    }
  }

  private void parseCtLogInCert(String certFile) throws Exception {
    byte[] certBytes = IoUtil.readAllBytesAndClose(getClass().getResourceAsStream(certFile));
    certBytes = X509Util.toDerEncoded(certBytes);
    Certificate cert = Certificate.getInstance(certBytes);
    Extension extn = cert.getTBSCertificate().getExtensions().getExtension(ObjectIdentifiers.Extn.id_SCTs);
    byte[] encodedScts = DEROctetString.getInstance(extn.getParsedValue()).getOctets();
    SignedCertificateTimestampList sctList2 = SignedCertificateTimestampList.getInstance(encodedScts);
    SignedCertificateTimestamp sct = sctList2.getSctList().get(0);
    sct.getDigitallySigned().getEncoded();
    Object signatureObject = sctList2.getSctList().get(0).getDigitallySigned().getSignatureObject();
    Assert.assertNotNull("signatureObject", signatureObject);
    Assert.assertArrayEquals(encodedScts, sctList2.getEncoded());
  }

}
