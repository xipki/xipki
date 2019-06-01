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

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.security.CtLog.SignedCertificateTimestamp;
import org.xipki.security.CtLog.SignedCertificateTimestampList;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.util.X509Util;

/**
 * CTLog test.
 *
 * @author Lijun Liao
 *
 */
public class CtLogTest {

  @Test
  public void parseCtLogInCerts() throws Exception {
    String[] certFiles = new String[]{
        "/ctlog-certs/githubcom.pem",
        "/ctlog-certs/cab-domain-validated1.crt"
    };

    for (String m : certFiles) {
      try {
        parseCtLogInCert(m);
      } catch (Exception ex) {
        throw new Exception("exception throw while parsing CT Log in file " + m, ex);
      }
    }
  }

  private void parseCtLogInCert(String certFile) throws Exception {
    Certificate cert = X509Util.parseBcCert(
        getClass().getResourceAsStream(certFile));
    Extension extn = cert.getTBSCertificate().getExtensions().getExtension(
                        ObjectIdentifiers.Extn.id_SCTs);
    byte[] encodedScts = DEROctetString.getInstance(extn.getParsedValue()).getOctets();
    SignedCertificateTimestampList sctList2 =
        SignedCertificateTimestampList.getInstance(encodedScts);
    SignedCertificateTimestamp sct = sctList2.getSctList().get(0);
    sct.getDigitallySigned().getEncoded();
    sctList2.getSctList().get(0).getDigitallySigned().getSignatureObject();
    byte[] encoded2 = sctList2.getEncoded();
    Assert.assertArrayEquals(encodedScts, encoded2);
  }

}
