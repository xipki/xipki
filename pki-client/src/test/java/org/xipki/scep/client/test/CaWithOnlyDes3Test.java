// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.asn1.pkcs10.CertificationRequest;
import org.xipki.asn1.x500.X500Name;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.scep.message.CaCaps;
import org.xipki.pkix.scep.transaction.CaCapability;
import org.xipki.scep.client.CaCertValidator;
import org.xipki.scep.client.CaIdentifier;
import org.xipki.scep.client.ScepClient;
import org.xipki.scep.client.ScepClientException;
import org.xipki.util.http.DefaultCurl;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Test CA which offers DES3 but not AES: the client does not use DES3 and refuses to send the
 * request.
 *
 * @author Lijun Liao (xipki)
 */
public class CaWithOnlyDes3Test extends AbstractCaTest {

  @Override
  protected boolean isWithRa() {
    return false;
  }

  @Override
  protected CaCapability[] getExcludedCaCaps() {
    // SCEPStandard implies AES
    return new CaCapability[]{CaCapability.AES, CaCapability.SCEPStandard};
  }

  @Override
  @Test
  public void test() throws Exception {
    CaIdentifier caId = new CaIdentifier("http://localhost:" + port + "/scep/pkiclient.exe", null);
    ScepClient client = new ScepClient(caId,
        new CaCertValidator.PreprovisionedCaCertValidator(scepServer.caCert()),
        new DefaultCurl());
    client.refresh();
    CaCaps caCaps = client.caCaps();
    Assert.assertTrue("DES3", caCaps.supportsDES3());
    Assert.assertFalse("AES", caCaps.supportsAES());

    KeyPairGenerator kpGen = CryptoApiFactory.get().newKeyPairGenerator("RSA");
    kpGen.initialize(2048);
    KeyPair kp = kpGen.generateKeyPair();
    SubjectPublicKeyInfo spki = MyUtil.createSubjectPublicKeyInfo(kp.getPublic());
    CertificationRequest p10Req = MyUtil.generateRequest(kp.getPrivate(), spki,
        new X500Name("CN=EE1, OU=emulator, O=myorg.org, C=DE"), secret, null);
    X509Cert selfSignedCert = MyUtil.generateSelfsignedCert(p10Req, kp.getPrivate());

    ScepClientException e = Assert.assertThrows(ScepClientException.class,
        () -> client.scepPkcsReq(p10Req, kp.getPrivate(), selfSignedCert));
    Assert.assertTrue(e.getMessage(), e.getMessage().contains("does not support AES"));
  }

}
