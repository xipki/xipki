// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.ocsp.BasicOCSPResponse;
import org.xipki.asn1.ocsp.OCSPResponse;
import org.xipki.asn1.ocsp.OCSPResponseStatus;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.test.CaH2TestEnv;
import org.xipki.codec.Base64;
import org.xipki.crypto.core.KeySpec;
import org.xipki.ocsp.server.OcspServer;
import org.xipki.ocsp.server.Responder;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.pkcs11.P11Module;
import org.xipki.pkix.pkcs11.P11Slot;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.misc.NameId;

import java.math.BigInteger;
import java.security.Signature;

/**
 * OCSP responder with the signer key on the in-memory HSM xihsm: the CA with the key on the
 * token answers itself (signer type {@code pkcs11}, certificate = CA certificate).
 *
 * @author Lijun Liao (xipki)
 */
public class OcspPkcs11H2Test {

  private static final String CA = "p11ca";

  private static final String KEY_LABEL = "p11-ocsp-key";

  private static CaH2TestEnv env;

  private static OcspServer server;

  private static Responder responder;

  private static X509Cert caCert;

  private static BigInteger serial;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv(new CaH2TestEnv.Options().pkcs11(true).extraDatabases("ocsp"));
    CaManagerImpl caManager = env.caManager();
    P11Module module = env.securities().p11CryptServiceFactory()
        .getP11Module(CaH2TestEnv.P11_MODULE);
    P11Slot slot = module.getSlot(module.getSlotIdForIndex(0));
    slot.generateKeyPair(KeySpec.P256,
        new PKCS11KeyPairSpec().token(true).label(KEY_LABEL).signVerify(true));

    String signerConf = "module=" + CaH2TestEnv.P11_MODULE + ",slot=0,key-label=" + KEY_LABEL
        + ",algo=" + CaH2TestEnv.SIG_ALGO;
    caCert = caManager.generateRootCa(CaH2TestEnv.newCaEntry(CA, "pkcs11", signerConf),
        "rootca", "CN=" + CA + ",O=myorg,C=DE", "1", null, null).x509Cert();
    caManager.addCertprofileToCa(CaH2TestEnv.PROFILE_TLS, CA);
    caManager.addPublisher(new PublisherEntry(new NameId(null, "ocsp-publisher"), "ocsp",
        "datasource=ocsp,publish.goodcerts=true"));
    caManager.addPublisherToCa("ocsp-publisher", CA);
    serial = X509Util.parseCert(caManager.generateKeyCert(CA, CaH2TestEnv.PROFILE_TLS,
        "CN=p11-ocsp.example.org,O=myorg,C=DE", null, null).cert()).serialNumber();

    server = new OcspServer(env.workDir().toString());
    server.setSecurityFactory(env.securities().securityFactory());
    server.setConfFile(OcspTestUtil.writeResponderConf(env.workDir(), env.ocspDbConf(),
        "{\"datasource\": \"ocspdb\", \"type\": \"xipki-db\", \"conf\": {}}", "unknown", "",
        "\"type\": \"pkcs11\",\n"
        + "    \"key\": \"" + signerConf + "\",\n"
        + "    \"cert\": {\"binary\": \"" + Base64.encodeToString(caCert.getEncoded()) + "\"}")
        .toString());
    server.init(true);
    responder = server.getResponder("responder1");
    Assert.assertNotNull("responder1", responder);
  }

  @AfterClass
  public static void shutdown() {
    if (server != null) {
      server.close();
    }
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void responseIsSignedWithTheTokenKey() throws Exception {
    Assert.assertEquals("good", 0, OcspTestUtil.status(server, responder, caCert, serial).getTagNo());

    OCSPResponse resp = OCSPResponse.fromEncoded(server.answer(responder,
        OcspTestUtil.request(OcspTestUtil.certId(caCert, serial)), false).response());
    Assert.assertEquals(OCSPResponseStatus.SUCCESSFUL, resp.getResponseStatus());
    BasicOCSPResponse basic = resp.getBasicOCSPResponse();

    Signature sig = Signature.getInstance("SHA256withECDSA");
    sig.initVerify(caCert.publicKey());
    sig.update(basic.getTbsResponseData().getEncoded());
    Assert.assertTrue("signature of the response", sig.verify(basic.signature()));
  }

}
