// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.KeypairGenEntry;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkix.cert.KeyCertBytesPair;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.cert.X509Crl;
import org.xipki.pkix.pkcs11.P11Module;
import org.xipki.pkix.pkcs11.P11Slot;
import org.xipki.pkix.util.X509Util;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;

/**
 * The CA with PKCS#11, on the in-memory HSM xihsm ({@code xihsm:mem}): CA signer with the key
 * on the token (certificates and CRLs), the PKCS#11 keypair generator for server-side key
 * generation, and the token information.
 *
 * @author Lijun Liao (xipki)
 */
public class Pkcs11H2Test {

  private static final String MODULE = CaH2TestEnv.P11_MODULE;

  private static CaH2TestEnv env;

  private static CaManagerImpl caManager;

  private static P11Slot slot;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv(new CaH2TestEnv.Options().pkcs11(true));
    caManager = env.caManager();
    P11Module module = env.securities().p11CryptServiceFactory().getP11Module(MODULE);
    slot = module.getSlot(module.getSlotIdForIndex(0));
  }

  @AfterClass
  public static void shutdown() {
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void caWithKeyOnTheToken() throws Exception {
    X509Cert caCert = newP11Ca("p11ca", "p11-ca-key");
    Assert.assertTrue("self-signed", caCert.isSelfSigned());
    caCert.verify(caCert.publicKey());

    // certificates and CRLs are signed with the key on the token
    X509Cert cert = X509Util.parseCert(caManager.generateKeyCert("p11ca",
        CaH2TestEnv.PROFILE_TLS, "CN=p11.example.org,O=myorg,C=DE", null, null).cert());
    cert.verify(caCert.publicKey());

    X509Crl crl = caManager.generateCrlOnDemand("p11ca").x509Crl();
    X509CRL jceCrl = (X509CRL) CertificateFactory.getInstance("X.509")
        .generateCRL(new ByteArrayInputStream(crl.getEncoded()));
    jceCrl.verify(caCert.publicKey());
  }

  @Test
  public void caSignsOnlyWithTheTokenKey() throws Exception {
    newP11Ca("p11ca-destroy", "p11-destroy-key");
    caManager.generateKeyCert("p11ca-destroy", CaH2TestEnv.PROFILE_TLS,
        "CN=p11-before.example.org,O=myorg,C=DE", null, null);

    // without the key on the token the CA cannot sign anymore
    Assert.assertTrue(slot.destroyObjectsByIdLabel(null, "p11-destroy-key") > 0);
    Assert.assertThrows(CaMgmtException.class, () -> caManager.generateKeyCert("p11ca-destroy",
        CaH2TestEnv.PROFILE_TLS, "CN=p11-after.example.org,O=myorg,C=DE", null, null));
  }

  @Test
  public void unknownKeyLabelIsRejected() {
    Assert.assertThrows(CaMgmtException.class, () -> caManager.generateRootCa(
        CaH2TestEnv.newCaEntry("p11ca-nokey", "pkcs11", signerConf("no-such-key")),
        "rootca", "CN=p11ca-nokey,O=myorg,C=DE", "1", null, null));
    Assert.assertFalse(caManager.getCaNames().contains("p11ca-nokey"));
  }

  @Test
  public void keypairGeneratorOnTheToken() throws Exception {
    caManager.addKeypairGen(new KeypairGenEntry("p11gen", "pkcs11",
        "module=" + MODULE + ",slot=0,keyspecs=P256"));
    CaEntry entry = CaH2TestEnv.newCaEntry("p11ca-gen");
    entry.base().setKeypairGenNames(List.of("p11gen"));
    caManager.generateRootCa(entry, "rootca", "CN=p11ca-gen,O=myorg,C=DE", "1", null, null);
    caManager.addCertprofileToCa(CaH2TestEnv.PROFILE_TLS, "p11ca-gen");

    KeyCertBytesPair keyCert = caManager.generateKeyCert("p11ca-gen", CaH2TestEnv.PROFILE_TLS,
        "CN=p11-gen.example.org,O=myorg,C=DE", null, null);
    X509Cert cert = X509Util.parseCert(keyCert.cert());

    // the returned private key belongs to the certificate
    PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(
        new PKCS8EncodedKeySpec(keyCert.key()));
    byte[] data = "data".getBytes(StandardCharsets.US_ASCII);
    Signature sig = Signature.getInstance("SHA256withECDSA");
    sig.initSign(key);
    sig.update(data);
    byte[] signature = sig.sign();
    sig.initVerify(cert.publicKey());
    sig.update(data);
    Assert.assertTrue("private key matches the certificate", sig.verify(signature));
  }

  @Test
  public void tokenInfo() throws Exception {
    slot.generateKeyPair(KeySpec.P256,
        new PKCS11KeyPairSpec().token(true).label("p11-info-key").signVerify(true));

    String modules = caManager.getTokenInfoP11(MODULE, null, false);
    Assert.assertTrue(modules, modules.contains("module: " + MODULE));

    String details = caManager.getTokenInfoP11(MODULE, 0, true);
    Assert.assertTrue(details, details.contains("p11-info-key"));

    Assert.assertThrows(CaMgmtException.class,
        () -> caManager.getTokenInfoP11("unknown-module", null, false));
  }

  // ---------------------------------------------------------------- helpers

  /** Generates a P-256 key pair on the token and a root CA with this key. */
  private static X509Cert newP11Ca(String name, String keyLabel) throws Exception {
    slot.generateKeyPair(KeySpec.P256,
        new PKCS11KeyPairSpec().token(true).label(keyLabel).signVerify(true));
    X509Cert caCert = caManager.generateRootCa(
        CaH2TestEnv.newCaEntry(name, "pkcs11", signerConf(keyLabel)),
        "rootca", "CN=" + name + ",O=myorg,C=DE", "1", null, null).x509Cert();
    caManager.addCertprofileToCa(CaH2TestEnv.PROFILE_TLS, name);
    return caCert;
  }

  private static String signerConf(String keyLabel) {
    return "module=" + MODULE + ",slot=0,key-label=" + keyLabel + ",algo="
        + CaH2TestEnv.SIG_ALGO;
  }

}
