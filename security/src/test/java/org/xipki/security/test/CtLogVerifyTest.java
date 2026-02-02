// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.test;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.security.HashAlgo;
import org.xipki.security.OIDs;
import org.xipki.security.pkix.CtLog;
import org.xipki.security.pkix.CtLog.SerializedSCT;
import org.xipki.security.pkix.CtLog.SignedCertificateTimestamp;
import org.xipki.security.pkix.CtLog.SignedCertificateTimestampList;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Hex;
import org.xipki.util.io.IoUtil;

import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

/**
 * Public keys can be found under https://ct.grahamedgecombe.com/
 * @author Lijun Liao (xipki)
 */
public class CtLogVerifyTest {

  private static final String pubkeyFile =
      "/ctlog-certs/letsencrypt/google-xenon2020-pubkey.pem";

  private static final String certFile =
      "/ctlog-certs/letsencrypt/letsencrypt-org.pem";

  private static final String caCertFile =
      "/ctlog-certs/letsencrypt/ca-of-letsencrypt-org.pem";

  @Test
  public void testVerify() throws Exception {
    Security.addProvider(KeyUtil.newBouncyCastleProvider());
    byte[] keyBytes = read(pubkeyFile);

    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
        X509Util.toDerEncoded(keyBytes));
    byte[] keyId = HashAlgo.SHA256.hash(spki.getEncoded());
    System.out.println("keyId: " + Hex.encode(keyId));

    PublicKey key = KeyUtil.getPublicKey(spki);
    X509Cert cert = X509Util.parseCert(read(certFile));
    X509Cert caCert = X509Util.parseCert(read(caCertFile));

    byte[] issuerKeyHash = HashAlgo.SHA256.hash(
        caCert.subjectPublicKeyInfo().getEncoded());
    byte[] preCertTbsCert = CtLog.getPreCertTbsCert(
        cert.toBcCert().toASN1Structure().getTBSCertificate());

    byte[] extnValue = cert.getExtensionCoreValue(
        OIDs.Extn.id_SignedCertificateTimestampList);

    byte[] encodedScts = ASN1OctetString.getInstance(extnValue).getOctets();
    SignedCertificateTimestampList list =
        SignedCertificateTimestampList.getInstance(encodedScts);
    SerializedSCT sctList = list.sctList();
    int size = sctList.size();
    Assert.assertEquals("SCT size", 2, size);

    SignedCertificateTimestamp sct = sctList.get(1);
    byte[] logId = sct.logId();
    Assert.assertEquals("logId", Hex.encodeUpper(keyId),
        Hex.encodeUpper(logId));

    Signature sig = Signature.getInstance("SHA256withECDSA");
    sig.initVerify(key);
    CtLog.update(sig, (byte) sct.version(), sct.timestamp(),
        sct.extensions(), issuerKeyHash, preCertTbsCert);

    boolean sigValid = sig.verify(sct.digitallySigned().signature());
    Assert.assertTrue("signature valid", sigValid);
  }

  public static byte[] read(String name) throws IOException {
    InputStream is = CtLogVerifyTest.class.getResourceAsStream(name);
    if (is == null) {
      throw new IOException("could not find " + name);
    }
    return IoUtil.readAllBytesAndClose(is);
  }

}
