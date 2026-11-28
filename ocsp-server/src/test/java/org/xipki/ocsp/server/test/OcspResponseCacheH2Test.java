// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.ocsp.OCSPRequest;
import org.xipki.asn1.ocsp.Request;
import org.xipki.asn1.ocsp.TBSRequest;
import org.xipki.asn1.x509.Extension;
import org.xipki.asn1.x509.Extensions;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.test.CaH2TestEnv;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.ocsp.server.OcspServer;
import org.xipki.ocsp.server.Responder;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.conf.ConfigurableProperties;
import org.xipki.util.misc.NameId;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * The response cache of the OCSP server ({@code ResponseCacher}) with the store type
 * {@code xipki-db}, filled by the OCSP publisher of the CA.
 *
 * @author Lijun Liao (xipki)
 */
public class OcspResponseCacheH2Test {

  private static final String CA = CaH2TestEnv.CA_NAME;

  private static CaH2TestEnv env;

  private static CaManagerImpl caManager;

  private static OcspServer server;

  private static Responder responder;

  private static X509Cert caCert;

  private static Path cacheDbConf;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv(true);
    caManager = env.caManager();
    caCert = env.caCert();
    caManager.addPublisher(new PublisherEntry(new NameId(null, "ocsp-publisher"), "ocsp",
        "datasource=ocsp,publish.goodcerts=true"));
    caManager.addPublisherToCa("ocsp-publisher", CA);

    cacheDbConf = env.newDatabase("ocsp-cache", "ocsp-cache-init.h2.sql");
    String cacheConf = cacheDbConf.toAbsolutePath().toString().replace("\\", "/");
    server = new OcspServer(env.workDir().toString());
    server.setSecurityFactory(env.securities().securityFactory());
    server.setConfFile(OcspTestUtil.writeResponderConf(env.workDir(), env.ocspDbConf(),
        "{\"datasource\": \"ocspdb\", \"type\": \"xipki-db\", \"conf\": {}}", "unknown",
        ",\n  \"responseCache\": {\"validity\": \"1d\", \"datasource\": {\"name\": \"cache\","
            + " \"conf\": {\"file\": \"" + cacheConf + "\"}}}").toString());
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
  public void responseIsCachedAndReused() throws Exception {
    BigInteger serial = issue("cache1.example.org");
    int before = cacheEntries();
    byte[] request = OcspTestUtil.request(OcspTestUtil.certId(caCert, serial));

    byte[] first = answer(request);
    Assert.assertEquals("one more cache entry", before + 1, cacheEntries());

    // the same response, from the cache (also the same producedAt and signature)
    Assert.assertArrayEquals(first, answer(request));
    Assert.assertEquals(before + 1, cacheEntries());
  }

  @Test
  public void responseWithNonceIsNotCached() throws Exception {
    BigInteger serial = issue("cache-nonce.example.org");
    int before = cacheEntries();
    Extension nonce = Extension.ofOcspNonce(false, new byte[]{1, 2, 3, 4, 5, 6, 7, 8});
    TBSRequest tbs = new TBSRequest(null, new Request.Seq0(List.of(
        new Request(OcspTestUtil.certId(caCert, serial), null))), new Extensions(nonce));
    answer(new OCSPRequest(tbs, null).getEncoded());
    Assert.assertEquals("no cache entry for a request with nonce", before, cacheEntries());
  }

  private static byte[] answer(byte[] request) throws Exception {
    return server.answer(responder, request, false).response();
  }

  private static BigInteger issue(String commonName) throws Exception {
    return X509Util.parseCert(caManager.generateKeyCert(CA, CaH2TestEnv.PROFILE_TLS,
        "CN=" + commonName + ",O=myorg,C=DE", null, null).cert()).serialNumber();
  }

  private static int cacheEntries() throws Exception {
    ConfigurableProperties props = new ConfigurableProperties();
    try (InputStream in = Files.newInputStream(cacheDbConf)) {
      props.load(in);
    }
    try (DataSourceWrapper datasource = new DataSourceFactory().createDataSource("cache-test",
        props)) {
      return datasource.getCount(null, "OCSP");
    }
  }

}
