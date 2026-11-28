// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.x500.X500Name;
import org.xipki.ca.api.mgmt.RequestorInfo;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.server.CertTemplateData;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.test.CaH2TestEnv;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.ca.CaUris;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.qa.ValidationResult;
import org.xipki.qa.ca.CertprofileQa;
import org.xipki.qa.ca.IssuerInfo;
import org.xipki.util.misc.NameId;

import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * The QA checker detects a certificate which does not match the profile, so that
 * {@link CertprofileQaH2Test} does not pass with a checker that accepts everything.
 *
 * @author Lijun Liao (xipki)
 */
public class CertprofileQaNegativeH2Test {

  private static final String PROFILE_DIR =
      "../assemblies/xipki-qa/src/assembly/unfiltered/xipki-qa-cli/qa/certprofile/";

  private static CaH2TestEnv env;

  private static IssuerInfo issuerInfo;

  private static byte[] tlsCert;

  private static X500Name subject;

  private static SubjectPublicKeyInfo publicKey;

  @BeforeClass
  public static void init() throws Exception {
    env = new CaH2TestEnv();
    CaManagerImpl caManager = env.caManager();
    caManager.addCertprofile(new CertprofileEntry(new NameId(null, "tls"), "xijson",
        Files.readString(Paths.get(PROFILE_DIR + "certprofile-tls.json"))));
    caManager.addCertprofileToCa("tls", CaH2TestEnv.CA_NAME);

    CaUris uris = caManager.getCa(CaH2TestEnv.CA_NAME).base().caUris();
    issuerInfo = new IssuerInfo(uris.cacertUris(), uris.ocspUris(), uris.crlUris(),
        uris.deltaCrlUris(), env.caCert().getEncoded(), true);

    subject = new X500Name("CN=tls1.myorg.org,O=myorg,C=DE");
    publicKey = KeyUtil.generateX509KeyPair2(KeySpec.P256).subjectPublicKeyInfo();
    RequestorInfo requestor = new RequestorInfo.ByCaRequestorInfo(
        caManager.idNameMap().getRequestor(RequestorInfo.NAME_BY_CA));
    tlsCert = caManager.getCaInstance(CaH2TestEnv.CA_NAME).generateCert(requestor,
        new CertTemplateData(subject, publicKey, null, null, null, "tls"), null)
        .cert().getEncodedCert();
  }

  @AfterClass
  public static void shutdown() {
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void matchingProfilePasses() throws Exception {
    Assert.assertTrue(check("tls", subject, publicKey).isAllSuccessful());
  }

  @Test
  public void otherProfileFails() throws Exception {
    Assert.assertFalse(check("smime", subject, publicKey).isAllSuccessful());
  }

  @Test
  public void otherRequestedSubjectFails() throws Exception {
    Assert.assertFalse(check("tls", new X500Name("CN=other.myorg.org,O=myorg,C=DE"), publicKey)
        .isAllSuccessful());
  }

  @Test
  public void otherRequestedPublicKeyFails() throws Exception {
    SubjectPublicKeyInfo otherKey =
        KeyUtil.generateX509KeyPair2(KeySpec.P256).subjectPublicKeyInfo();
    Assert.assertFalse(check("tls", subject, otherKey).isAllSuccessful());
  }

  private static ValidationResult check(String profile, X500Name requestedSubject,
                                        SubjectPublicKeyInfo requestedKey) throws Exception {
    return new CertprofileQa(Files.readAllBytes(Paths.get(
        PROFILE_DIR + "certprofile-" + profile + ".json")))
        .checkCert(tlsCert, issuerInfo, requestedSubject, requestedKey, null);
  }

}
