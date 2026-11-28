// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.Extensions;
import org.xipki.ca.api.mgmt.RequestorInfo;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.certprofile.xijson.conf.XijsonCertprofileType;
import org.xipki.ca.server.Ca;
import org.xipki.ca.server.CertTemplateData;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.ca.server.test.CaH2TestEnv;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.ca.CaUris;
import org.xipki.pkix.ca.X509CertificateInfo;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.qa.ValidationIssue;
import org.xipki.qa.ValidationResult;
import org.xipki.qa.ca.CertprofileQa;
import org.xipki.qa.ca.IssuerInfo;
import org.xipki.util.misc.NameId;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Issues a certificate for the QA certificate profiles on the H2 CA of {@link CaH2TestEnv}
 * and checks it with the QA checker {@link CertprofileQa}. The request inputs (subject,
 * requested extensions) are the ones of the QA scripts.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Parameterized.class)
public class CertprofileQaH2Test {

  private static final String QA_DIR = "../assemblies/xipki-qa/src/assembly/unfiltered/xipki-qa-cli/qa";

  /** profile, requested subject, file with the requested extensions (in qa/extensions). */
  private static final String[][] CASES = {
      {"tls",                   "CN=tls1.myorg.org,O=myorg,C=DE",                 null},
      {"tls-c",                 "CN=tls-c1,O=myorg,C=DE",                         null},
      {"smime",                 "CN=smime1,E=InFo@myorg.com,O=myorg,C=DE",         null},
      {"smime-legacy",          "CN=smime-legacy1,E=InFo@myorg.com,O=myorg,C=DE",  null},
      {"ocsp",                  "CN=ocsp1,2.5.4.97=VATDE-123456789,O=myorg,C=DE",  null},
      {"multiple-ous",          "CN=multiple-ous1,OU=A12345,OU=54321,O=myorg,C=DE", null},
      {"qc",                    "CN=qc1,2.5.4.97=VATDE-123456789,O=myorg,C=DE",    null},
      {"fixed-partial-subject", "CN=fixed-partial-subject1",                       null},
      {"constant-ext",          "CN=constant-ext1,O=myorg,C=DE",                   null},
      {"max-time",              "CN=max-time1.myorg.org,O=myorg,C=DE",             null},
      {"subca",                 "CN=subca1,O=myorg,C=DE",                          null},
      {"microsoft",             "CN=microsoft.myorg.org,O=myorg,C=DE",             "microsoft.der"},
      {"gmt0015",               "CN=gmt0015.myorg.org,O=myorg,C=DE",               "gmt0015.der"},
      {"rpki",                  "CN=rpki.myorg.org,O=myorg,C=DE",                  "rpki.der"},
      {"spdm",                  "CN=spdm.myorg.org,O=myorg,C=DE",                  "spdm.der"},
      {"stir",                  "CN=spdm.myorg.org,O=myorg,C=DE",                  "stir.der"},
      {"rfc3739",               "CN=rfc3739.myorg.org,O=myorg,C=DE",               "rfc3739.der"},
      {"tcg",                   "CN=tcg.myorg.org,O=myorg,C=DE",                   "tcg.der"},
      {"othernames",            "CN=othernames.myorg.org,O=myorg,C=DE",            "othernames.der"},
      {"caliptra",              "CN=caliptra.myorg.org",                           "caliptra.der"},
      {"ccc-e",                 "CN=ccc-e.myorg.org,O=myorg,C=DE",                 "ccc-e.der"},
      {"ccc-h",                 "CN=ccc-h.myorg.org,O=myorg,C=DE",                 "ccc-h.der"},
      {"ccc-k",                 "CN=ccc-k.myorg.org,O=myorg,C=DE",                 null},
      {"ccc-t",                 "CN=ccc-t.myorg.org,O=myorg,C=DE",                 "ccc-t.der"},
      {"brski",                 "CN=brski.myorg.org,O=myorg,C=DE",                 null},
      {"matter", "1.3.6.1.4.1.37244.1.1=1234567890ABCDEF,CN=matter.myorg.org,O=myorg,C=DE", null},
      {"mrtd",                  "CN=mrtd.myorg.org,O=myorg,C=DE",                  null},
      {"dice",                  "CN=dice.myorg.org,O=myorg,C=DE",                  null},
      {"rfc9608",               "CN=rfc9608.myorg.org,O=myorg,C=DE",               null}};

  private static CaH2TestEnv env;

  private static Ca ca;

  private static RequestorInfo requestor;

  private static IssuerInfo issuerInfo;

  private final String profileName;

  private final String subject;

  private final String extensionsFile;

  public CertprofileQaH2Test(String profileName, String subject, String extensionsFile) {
    this.profileName = profileName;
    this.subject = subject;
    this.extensionsFile = extensionsFile;
  }

  @Parameterized.Parameters(name = "{0}")
  public static List<Object[]> cases() {
    List<Object[]> ret = new ArrayList<>(CASES.length);
    for (String[] c : CASES) {
      ret.add(new Object[]{c[0], c[1], c[2]});
    }
    return ret;
  }

  private static synchronized void init() throws Exception {
    if (env != null) {
      return;
    }

    env = new CaH2TestEnv();
    CaManagerImpl caManager = env.caManager();
    for (String[] c : CASES) {
      caManager.addCertprofile(new CertprofileEntry(new NameId(null, c[0]), "xijson",
          Files.readString(profileFile(c[0]))));
      caManager.addCertprofileToCa(c[0], CaH2TestEnv.CA_NAME);
    }

    ca = caManager.getCaInstance(CaH2TestEnv.CA_NAME);
    requestor = new RequestorInfo.ByCaRequestorInfo(
        caManager.idNameMap().getRequestor(RequestorInfo.NAME_BY_CA));

    CaUris uris = caManager.getCa(CaH2TestEnv.CA_NAME).base().caUris();
    issuerInfo = new IssuerInfo(uris.cacertUris(), uris.ocspUris(), uris.crlUris(),
        uris.deltaCrlUris(), env.caCert().getEncoded(), true);
  }

  @AfterClass
  public static void shutdown() {
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void issuedCertificatePassesTheQaCheck() throws Exception {
    init();

    byte[] profileBytes = Files.readAllBytes(profileFile(profileName));
    SubjectPublicKeyInfo publicKey = KeyUtil.generateX509KeyPair2(
        keySpec(XijsonCertprofileType.parse(profileBytes).keyAlgorithms())).subjectPublicKeyInfo();
    X500Name requestedSubject = new X500Name(subject);
    Extensions requestedExtensions = (extensionsFile == null) ? null
        : Extensions.fromEncoded(Files.readAllBytes(Paths.get(QA_DIR, "extensions",
            extensionsFile)));

    X509CertificateInfo certInfo = ca.generateCert(requestor, new CertTemplateData(requestedSubject,
        publicKey, null, null, requestedExtensions, profileName), null);

    ValidationResult result = new CertprofileQa(profileBytes).checkCert(
        certInfo.cert().getEncodedCert(), issuerInfo, requestedSubject, publicKey,
        requestedExtensions);

    StringBuilder failures = new StringBuilder();
    for (ValidationIssue issue : result.getFailedValidationIssues()) {
      failures.append("\n  ").append(issue.getCode()).append(": ")
          .append(issue.getFailureMessage());
    }
    Assert.assertTrue("QA check of " + profileName + " failed:" + failures,
        result.isAllSuccessful());
  }

  private static Path profileFile(String name) {
    return Paths.get(QA_DIR, "certprofile", "certprofile-" + name + ".json");
  }

  /** P256 if allowed, else RSA2048, else the first allowed key type. */
  private static KeySpec keySpec(List<KeySpec> allowed) {
    if (allowed == null || allowed.isEmpty() || allowed.contains(KeySpec.P256)) {
      return KeySpec.P256;
    }
    return allowed.contains(KeySpec.RSA2048) ? KeySpec.RSA2048 : allowed.get(0);
  }

}
