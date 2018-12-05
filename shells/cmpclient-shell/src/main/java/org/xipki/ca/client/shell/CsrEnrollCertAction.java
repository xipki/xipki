/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.client.shell;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.xipki.cmpclient.EnrollCertResult;
import org.xipki.cmpclient.EnrollCertResult.CertifiedKeyPairOrError;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.util.DateUtil;
import org.xipki.util.ReqRespDebug;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "cmp-csr-enroll", description = "enroll certificate via CSR")
@Service
public class CsrEnrollCertAction extends ClientAction {

  @Option(name = "--csr", required = true, description = "CSR file")
  @Completion(FileCompleter.class)
  private String csrFile;

  @Option(name = "--profile", aliases = "-p", required = true, description = "certificate profile")
  private String profile;

  @Option(name = "--not-before", description = "notBefore, UTC time of format yyyyMMddHHmmss")
  private String notBeforeS;

  @Option(name = "--not-after", description = "notAfter, UTC time of format yyyyMMddHHmmss")
  private String notAfterS;

  @Option(name = "--outform", description = "output format of the certificate")
  @Completion(Completers.DerPemCompleter.class)
  private String outform = "der";

  @Option(name = "--out", aliases = "-o", required = true,
      description = "where to save the certificate")
  @Completion(FileCompleter.class)
  private String outputFile;

  @Option(name = "--ca",
      description = "CA name\n(required if the profile is supported by more than one CA)")
  @Completion(CaNameCompleter.class)
  private String caName;

  @Override
  protected Object execute0() throws Exception {
    if (caName != null) {
      caName = caName.toLowerCase();
    }

    CertificationRequest csr = X509Util.parseCsr(new File(csrFile));

    Date notBefore = StringUtil.isNotBlank(notBeforeS)
        ? DateUtil.parseUtcTimeyyyyMMddhhmmss(notBeforeS) : null;
    Date notAfter = StringUtil.isNotBlank(notAfterS)
          ? DateUtil.parseUtcTimeyyyyMMddhhmmss(notAfterS) : null;
    EnrollCertResult result;
    ReqRespDebug debug = getReqRespDebug();
    try {
      result = client.enrollCert(caName, csr, profile, notBefore, notAfter, debug);
    } finally {
      saveRequestResponse(debug);
    }

    X509Certificate cert = null;
    if (result != null) {
      String id = result.getAllIds().iterator().next();
      CertifiedKeyPairOrError certOrError = result.getCertOrError(id);
      cert = (X509Certificate) certOrError.getCertificate();
    }

    if (cert == null) {
      throw new CmdFailure("no certificate received from the server");
    }

    saveVerbose("certificate saved to file", outputFile, encodeCert(cert.getEncoded(), outform));
    return null;
  }

}
