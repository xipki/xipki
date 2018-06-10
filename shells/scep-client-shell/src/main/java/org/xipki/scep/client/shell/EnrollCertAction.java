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

package org.xipki.scep.client.shell;

import java.io.File;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.apache.karaf.shell.support.completers.StringsCompleter;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.xipki.scep.client.EnrolmentResponse;
import org.xipki.scep.client.ScepClient;
import org.xipki.shell.CmdFailure;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
@Command(scope = "xi", name = "scep-enroll", description = "enroll certificate")
@Service
public class EnrollCertAction extends ClientAction {

  @Option(name = "--csr", required = true, description = "CSR file")
  @Completion(FileCompleter.class)
  private String csrFile;

  @Option(name = "--out", aliases = "-o", required = true,
      description = "where to save the certificate")
  @Completion(FileCompleter.class)
  private String outputFile;

  @Option(name = "--method", description = "method to enroll the certificate.")
  @Completion(value = StringsCompleter.class, values = {"pkcs", "renewal", "update"})
  private String method;

  @Override
  protected Object execute0() throws Exception {
    ScepClient client = getScepClient();

    CertificationRequest csr = CertificationRequest.getInstance(IoUtil.read(csrFile));
    EnrolmentResponse resp;

    PrivateKey key0 = getIdentityKey();
    X509Certificate cert0 = getIdentityCert();
    if (StringUtil.isBlank(method)) {
      resp = client.scepEnrol(csr, key0, cert0);
    } else if ("pkcs".equalsIgnoreCase(method)) {
      resp = client.scepPkcsReq(csr, key0, cert0);
    } else if ("renewal".equalsIgnoreCase(method)) {
      resp = client.scepRenewalReq(csr, key0, cert0);
    } else if ("update".equalsIgnoreCase(method)) {
      resp = client.scepUpdateReq(csr, key0, cert0);
    } else {
      throw new CmdFailure("invalid enroll method");
    }

    if (resp.isFailure()) {
      throw new CmdFailure("server returned 'failure'");
    }

    if (resp.isPending()) {
      throw new CmdFailure("server returned 'pending'");
    }

    X509Certificate cert = resp.getCertificates().get(0);
    saveVerbose("saved enrolled certificate to file", new File(outputFile), cert.getEncoded());
    return null;
  }

}
