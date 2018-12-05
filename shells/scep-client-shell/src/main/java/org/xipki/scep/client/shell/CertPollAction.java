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
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.scep.client.EnrolmentResponse;
import org.xipki.scep.client.ScepClient;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "scep-certpoll", description = "poll certificate")
@Service
public class CertPollAction extends ClientAction {

  @Option(name = "--csr", required = true, description = "CSR file")
  @Completion(FileCompleter.class)
  private String csrFile;

  @Option(name = "--outform", description = "output format of the certificate")
  @Completion(Completers.DerPemCompleter.class)
  protected String outform = "der";

  @Option(name = "--out", aliases = "-o", required = true,
      description = "where to save the certificate")
  @Completion(FileCompleter.class)
  private String outputFile;

  @Override
  protected Object execute0() throws Exception {
    CertificationRequest csr = X509Util.parseCsr(new File(csrFile));

    ScepClient client = getScepClient();
    X509Certificate caCert = client.getAuthorityCertStore().getCaCert();
    X500Name caSubject = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());

    EnrolmentResponse resp = client.scepCertPoll(getIdentityKey(), getIdentityCert(), csr,
        caSubject);
    if (resp.isFailure()) {
      throw new CmdFailure("server returned 'failure'");
    } else if (resp.isPending()) {
      throw new CmdFailure("server returned 'pending'");
    }

    List<X509Certificate> certs = resp.getCertificates();
    if (certs == null || certs.isEmpty()) {
      throw new CmdFailure("received no certficate from server");
    }

    saveVerbose("saved certificate to file", outputFile,
        encodeCert(certs.get(0).getEncoded(), outform));
    return null;
  }

}
