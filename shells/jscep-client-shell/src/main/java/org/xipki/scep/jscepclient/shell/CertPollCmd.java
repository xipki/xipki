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

package org.xipki.scep.jscepclient.shell;

import java.io.File;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.client.Client;
import org.jscep.client.EnrollmentResponse;
import org.jscep.transaction.TransactionId;
import org.jscep.util.CertificationRequestUtils;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.completer.FilePathCompleter;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "jscep-certpoll",
    description = "poll certificate")
@Service
public class CertPollCmd extends ClientAction {

  @Option(name = "--csr", required = true,
      description = "CSR file\n(required)")
  @Completion(FilePathCompleter.class)
  private String csrFile;

  @Option(name = "--out", aliases = "-o", required = true,
      description = "where to save the certificate\n(required)")
  @Completion(FilePathCompleter.class)
  private String outputFile;

  @Override
  protected Object execute0() throws Exception {
    PKCS10CertificationRequest csr = new PKCS10CertificationRequest(IoUtil.read(csrFile));

    Client client = getScepClient();

    TransactionId transId = TransactionId.createTransactionId(
        CertificationRequestUtils.getPublicKey(csr), "SHA-1");
    EnrollmentResponse resp = client.poll(getIdentityCert(), getIdentityKey(),
        new X500Principal(csr.getSubject().getEncoded()), transId);
    if (resp.isFailure()) {
      throw new CmdFailure("server returned 'failure'");
    }

    if (resp.isPending()) {
      throw new CmdFailure("server returned 'pending'");
    }

    X509Certificate cert = extractEeCerts(resp.getCertStore());

    if (cert == null) {
      throw new Exception("received no certificate");
    }

    saveVerbose("saved polled certificate to file", new File(outputFile), cert.getEncoded());
    return null;
  }

}
