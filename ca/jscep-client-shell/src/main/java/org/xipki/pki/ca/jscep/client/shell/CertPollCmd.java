/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.jscep.client.shell;

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
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.console.karaf.CmdFailure;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.0
 */

@Command(scope = "jscep", name = "certpoll",
    description = "poll certificate")
@Service
public class CertPollCmd extends ClientCommandSupport {

  @Option(name = "--p10",
      required = true,
      description = "PKCS#10 request file\n"
          + "(required)")
  @Completion(FilePathCompleter.class)
  private String p10File;

  @Option(name = "--out", aliases = "-o",
      required = true,
      description = "where to save the certificate\n"
          + "(required)")
  @Completion(FilePathCompleter.class)
  private String outputFile;

  @Override
  protected Object doExecute()
  throws Exception {
    PKCS10CertificationRequest csr = new PKCS10CertificationRequest(IoUtil.read(p10File));

    Client client = getScepClient();

    TransactionId transId = TransactionId.createTransactionId(
        CertificationRequestUtils.getPublicKey(csr), "SHA-1");
    EnrollmentResponse resp = client.poll(getIdentityCert(),
        getIdentityKey(),
        new X500Principal(csr.getSubject().getEncoded()),
        transId);
    if (resp.isFailure()) {
      throw new CmdFailure("server returned 'failure'");
    }

    if (resp.isPending()) {
      throw new CmdFailure("server returned 'pending'");
    }

    X509Certificate cert = extractEECerts(resp.getCertStore());

    if (cert == null) {
      throw new Exception("received no certificate");
    }

    saveVerbose("saved polled certificate to file", new File(outputFile), cert.getEncoded());
    return null;
  }

}
