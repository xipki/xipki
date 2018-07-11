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

package org.xipki.ca.server.mgmt.shell.cert;

import java.io.File;
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.server.mgmt.api.CertWithStatusInfo;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "cert-status",
    description = "show certificate status and save the certificate")
@Service
public class CertStatusAction extends UnRevRmCertAction {

  @Option(name = "--out", aliases = "-o", description = "where to save the DER encoded certificate")
  @Completion(FileCompleter.class)
  private String outputFile;

  @Override
  protected Object execute0() throws Exception {
    CertWithStatusInfo certInfo = caManager.getCert(caName, getSerialNumber());
    X509Certificate cert = (X509Certificate) certInfo.getCert();

    if (cert == null) {
      System.out.println("certificate unknown");
      return null;
    }

    String msg = StringUtil.concat("certificate profile: ", certInfo.getCertprofile(), "\nstatus: ",
        (certInfo.getRevocationInfo() == null
            ? "good" : "revoked with " + certInfo.getRevocationInfo()));
    println(msg);
    if (outputFile != null) {
      saveVerbose("certificate saved to file", new File(outputFile), cert.getEncoded());
    }
    return null;
  }

}
