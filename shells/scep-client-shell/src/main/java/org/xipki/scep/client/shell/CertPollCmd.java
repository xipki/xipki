/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.scep.client.EnrolmentResponse;
import org.xipki.scep.client.ScepClient;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-scep", name = "certpoll",
        description = "poll certificate")
@Service
public class CertPollCmd extends ClientCommandSupport {

    @Option(name = "--csr",
            required = true,
            description = "CSR file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String csrFile;

    @Option(name = "--out", aliases = "-o",
            required = true,
            description = "where to save the certificate\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String outputFile;

    @Override
    protected Object execute0() throws Exception {
        CertificationRequest csr = CertificationRequest.getInstance(IoUtil.read(csrFile));

        ScepClient client = getScepClient();
        X509Certificate caCert = client.authorityCertStore().caCert();
        X500Name caSubject = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());

        EnrolmentResponse resp = client.scepCertPoll(getIdentityKey(), getIdentityCert(), csr,
                caSubject);
        if (resp.isFailure()) {
            throw new CmdFailure("server returned 'failure'");
        }

        if (resp.isPending()) {
            throw new CmdFailure("server returned 'pending'");
        }

        List<X509Certificate> certs = resp.certificates();
        if (certs == null || certs.isEmpty()) {
            throw new CmdFailure("received no certficate from server");
        }

        saveVerbose("saved certificate to file", new File(outputFile), certs.get(0).getEncoded());
        return null;
    }

}
