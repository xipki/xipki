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
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.scep.client.EnrolmentResponse;
import org.xipki.scep.client.ScepClient;
import org.xipki.scep.client.exception.ScepClientException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class EnrollCertCommandSupport extends ClientCommandSupport {

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

    /**
     *
     * @param client
     *          SCEP client. Must not be {@code null}.
     * @param csr
     *          CSR. Must not be {@code null}.
     * @param identityKey
     *          Identity key. Must not be {@code null}.
     * @param identityCert
     *          Identity certificate. Must not be {@code null}.
     * @return
     * @throws ScepClientException
     */
    protected abstract EnrolmentResponse requestCertificate(ScepClient client,
            CertificationRequest csr, PrivateKey identityKey,
            X509Certificate identityCert) throws ScepClientException;

    @Override
    protected Object execute0() throws Exception {
        ScepClient client = getScepClient();

        CertificationRequest csr = CertificationRequest.getInstance(IoUtil.read(csrFile));
        EnrolmentResponse resp = requestCertificate(client, csr, getIdentityKey(),
                getIdentityCert());
        if (resp.isFailure()) {
            throw new CmdFailure("server returned 'failure'");
        }

        if (resp.isPending()) {
            throw new CmdFailure("server returned 'pending'");
        }

        X509Certificate cert = resp.certificates().get(0);
        saveVerbose("saved enrolled certificate to file", new File(outputFile), cert.getEncoded());
        return null;
    }

}
