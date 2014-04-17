/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.client.shell;

import java.io.File;
import java.security.cert.X509Certificate;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.xipki.ca.client.api.RAWorker;
import org.xipki.ca.common.CertificateOrError;
import org.xipki.ca.common.EnrollCertResult;
import org.xipki.security.common.IoCertUtil;

@Command(scope = "caclient", name = "ra-enroll", description="Enroll certificate")
public class RAEnrollCertCommand extends ClientCommand {

    @Option(name = "-p10",
            required = true, description = "Required. PKCS-10 request file")
    protected String            p10File;

    @Option(name = "-profile",
            required = true, description = "Required. Certificate profile")
    protected String            profile;

    @Option(name = "-out",
            required = false, description = "Where to save the certificate")
    protected String            outputFile;

    private RAWorker             raWorker;

    @Override
    protected Object doExecute() throws Exception {
        CertificationRequest p10Req = CertificationRequest.getInstance(
                IoCertUtil.read(p10File));
        EnrollCertResult result = raWorker.requestCert(
                p10Req, profile, null);

        X509Certificate cert = null;
        if(result != null)
        {
            String id = result.getAllIds().iterator().next();
            CertificateOrError certOrError = result.getCertificateOrError(id);
            cert = (X509Certificate) certOrError.getCertificate();
        }

        if(cert == null)
        {
            System.err.println("No certificate received from the server");
        }
        else
        {
            if(outputFile == null)
            {
                outputFile = p10File.substring(0, p10File.length() - ".p10".length()) + ".der";
            }

            File certFile = new File(outputFile);

            IoCertUtil.save(certFile, cert.getEncoded());
            System.out.println("Certificate saved to " + certFile.getPath());
        }

        return null;
    }

    public void setRaWorker(RAWorker raWorker) {
        this.raWorker = raWorker;
    }

}
