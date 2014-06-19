/*
 * Copyright (c) 2014 Lijun Liao
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

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.client.api.RAWorker;
import org.xipki.ca.common.CertIDOrError;
import org.xipki.ca.common.PKIStatusInfo;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "caclient", name = "unrevoke", description="Unrevoke certificate")
public class RAUnrevokeCertCommand extends ClientCommand
{
    @Option(name = "-cert",
            description = "Certificate file")
    protected String            certFile;

    @Option(name = "-cacert",
            description = "CA Certificate file")
    protected String            caCertFile;

    @Option(name = "-serial",
            description = "Serial number")
    protected String            serialNumber;

    private RAWorker             raWorker;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(certFile == null && (caCertFile == null || serialNumber == null))
        {
            System.err.println("either cert or (cacert, serial) must be specified");
            return null;
        }

        CertIDOrError certIdOrError;
        if(certFile != null)
        {
            X509Certificate cert = IoCertUtil.parseCert(certFile);
            certIdOrError = raWorker.unrevokeCert(cert);
        }
        else
        {
            X509Certificate caCert = IoCertUtil.parseCert(caCertFile);
            X500Name issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
            certIdOrError = raWorker.unrevokeCert(issuer, new BigInteger(serialNumber));
        }

        if(certIdOrError.getError() != null)
        {
            PKIStatusInfo error = certIdOrError.getError();
            System.err.println("Releasing revocation failed: " + error);
        }
        else
        {
            System.out.println("Unrevoked certificate");
        }
        return null;
    }
}
