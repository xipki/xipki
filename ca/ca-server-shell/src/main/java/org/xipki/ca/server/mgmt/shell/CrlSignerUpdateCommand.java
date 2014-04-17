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

package org.xipki.ca.server.mgmt.shell;

import java.io.ByteArrayInputStream;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.util.encoders.Base64;
import org.xipki.ca.server.mgmt.CAManager;
import org.xipki.security.common.IoCertUtil;

@Command(scope = "ca", name = "crlsigner-update", description="Update CRL signer")
public class CrlSignerUpdateCommand extends CaCommand
{
    @Option( name = "-name",
             description = "Required. CRL signer name",
             required = true, multiValued = false)
    protected String            name;

    @Option(name = "-signerType",
            description = "CRL signer type, use 'CA' to sign the CRL by the CA itself")
    protected String            signerType;

    @Option(name = "-signerConf",
            description = "CRL signer configuration")
    protected String            signerConf;

    @Option(name = "-cert",
            description = "CRL signer's certificate file or 'NULL'")
    protected String            signerCert;

    @Option(name = "-period",
            description = "Interval in minutes of two CRLs, set to 0 to generate CRL on demand")
    protected Integer            period;

    @Option(name = "-overlap",
            description = "Overlap of CRL")
    protected Integer            overlap;

    @Option(name = "-ewc", aliases = { "--enableWithCerts" },
            description = "Certificates are contained in the CRL, the default is not")
    protected Boolean            enableWithCerts;

    @Option(name = "-dwc", aliases = { "--disableWithCerts" },
            description = "Certificates are not contained in the CRL, the default is not")
    protected Boolean            disableWithCerts;

    @Override
    protected Object doExecute() throws Exception
    {
        String signerCertConf = null;
        if(CAManager.NULL.equalsIgnoreCase(signerCert))
        {
            signerCertConf = CAManager.NULL;
        }
        else if(signerCert != null)
        {
            byte[] certBytes = IoCertUtil.read(signerCert);
            IoCertUtil.parseCert(new ByteArrayInputStream(certBytes));
            signerCertConf = Base64.toBase64String(certBytes);
        }

        if(enableWithCerts != null && disableWithCerts != null )
        {
            System.err.println("Containing certificates in CRL could not be enabled and disabled at the same time");
        }

        Boolean includeCerts = null;
        if(enableWithCerts != null || disableWithCerts != null)
        {
            includeCerts = isEnabled(enableWithCerts, disableWithCerts, false);
        }

        caManager.changeCrlSigner(name, signerType, signerConf, signerCertConf, period, overlap, includeCerts);
        return null;
    }
}
