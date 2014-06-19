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

package org.xipki.ca.server.mgmt.shell;

import java.io.ByteArrayInputStream;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.util.encoders.Base64;
import org.xipki.ca.server.mgmt.CAManager;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

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

    @Option(name = "-wc", aliases = { "--withCert" },
            description = "Whether certificates are contained in CRL.\n"
                + "Valid values are 'yes' and 'no',\n"
                + "the default is 'no'")
    protected String            withCertS;

    @Option(name = "-wec", aliases = { "--withExpiredCerts" },
            description = "Whether expired certificates are contained in CRL.\n"
                    + "Valid values are 'yes' and 'no',\n"
                    + "the default is 'no'")
    protected String            withExpiredCertS;

    @Override
    protected Object doExecute()
    throws Exception
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

        Boolean withCert = isEnabled(withCertS, "withCert");
        Boolean withExpiredCert = isEnabled(withExpiredCertS, "withExpiredCerts");

        caManager.changeCrlSigner(name, signerType, signerConf, signerCertConf, period, overlap,
                withCert, withExpiredCert);
        return null;
    }
}
