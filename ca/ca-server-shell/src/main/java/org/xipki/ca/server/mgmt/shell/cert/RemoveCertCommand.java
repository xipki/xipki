/*
 * Copyright (c) 2014 xipki.org
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

package org.xipki.ca.server.mgmt.shell.cert;

import java.math.BigInteger;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.ca.server.X509CA;
import org.xipki.ca.server.mgmt.shell.CaCommand;

@Command(scope = "ca", name = "remove-cert", description="Remove certificate")
public class RemoveCertCommand extends CaCommand
{
    @Option(name = "-ca",
            required = true, description = "Required. CA name")
    protected String caName;

    @Option(name = "-serial",
            required = true,
            description = "Serial number")
    protected Long   serialNumber;

    @Override
    protected Object doExecute()
    throws Exception
    {
        X509CA ca = caManager.getX509CA(caName);
        if(ca == null)
        {
            System.err.println("CA " + caName + " not available");
            return null;
        }

        X509CertificateWithMetaInfo cert =
                ca.removeCertificate(BigInteger.valueOf(serialNumber));

        if(cert != null)
        {
            System.out.println("Removed certificate");
        }
        else
        {
            System.out.println("Could not remove certificate");
        }

        return null;
    }

}
