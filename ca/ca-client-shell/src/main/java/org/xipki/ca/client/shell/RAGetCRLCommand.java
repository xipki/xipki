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
import java.security.cert.X509CRL;
import java.util.Set;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.client.api.RAWorker;
import org.xipki.security.common.IoCertUtil;

@Command(scope = "caclient", name = "ra-getcrl", description="Download CRL")
public class RAGetCRLCommand extends ClientCommand
{

    @Option(name = "-ca",
            required = false, description = "Required if multiple CAs are configured. CA name")
    protected String            caName;

    @Option(name = "-out",
            description = "Required. Where to save the CRL",
            required = true)
    protected String            outFile;

    private RAWorker             raWorker;

    @Override
    protected Object doExecute()
    throws Exception
    {
        Set<String> caNames = raWorker.getCaNames();
        if(caNames.isEmpty())
        {
            System.out.println("No CA is configured");
            return  null;
        }

        if(caName != null && ! caNames.contains(caName))
        {
            System.err.println("CA " + caName + " is not within the configured CAs " + caNames);
            return null;
        }

        if(caName == null)
        {
            if(caNames.size() == 1)
            {
                caName = caNames.iterator().next();
            }
            else
            {
                System.err.println("caName, one of " + caNames + ", is required");
            }
        }

        X509CRL crl = raWorker.downloadCRL(caName);
        if(crl == null)
        {
            System.err.println("Received no CRL from server");
            return null;
        }

        IoCertUtil.save(new File(outFile), crl.getEncoded());
        return null;
    }

    public void setRaWorker(RAWorker raWorker)
    {
        this.raWorker = raWorker;
    }

}
