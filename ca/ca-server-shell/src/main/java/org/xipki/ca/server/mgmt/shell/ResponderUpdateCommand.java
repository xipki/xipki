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

package org.xipki.ca.server.mgmt.shell;

import java.io.ByteArrayInputStream;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.util.encoders.Base64;
import org.xipki.ca.server.mgmt.CAManager;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.IoCertUtil;

@Command(scope = "ca", name = "responder-update", description="Update responder")
public class ResponderUpdateCommand extends CaCommand
{
    @Option(name = "-signerType",
            description = "Type of the responder signer",
            required = true)
    protected String            signerType;

    @Option(name = "-signerConf",
            description = "Conf of the responder signer or 'NULL'")
    protected String            signerConf;

    @Option(name = "-cert",
            description = "Requestor certificate file or 'NULL'")
    protected String            certFile;

    private PasswordResolver passwordResolver;

    @Override
    protected Object doExecute()
    throws Exception
    {
        String cert = null;
        if(CAManager.NULL.equalsIgnoreCase(certFile))
        {
            cert = CAManager.NULL;
        }
        else if(certFile != null)
        {
            byte[] certBytes = IoCertUtil.read(certFile);
            IoCertUtil.parseCert(new ByteArrayInputStream(certBytes));
            cert = Base64.toBase64String(certBytes);
        }

        if("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType))
        {
            signerConf = ShellUtil.canonicalizeSignerConf(signerType, signerConf, passwordResolver);
        }

        caManager.changeCmpResponder(signerType, signerConf, cert);

        return null;
    }

    public void setPasswordResolver(PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }

}
