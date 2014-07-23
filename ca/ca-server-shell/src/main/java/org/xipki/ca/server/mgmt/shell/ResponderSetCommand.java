/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.security.cert.X509Certificate;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.server.mgmt.CmpResponderEntry;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "responder-set", description="Set responder")
public class ResponderSetCommand extends CaCommand
{
    @Option(name = "-signerType",
            description = "Required. Type of the responder signer",
            required = true)
    protected String            signerType;

    @Option(name = "-signerConf",
            description = "Conf of the responder signer")
    protected String            signerConf;

    @Option(name = "-cert",
            description = "Requestor certificate, in form of 'file:<path> or base64:<content>")
    protected String            certFile;

    private SecurityFactory securityFactory;
    private PasswordResolver passwordResolver;

    @Override
    protected Object doExecute()
    throws Exception
    {
        CmpResponderEntry entry = new CmpResponderEntry();
        X509Certificate signerCert = null;
        if(certFile != null)
        {
            signerCert = IoCertUtil.parseCert(certFile);
            entry.setCertificate(signerCert);
        }
        entry.setType(signerType);

        if("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType))
        {
            signerConf = ShellUtil.canonicalizeSignerConf(signerType, signerConf, passwordResolver);
        }

        entry.setConf(signerConf);

        // check whether we can initialize the signer
        securityFactory.createSigner(signerType, signerConf, signerCert, passwordResolver);

        caManager.setCmpResponder(entry);

        return null;
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    public void setPasswordResolver(PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }
}
