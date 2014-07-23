/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
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

/**
 * @author Lijun Liao
 */

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
