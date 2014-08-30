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
import org.xipki.ca.server.mgmt.api.CAManager;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "crlsigner-update", description="Update CRL signer")
public class CrlSignerUpdateCommand extends CaCommand
{
    @Option(name = "-name",
            description = "Required. CRL signer name",
            required = true, multiValued = false)
    protected String name;

    @Option(name = "-signerType",
            description = "CRL signer type, use 'CA' to sign the CRL by the CA itself")
    protected String signerType;

    @Option(name = "-signerConf",
            description = "CRL signer configuration")
    protected String signerConf;

    @Option(name = "-cert",
            description = "CRL signer's certificate file or 'NULL'")
    protected String signerCert;

    @Option(name = "-crlControl",
            description = "CRL control")
    protected String crlControl;

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

        caManager.changeCrlSigner(name, signerType, signerConf, signerCertConf, crlControl);
        out("updated CRL signer " + name);
        return null;
    }
}
