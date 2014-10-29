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
import org.xipki.ca.server.mgmt.api.CrlSignerEntry;
import org.xipki.common.IoCertUtil;
import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "crlsigner-add", description="Add CRL signer")
public class CrlSignerAddCommand extends CaCommand
{
    @Option(name = "-name",
            description = "Required. CRL signer name",
            required = true, multiValued = false)
    protected String name;

    @Option(name = "-signerType",
            description = "Required. CRL signer type, use 'CA' to sign the CRL by the CA itself",
            required = true)
    protected String signerType;

    @Option(name = "-signerConf",
            description = "CRL signer configuration")
    protected String signerConf;

    @Option(name = "-cert",
            description = "CRL signer's certificate file")
    protected String signerCertFile;

    @Option(name = "-crlControl",
            required = true, description = "Required. CRL control")
    protected String crlControl;

    private SecurityFactory securityFactory;

    @Override
    protected Object doExecute()
    throws Exception
    {
        X509Certificate signerCert = null;
        if("CA".equalsIgnoreCase(signerType) == false)
        {
            if(signerCertFile != null)
            {
                signerCert = IoCertUtil.parseCert(signerCertFile);
            }

            if(signerConf != null)
            {
                if("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType))
                {
                    signerConf = ShellUtil.canonicalizeSignerConf(signerType,
                            signerConf, securityFactory.getPasswordResolver());
                }
            }
            // check whether we can initialize the signer
            securityFactory.createSigner(signerType, signerConf, signerCert);
        }

        CrlSignerEntry entry = new CrlSignerEntry(name, signerType, signerConf, crlControl);
        if(signerCert != null)
        {
            entry.setCertificate(signerCert);
        }
        caManager.addCrlSigner(entry);
        out("added CRL signer " + name);
        return null;
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

}
