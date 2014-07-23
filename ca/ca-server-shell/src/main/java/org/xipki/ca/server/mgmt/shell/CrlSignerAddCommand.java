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
import org.xipki.ca.server.mgmt.CrlSignerEntry;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "crlsigner-add", description="Add CRL signer")
public class CrlSignerAddCommand extends CaCommand
{
    @Option( name = "-name",
             description = "Required. CRL signer name",
             required = true, multiValued = false)
    protected String            name;

    @Option(name = "-signerType",
            description = "Required. CRL signer type, use 'CA' to sign the CRL by the CA itself",
            required = true)
    protected String            signerType;

    @Option(name = "-signerConf",
            description = "CRL signer configuration")
    protected String            signerConf;

    @Option(name = "-cert",
            description = "CRL signer's certificate file")
    protected String            signerCertFile;

    @Option(name = "-period",
            required=true, description = "Required. Interval in minutes of two CRLs,\n"
                    + "set to 0 to generate CRL on demand")
    protected Integer            period;

    @Option(name = "-overlap",
            description = "Overlap of CRL")
    protected Integer            overlap;

    @Option(name = "-wc", aliases = { "--withCert" },
            description = "Whether certificates are contained in CRL.\n"
                + "Valid values are 'yes' and 'no',\n"
                + "the default is 'no'")
    protected String            withCertS;

    @Option(name = "-wec", aliases = { "--withExpiredCert" },
            description = "Whether expired certificates are contained in CRL.\n"
                    + "Valid values are 'yes' and 'no',\n"
                    + "the default is 'no'")
    protected String            withExpiredCertS;

    private SecurityFactory securityFactory;
    private PasswordResolver passwordResolver;

    @Override
    protected Object doExecute()
    throws Exception
    {
        CrlSignerEntry entry = new CrlSignerEntry(name);

        entry.setType(signerType);
        if("CA".equalsIgnoreCase(signerType) == false)
        {
            X509Certificate signerCert = null;
            if(signerCertFile != null)
            {
                signerCert = IoCertUtil.parseCert(signerCertFile);
                entry.setCertificate(signerCert);
            }

            if(signerConf != null)
            {
                if("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType))
                {
                    signerConf = ShellUtil.canonicalizeSignerConf(signerType,
                            signerConf, passwordResolver);
                }
                entry.setConf(signerConf);
            }

            // check whether we can initialize the signer
            securityFactory.createSigner(signerType, signerConf, signerCert, passwordResolver);
        }

        entry.setPeriod(period);

        if(overlap != null)
        {
            entry.setOverlap(overlap);
        }

        boolean withCert = isEnabled(withCertS, false, "withCert");
        entry.setIncludeCertsInCrl(withCert);

        boolean withExpiredCert = isEnabled(withExpiredCertS, false, "withExpiredCerts");
        entry.setIncludeExpiredCerts(withExpiredCert);

        caManager.addCrlSigner(entry);

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
