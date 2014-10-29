/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell.cert;

import java.io.File;
import java.security.cert.X509Certificate;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.server.mgmt.api.CAEntry;
import org.xipki.ca.server.mgmt.shell.CaCommand;
import org.xipki.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "enroll-cert", description="Enroll certificate")
public class EnrollCertCommand extends CaCommand
{
    private static final Logger LOG = LoggerFactory.getLogger(EnrollCertCommand.class);

    @Option(name = "-ca",
            required = true, description = "Required. CA name")
    protected String caName;

    @Option(name = "-p10",
            required = true, description = "Required. PKCS#10 request file")
    protected String p10File;

    @Option(name = "-out",
            description = "Required. Where to save the certificate",
            required = true)
    protected String outFile;

    @Option(name = "-profile",
            required = true, description = "Required. Profile name")
    protected String profileName;

    @Option(name = "-user",
            required = false, description = "Username")
    protected String user;

    @Override
    protected Object doExecute()
    throws Exception
    {
        CAEntry ca = caManager.getCA(caName);
        if(ca == null)
        {
            err("CA " + caName + " not available");
            return null;
        }

        byte[] encodedP10Request = IoCertUtil.read(p10File);

        try
        {
            X509Certificate cert = caManager.generateCertificate(caName, profileName, user, encodedP10Request);
            saveVerbose("Saved certificate to file", new File(outFile), cert.getEncoded());
        } catch (Exception e)
        {
            LOG.warn("Exception: {}", e.getMessage());
            LOG.debug("Exception", e);
            err("ERROR: " + e.getMessage());
            return null;
        }

        return null;
    }

}
