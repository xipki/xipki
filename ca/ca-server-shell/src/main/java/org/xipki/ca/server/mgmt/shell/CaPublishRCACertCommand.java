/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Argument;
import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "publish-self", description="Publish the certificate of root CA")
public class CaPublishRCACertCommand extends CaCommand
{
    @Argument(index = 0, name = "name", description = "CA name", required = true)
    protected String caName;

    @Option(name = "-profile",
            description = "Required. Certificate profile name",
            required = true)
    protected String certprofile;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.publishRootCA(caName, certprofile);
        out("published CA certificate of root CA " + caName);
        return null;
    }
}
