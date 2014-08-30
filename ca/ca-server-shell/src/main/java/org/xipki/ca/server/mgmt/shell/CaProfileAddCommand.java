/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.util.List;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "caprofile-add", description="Add certificate profiles to CA")
public class CaProfileAddCommand extends CaCommand
{
    @Option(name = "-ca",
            description = " Required. CA name",
            required = true)
    protected String caName;

    @Option(name = "-profile",
        description = "Required. Profile profileNames, multi values allowed",
        required = true, multiValued = true)
    protected List<String> profileNames;

    @Override
    protected Object doExecute()
    throws Exception
    {
        for(String name : profileNames)
        {
            caManager.addCertProfileToCA(name, caName);
            out("associated certificate profile " + name + " to CA " + caName);
        }
        return null;
    }
}
