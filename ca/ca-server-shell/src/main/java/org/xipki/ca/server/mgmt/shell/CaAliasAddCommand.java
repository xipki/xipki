/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "caalias-add", description="Add CA alias")
public class CaAliasAddCommand extends CaCommand
{
    @Option(name = "-ca",
            description = "Required. CA name",
            required = true)
    protected String caName;

    @Option(name = "-alias",
            description = "Required. CA alias",
            required = true)
    protected String caAlias;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.addCaAlias(caAlias, caName);
        out("added CA alias " + caAlias + " associated with CA " + caName);
        return null;
    }
}
