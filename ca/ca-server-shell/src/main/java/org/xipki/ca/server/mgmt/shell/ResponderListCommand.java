/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.server.mgmt.api.CmpResponderEntry;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "responder-list", description="List responder")
public class ResponderListCommand extends CaCommand
{

    @Option(name = "-v", aliases="--verbose",
            required = false, description = "Show responder information verbosely")
    protected Boolean verbose;

    @Override
    protected Object doExecute()
    throws Exception
    {
        CmpResponderEntry responder = caManager.getCmpResponder();
        System.out.println(responder.toString(verbose == null ? false :verbose.booleanValue()));
        return null;
    }
}
