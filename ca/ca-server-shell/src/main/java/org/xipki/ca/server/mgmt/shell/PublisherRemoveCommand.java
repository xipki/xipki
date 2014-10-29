/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Argument;
import org.apache.felix.gogo.commands.Command;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "publisher-rm", description="Remove publisher")
public class PublisherRemoveCommand extends CaCommand
{
    @Argument(index = 0, name = "name", description = "Publisher name", required = true)
    protected String name;

    @Override
    protected Object doExecute()
    throws Exception
    {
        caManager.removePublisher(name);
        out("removed certificate profile " + name);
        return null;
    }
}
