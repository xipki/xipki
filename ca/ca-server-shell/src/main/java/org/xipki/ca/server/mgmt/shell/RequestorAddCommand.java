/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "requestor-add", description="Add requestor")
public class RequestorAddCommand extends CaCommand
{
    @Option(name = "-name",
            description = "Required. Requestor name",
            required = true, multiValued = false)
    protected String name;

    @Option(name = "-cert",
            description = "Required. Requestor certificate file",
            required = true)
    protected String certFile;

    @Override
    protected Object doExecute()
    throws Exception
    {
        CmpRequestorEntry entry = new CmpRequestorEntry(name);
        entry.setCert(IoCertUtil.parseCert(certFile));
        caManager.addCmpRequestor(entry);
        out("added CMP requestor " + name);
        return null;
    }
}
