/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "publisher-update", description="Update publisher")
public class PublisherUpdateCommand extends CaCommand
{

    @Option(name = "-name",
                description = "Required. Publisher Name",
                required = true, multiValued = false)
    protected String name;

    @Option(name = "-type",
            description = "Publisher type")
    protected String type;

    @Option(name = "-conf",
            description = "Publisher configuration or 'NULL'")
    protected String conf;

    @Option(name = "-confFile",
            description = "Profile configuration file")
    protected String confFile;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(type == null && conf == null && confFile == null)
        {
            err("Nothing to update");
            return null;
        }

        if(conf == null && confFile != null)
        {
            conf = new String(IoCertUtil.read(confFile));
        }

        caManager.changePublisher(name, type, conf);
        out("updated certificate profile " + name);
        return null;
    }
}
