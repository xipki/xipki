/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.io.File;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.server.mgmt.api.CertProfileEntry;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "profile-export", description="Export profile configuration")
public class ProfileExportCommand extends CaCommand
{
    @Option(name = "-name",
            description = "Required. Profile name",
            required = true, multiValued = false)
    protected String name;

    @Option(name = "-out",
            description = "Required. Where to save the profile configuration",
            required = true)
    protected String confFile;

    @Override
    protected Object doExecute()
    throws Exception
    {
        CertProfileEntry entry = caManager.getCertProfile(name);
        if(entry == null)
        {
            err("No cert profile named " + name + " is defined");
            return null;
        }

        saveVerbose("Saved cert profile configuration to", new File(confFile), entry.getConf().getBytes("UTF-8"));
        return null;
    }
}
