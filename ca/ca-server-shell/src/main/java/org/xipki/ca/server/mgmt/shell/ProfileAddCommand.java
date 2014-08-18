/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.server.mgmt.api.CertProfileEntry;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "profile-add", description="Add certificate profile")
public class ProfileAddCommand extends CaCommand
{

    @Option(name = "-name",
                description = "Required. Profile name",
                required = true, multiValued = false)
    protected String name;

    @Option(name = "-type",
            description = "Required. Profile type",
            required = true)
    protected String type;

    @Option(name = "-conf",
            description = "Profile configuration")
    protected String conf;

    @Option(name = "-confFile",
            description = "Profile configuration file")
    protected String confFile;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(conf == null && confFile != null)
        {
            conf = new String(IoCertUtil.read(confFile));
        }

        CertProfileEntry entry = new CertProfileEntry(name, type, conf);
        caManager.addCertProfile(entry);

        return null;
    }
}
