/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.apache.felix.gogo.commands.Argument;
import org.apache.felix.gogo.commands.Command;
import org.xipki.ca.server.mgmt.CertProfileEntry;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "profile-list", description="List profiles")
public class ProfileListCommand extends CaCommand
{
    @Argument(index = 0, name = "name", description = "Certificate profile name", required = false)
    protected String name;

    @Override
    protected Object doExecute()
    throws Exception
    {
        StringBuilder sb = new StringBuilder();

        if(name == null)
        {
            Set<String> names = caManager.getCertProfileNames();
            int n = names.size();

            if(n == 0 || n == 1)
            {
                sb.append(((n == 0) ? "no" : "1") + " profile is configured\n");
            }
            else
            {
                sb.append(n + " profiles are configured:\n");
            }

            List<String> sorted = new ArrayList<>(names);
            Collections.sort(sorted);

            for(String name : sorted)
            {
                sb.append("\t").append(name).append("\n");
            }
        }
        else
        {
            CertProfileEntry entry = caManager.getCertProfile(name);
            if(entry != null)
            {
                sb.append(entry.toString());
            }
        }

        System.out.println(sb.toString());
        return null;
    }
}
