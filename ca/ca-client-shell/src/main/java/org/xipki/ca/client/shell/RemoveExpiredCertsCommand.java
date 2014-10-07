/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell;

import java.util.Set;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.client.api.RemoveExpiredCertsResult;

/**
 * @author Lijun Liao
 */

@Command(scope = "caclient", name = "remove-expired-certs", description="Remove expired certificates")
public class RemoveExpiredCertsCommand extends ClientCommand
{
    @Option(name = "-ca",
            required = false, description = "Required if multiple CAs are configured. CA name")
    protected String caName;

    @Option(name = "-profile",
            required = true, description = "Required. Certificate profile.")
    protected String profile;

    @Option(name = "-user",
            required = false, description = "Username, wildcards '%' and '*' are allowed.\n"
                    + "'all' for all users")
    protected String userLike;

    @Option(name = "-overlap",
            required = false, description = "Overlap in seconds")
    protected Long overlapSeconds = 24L * 60 * 60;

    @Override
    protected Object doExecute()
    throws Exception
    {
        Set<String> caNames = raWorker.getCaNames();
        if(caNames.isEmpty())
        {
            err("No CA is configured");
            return  null;
        }

        if(caName != null && ! caNames.contains(caName))
        {
            err("CA " + caName + " is not within the configured CAs " + caNames);
            return null;
        }

        if(caName == null)
        {
            if(caNames.size() == 1)
            {
                caName = caNames.iterator().next();
            }
            else
            {
                err("No caname is specified, one of " + caNames + " is required");
                return null;
            }
        }

        RemoveExpiredCertsResult result = raWorker.removeExpiredCerts(caName, profile, userLike, overlapSeconds);
        int n = result.getNumOfCerts();

        String prefix;
        if(n == 0)
        {
            prefix = "No certificate";
        }
        else if(n == 1)
        {
            prefix = "One certificate";
        }
        else
        {
            prefix = n + " certificates";
        }

        System.out.println(prefix + " will be deleted according to the given criteria");
        return null;
    }

}
