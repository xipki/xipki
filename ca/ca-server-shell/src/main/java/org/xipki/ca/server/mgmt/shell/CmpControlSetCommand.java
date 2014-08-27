/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.common.CmpControl;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "cmpcontrol-set", description="Set CMP control")
public class CmpControlSetCommand extends CaCommand
{
    @Option(name = "-cc", aliases = { "--confirmCert" },
            description = "Whether confirm of certificate is required.\n"
                + "Valid values are 'yes' and 'no'")
    protected String confirmCertS = "no";

    @Option(name = "-scc", aliases = { "--sendCaCert" },
            description = "Whether CA certificate is included in response.\n"
                + "Valid values are 'yes' and 'no'")
    protected String sendCaCertS = "no";

    @Option(name = "-src", aliases = { "--sendResponderCert" },
            description = "Whether responder certificate is included in response.\n"
                + "Valid values are 'yes' and 'no'")
    protected String sendResponderCertS = "yes";

    @Option(name = "-mt", aliases = { "--messageTime" },
            description = "Whether message time is required in request.\n"
                + "Valid values are 'yes' and 'no'")
    protected String requireMessageTimeS = "yes";

    @Option(name = "-mtb", aliases = { "--msgTimeBias" },
            description = "Message time bias in seconds")
    protected Integer messageTimeBias;

    @Option(name = "-cwt", aliases = { "--confirmWaitTime" },
            description = "Maximal confirmation time in seconds")
    protected Integer confirmWaitTime;

    @Override
    protected Object doExecute()
    throws Exception
    {
        CmpControl entry = new CmpControl();

        boolean confirmCert = isEnabled(confirmCertS, false, "confirmCert");
        entry.setRequireConfirmCert(confirmCert);

        boolean sendCaCert = isEnabled(sendCaCertS, false, "sendCaCert");
        entry.setSendCaCert(sendCaCert);

        boolean sendResponderCert = isEnabled(sendResponderCertS, true, "sendResponderCert");
        entry.setSendResponderCert(sendResponderCert);

        boolean requireMessageTime = isEnabled(requireMessageTimeS, true, "messageTime");
        entry.setMessageTimeRequired(requireMessageTime);

        if(messageTimeBias != null)
        {
            entry.setMessageBias(messageTimeBias);
        }

        if(confirmWaitTime != null)
        {
            entry.setConfirmWaitTime(confirmWaitTime);
        }

        caManager.setCmpControl(entry);

        return null;
    }
}
