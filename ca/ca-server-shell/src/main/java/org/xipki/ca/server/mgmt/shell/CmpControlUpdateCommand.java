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

@Command(scope = "ca", name = "cmpcontrol-update", description="Update CMP control")
public class CmpControlUpdateCommand extends CaCommand
{
    @Option(name = "-cc", aliases = { "--confirmCert" },
            description = "Whether confirm of certificate is required.\n"
                + "Valid values are 'yes' and 'no'")
    protected String confirmCertS;

    @Option(name = "-scc", aliases = { "--sendCaCert" },
            description = "Whether CA certificate is included in response.\n"
                + "Valid values are 'yes' and 'no'")
    protected String sendCaCertS;

    @Option(name = "-src", aliases = { "--sendResponderCert" },
            description = "Whether responder certificate is included in response.\n"
                + "Valid values are 'yes' and 'no'")
    protected String sendResponderCertS;

    @Option(name = "-mt", aliases = { "--messageTime" },
            description = "Whether message time is required in request.\n"
                + "Valid values are 'yes' and 'no'")
    protected String requireMessageTimeS;

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
        Boolean sendCaCert = isEnabled(sendCaCertS, "sendCaCert");
        Boolean sendResponderCert = isEnabled(sendResponderCertS, "sendResponderCert");
        Boolean requireMessageTime = isEnabled(requireMessageTimeS, "messageTime");
        Boolean requireConfirmCert = isEnabled(confirmCertS, "confirmCert");

        caManager.changeCmpControl(requireConfirmCert, requireMessageTime, messageTimeBias, confirmWaitTime,
                sendCaCert, sendResponderCert);

        return null;
    }
}
