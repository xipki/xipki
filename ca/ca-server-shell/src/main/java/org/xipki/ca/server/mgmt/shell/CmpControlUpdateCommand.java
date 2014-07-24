/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Command;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "cmpcontrol-update", description="Update CMP control")
public class CmpControlUpdateCommand extends CmpControlSetOrUpdateCommand
{
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
