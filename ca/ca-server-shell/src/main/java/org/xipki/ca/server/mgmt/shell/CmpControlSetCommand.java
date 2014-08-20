/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Command;
import org.xipki.ca.common.CmpControl;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "cmpcontrol-set", description="Set CMP control")
public class CmpControlSetCommand extends CmpControlSetOrUpdateCommand
{
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
