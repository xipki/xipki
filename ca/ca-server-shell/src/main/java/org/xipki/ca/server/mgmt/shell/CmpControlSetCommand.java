/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.cmp.server.CmpControl;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "cmpcontrol-set", description="Set CMP control")
public class CmpControlSetCommand extends CaCommand
{
    @Option(name = "-cc", aliases = { "--confirmCert" },
            description = "Whether confirm of certificate is required.\n"
                + "Valid values are 'yes' and 'no',\n"
                + "the default is 'no'")
    protected String           confirmCertS;

    @Option(name = "-scc", aliases = { "--sendCaCert" },
            description = "Whether CA certificate is included in response.\n"
                + "Valid values are 'yes' and 'no',\n"
                + "the default is 'no'")
    protected String            sendCaCertS;

    @Option(name = "-src", aliases = { "--sendResponderCert" },
            description = "Whether responder certificate is included in response.\n"
                + "Valid values are 'yes' and 'no',\n"
                + "the default is 'yes'")
    protected String            sendResponderCertS;

    @Option(name = "-mt", aliases = { "--messageTime" },
            description = "Whether message time is required in request.\n"
                + "Valid values are 'yes' and 'no',\n"
                + "the default is 'yes'")
    protected String            requireMessageTimeS;

    @Option(name = "-mtb", aliases = { "--msgTimeBias" },
            description = "Message time bias in seconds")
    protected Integer            messageTimeBias;

    @Option(name = "-cwt", aliases = { "--confirmWaitTime" },
            description = "Maximal confirmation time in seconds")
    protected Integer            confirmWaitTime;

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
