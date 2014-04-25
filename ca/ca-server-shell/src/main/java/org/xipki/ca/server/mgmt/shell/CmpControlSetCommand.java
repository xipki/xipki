/*
 * Copyright (c) 2014 xipki.org
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

@Command(scope = "ca", name = "cmpcontrol-set", description="Set CMP control")
public class CmpControlSetCommand extends CaCommand
{
    @Option(name = "-ecc", aliases = { "--enableConfirmCert" },
            description = "Confirm of certificate is required, the default is not required")
    protected Boolean           enabledConfirmCert;

    @Option(name = "-dcc", aliases = { "--disableConfirmCert" },
            description = "Confirm of certificate is not required")
    protected Boolean           disableConfirmCert;

    @Option(name = "-esc", aliases = { "--enableSendCaCert" },
            description = "Enable sending CA certificate in the response, the default is disabled")
    protected Boolean            enableSendCaCert;

    @Option(name = "-dsc", aliases = { "--disableSendCaCert" },
            description = "Disable sending CA certificate in the responsed")
    protected Boolean            disableSendCaCert;

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

        if(enabledConfirmCert != null && disableConfirmCert != null )
        {
            System.err.println("Confirm of certificate could not be enabled and disabled at the same time");
        }
        boolean confirmCert = isEnabled(enabledConfirmCert, disableConfirmCert, false);
        entry.setRequireConfirmCert(confirmCert);

        if(enableSendCaCert != null && disableSendCaCert != null )
        {
            System.err.println("Sending CA certificate could not be enabled and disabled at the same time");
        }
        boolean sendCaCert = isEnabled(enableSendCaCert, disableSendCaCert, false);
        entry.setSendCaCert(sendCaCert);

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
