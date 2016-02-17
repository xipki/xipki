/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.ca.server.mgmt.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.common.CmpControl;
import org.xipki.console.karaf.YesNoCompleter;

/**
 * @author Lijun Liao
 */

@Command(scope = "ca", name = "cmpcontrol-set", description="Set CMP control")
@Service
public class CmpControlSetCommand extends CaCommand
{
    @Option(name = "-cc", aliases = { "--confirmCert" },
            description = "Whether confirm of certificate is required.\n"
                + "Valid values are 'yes' and 'no'")
    @Completion(YesNoCompleter.class)
    protected String confirmCertS = "no";

    @Option(name = "-scc", aliases = { "--sendCaCert" },
            description = "Whether CA certificate is included in response.\n"
                + "Valid values are 'yes' and 'no'")
    @Completion(YesNoCompleter.class)
    protected String sendCaCertS = "no";

    @Option(name = "-src", aliases = { "--sendResponderCert" },
            description = "Whether responder certificate is included in response.\n"
                + "Valid values are 'yes' and 'no'")
    @Completion(YesNoCompleter.class)
    protected String sendResponderCertS = "yes";

    @Option(name = "-mt", aliases = { "--messageTime" },
            description = "Whether message time is required in request.\n"
                + "Valid values are 'yes' and 'no'")
    @Completion(YesNoCompleter.class)
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
        out("configured CMP control");

        return null;
    }
}
