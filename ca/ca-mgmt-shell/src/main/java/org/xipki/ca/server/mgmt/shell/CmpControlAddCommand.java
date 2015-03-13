/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.xipki.ca.server.mgmt.api.CmpControl;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-ca", name = "cmpcontrol-add", description="add CMP control")
public class CmpControlAddCommand extends CaCommand
{
    @Option(name = "-name",
            required = true,
            description = "CMP control name\n"
                    + "required")
    private String name;

    @Option(name = "-cc", aliases = { "--confirmCert" },
            description = "whether confirm of certificate is required")
    private String confirmCertS = "no";

    @Option(name = "-scc", aliases = { "--sendCaCert" },
            description = "whether CA certificate is included in response")
    private String sendCaCertS = "no";

    @Option(name = "-src", aliases = { "--sendResponderCert" },
            description = "whether responder certificate is included in response")
    private String sendResponderCertS = "yes";

    @Option(name = "-mt", aliases = { "--messageTime" },
            description = "whether message time is required in request")
    private String requireMessageTimeS = "yes";

    @Option(name = "-mtb", aliases = { "--msgTimeBias" },
            description = "message time bias in seconds")
    private Integer messageTimeBias;

    @Option(name = "-cwt", aliases = { "--confirmWaitTime" },
            description = "maximal confirmation time in seconds")
    private Integer confirmWaitTime;

    @Override
    protected Object _doExecute()
    throws Exception
    {
        CmpControl entry = new CmpControl(name);

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

        boolean b = caManager.addCmpControl(entry);
        output(b, "added", "could not add", "CMP control " + name);
        return null;
    }
}
