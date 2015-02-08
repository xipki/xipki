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

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-ca", name = "cmpcontrol-update", description="Update CMP control")
public class CmpControlUpdateCommand extends CaCommand
{
    @Option(name = "-name",
            description = "Required. CMP control name",
            required = true, multiValued = false)
    protected String name;

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

        caManager.changeCmpControl(name, requireConfirmCert, requireMessageTime, messageTimeBias, confirmWaitTime,
                sendCaCert, sendResponderCert);
        out("updated CMP control");
        return null;
    }
}
