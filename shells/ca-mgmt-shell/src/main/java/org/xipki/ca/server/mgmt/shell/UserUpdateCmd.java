/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.api.NameId;
import org.xipki.ca.server.mgmt.api.ChangeUserEntry;
import org.xipki.console.karaf.IllegalCmdParamException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "user-up",
        description = "update user")
@Service
public class UserUpdateCmd extends CaCommandSupport {

    @Option(name = "--name", aliases = "-n",
            required = true,
            description = "user Name\n"
                    + "(required)")
    private String name;

    @Option(name = "--active",
            description = "activate this user")
    private Boolean active;

    @Option(name = "--inactive",
            description = "deactivate this user")
    private Boolean inactive;

    @Option(name = "--password",
            description = "user password, 'CONSOLE' to read from console")
    private String password;

    @Override
    protected Object execute0() throws Exception {
        Boolean realActive;
        if (active != null) {
            if (inactive != null) {
                throw new IllegalCmdParamException(
                        "maximal one of --active and --inactive can be set");
            }
            realActive = Boolean.TRUE;
        } else if (inactive != null) {
            realActive = Boolean.FALSE;
        } else {
            realActive = null;
        }

        ChangeUserEntry entry = new ChangeUserEntry(new NameId(null, name));
        if (realActive != null) {
            entry.setActive(realActive);
        }

        if ("CONSOLE".equalsIgnoreCase(password)) {
            password = new String(readPassword());
        }

        if (password != null) {
            entry.setPassword(password);
        }

        boolean bo = caManager.changeUser(entry);
        output(bo, "changed", "could not change", "user " + name);
        return null;
    }

}
