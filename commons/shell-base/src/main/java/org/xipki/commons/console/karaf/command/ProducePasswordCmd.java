/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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

package org.xipki.commons.console.karaf.command;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.console.karaf.XipkiCommandSupport;
import org.xipki.commons.console.karaf.completer.PasswordNameCompleter;
import org.xipki.commons.password.api.PasswordProducer;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-cmd", name = "produce-password",
        description = "Produce password")
@Service
public class ProducePasswordCmd extends XipkiCommandSupport {

    @Option(name = "--name", required = true, description = "name of the password")
    @Completion(PasswordNameCompleter.class)
    private String name;

    @Option(name = "-k", description = "quorum of the password parts")
    private Integer quorum = 1;

    @Override
    protected Object doExecute()
    throws Exception {
        if (!PasswordProducer.needsPassword(name)) {
            throw new IllegalCmdParamException("password named '" + name
                    + "' will not be requested");
        }

        while (PasswordProducer.needsPassword(name)) {
            char[] password;
            if (quorum == 1) {
                password = readPassword("Password");
            } else {
                char[][] parts = new char[quorum][];
                for (int i = 0; i < quorum; i++) {
                    parts[i] = readPassword("Password (part " + (i + 1) + "/" + quorum + ")");
                }
                password = StringUtil.merge(parts);
            }
            PasswordProducer.putPassword(name, password);
            // wait for 2 seconds so that the password will be consumed
            Thread.sleep(2000);
        }
        return null;
    }

}
