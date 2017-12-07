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

import java.util.Set;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.server.mgmt.api.CaEntry;
import org.xipki.ca.server.mgmt.api.CaStatus;
import org.xipki.ca.server.mgmt.shell.completer.CaNameCompleter;
import org.xipki.console.karaf.CmdFailure;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "ca-info",
        description = "show information of CA")
@Service
public class CaInfoCmd extends CaCommandSupport {

    @Argument(index = 0, name = "name", description = "CA name")
    @Completion(CaNameCompleter.class)
    private String name;

    @Option(name = "--verbose", aliases = "-v",
            description = "show CA information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
        StringBuilder sb = new StringBuilder();
        if (name == null) {
            sb.append("successful CAs:\n");
            String prefix = "  ";
            printCaNames(sb, caManager.getSuccessfulCaNames(), prefix);

            sb.append("failed CAs:\n");
            printCaNames(sb, caManager.getFailedCaNames(), prefix);

            sb.append("inactive CAs:\n");
            printCaNames(sb, caManager.getInactiveCaNames(), prefix);
        } else {
            CaEntry entry = caManager.getCa(name);
            if (entry == null) {
                throw new CmdFailure("could not find CA '" + name + "'");
            } else {
                if (CaStatus.ACTIVE == entry.status()) {
                    boolean started = caManager.getSuccessfulCaNames().contains(
                            entry.ident().name());
                    sb.append("started: ").append(started).append("\n");
                }
                Set<String> aliases = caManager.getAliasesForCa(name);
                sb.append("aliases: ").append(toString(aliases)).append("\n");
                sb.append(entry.toString(verbose.booleanValue()));
            }
        }

        println(sb.toString());
        return null;
    } // method execute0

}
