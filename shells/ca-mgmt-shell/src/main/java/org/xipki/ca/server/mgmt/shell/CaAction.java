/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.server.mgmt.shell;

import java.util.Collection;
import java.util.Set;

import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.xipki.ca.server.mgmt.api.CaManager;
import org.xipki.common.util.CollectionUtil;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.console.karaf.XiAction;
import org.xipki.security.SecurityFactory;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class CaAction extends XiAction {

    @Reference
    protected CaManager caManager;

    @Reference
    protected SecurityFactory securityFactory;

    protected static String getRealString(final String str) {
        return CaManager.NULL.equalsIgnoreCase(str) ? null : str;
    }

    protected static String toString(final Collection<? extends Object> col) {
        if (col == null) {
            return "null";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        int size = col.size();

        int idx = 0;
        for (Object o : col) {
            sb.append(o);
            if (idx < size - 1) {
                sb.append(", ");
            }
            idx++;
        }
        sb.append("}");
        return sb.toString();
    }

    protected void output(final boolean successful, final String posPrefix, final String negPrefix,
            final String message) throws CmdFailure {
        if (successful) {
            println(posPrefix + " " + message);
        } else {
            throw new CmdFailure(negPrefix + " " + message);
        }
    }

    protected void printCaNames(StringBuilder sb, Set<String> caNames, String prefix) {
        if (caNames.isEmpty()) {
            sb.append(prefix).append("-\n");
            return;
        }

        for (String caName : caNames) {
            Set<String> aliases = caManager.getAliasesForCa(caName);
            if (CollectionUtil.isEmpty(aliases)) {
                sb.append(prefix).append(caName);
            } else {
                sb.append(prefix).append(caName + " (aliases " + aliases + ")");
            }
            sb.append("\n");
        }
    }

}
