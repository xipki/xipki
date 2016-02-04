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

package org.xipki.pki.ca.server.mgmt.shell;

import java.util.Collection;

import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.xipki.commons.console.karaf.CmdFailure;
import org.xipki.commons.console.karaf.XipkiCommandSupport;
import org.xipki.pki.ca.server.mgmt.api.CAManager;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class CaCommandSupport extends XipkiCommandSupport {

    @Reference
    protected CAManager caManager;

    protected static String getRealString(
            final String s) {
        return CAManager.NULL.equalsIgnoreCase(s)
                ? null
                : s;
    }

    protected static String toString(
            final Collection<? extends Object> c) {
        if (c == null) {
            return "null";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        int n = c.size();

        int i = 0;
        for (Object o : c) {
            sb.append(o);
            if (i < n - 1) {
                sb.append(", ");
            }
            i++;
        }
        sb.append("}");
        return sb.toString();
    }

    protected void output(
            final boolean successful,
            final String posPrefix,
            final String negPrefix,
            final String message)
    throws CmdFailure {
        if (successful) {
            out(posPrefix + " " + message);
        } else {
            throw new CmdFailure(negPrefix + " " + message);
        }
    }

}
