/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.pki.ca.server.mgmt.qa.shell;

import java.util.Collection;

import org.xipki.commons.console.karaf.CmdFailure;
import org.xipki.pki.ca.server.mgmt.api.CaManager;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class MgmtQaShellUtil {

    private MgmtQaShellUtil() {
    }

    public static void assertEquals(
            final String desc,
            final String ex,
            final String is)
    throws CmdFailure {

        String tmpEx = ex;
        if (CaManager.NULL.equals(tmpEx)) {
            tmpEx = null;
        }

        boolean b;
        if (tmpEx == null) {
            b = (is == null);
        } else {
            b = tmpEx.equals(is);
        }

        if (!b) {
            throw new CmdFailure(desc + ": is '" + is + "', but expected '" + tmpEx + "'");
        }
    }

    public static void assertEquals(
            final String desc,
            final Collection<?> ex, Collection<?> is)
    throws CmdFailure {
        boolean b;
        if (ex == null) {
            b = (is == null);
        } else {
            b = ex.equals(is);
        }

        if (!b) {
            throw new CmdFailure(desc + ": is '" + is + "', but expected '" + ex + "'");
        }
    }

}
