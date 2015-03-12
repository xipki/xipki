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

import java.util.List;

import org.xipki.ca.server.mgmt.api.CAManager;
import org.xipki.console.karaf.XipkiOsgiCommandSupport;

/**
 * @author Lijun Liao
 */

public abstract class CaCommand extends XipkiOsgiCommandSupport
{
    public final static String permissionsText =
            "enroll, revoke, unrevoke, remove, key-update, gen-crl, get-crl, enroll-cross, all";

    protected CAManager caManager;

    public void setCaManager(CAManager caManager)
    {
        this.caManager = caManager;
    }

    protected static String getRealString(String s)
    {
        return CAManager.NULL.equalsIgnoreCase(s) ? null : s;
    }

    protected static String toString(List<? extends Object> list)
    {
        StringBuilder sb = new StringBuilder();
        if(list == null)
        {
            sb.append("null");
        }

        sb.append("{");
        int n = list.size();
        for(int i = 0; i < n; i++)
        {
            Object o = list.get(i);
            sb.append(o);
            if(i == n - 1 && n != 0)
            {
                sb.append(", ");
            }
        }
        sb.append("}");
        return sb.toString();
    }

    protected void output(boolean successful, String posPrefix, String negPrefix, String message)
    {
        if(successful)
        {
            out(posPrefix + " " + message);
        }
        else
        {
            err(negPrefix + " " + message);
        }
    }
}
