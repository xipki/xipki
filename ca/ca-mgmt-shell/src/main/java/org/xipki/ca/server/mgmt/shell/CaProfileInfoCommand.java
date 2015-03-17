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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-ca", name = "caprofile-info",
        description="show information of certificate profiles in given CA")
public class CaProfileInfoCommand extends CaCommand
{
    @Option(name = "-ca",
            required = true,
            description = "CA name\n"
                    + "(required)")
    private String caName;

    @Override
    protected Object _doExecute()
    throws Exception
    {
        StringBuilder sb = new StringBuilder();
        if(caManager.getCA(caName) == null)
        {
            sb.append("could not find CA '").append(caName).append("'");
        }
        else
        {
            Set<String> entries = caManager.getCertprofilesForCA(caName);
            if(isNotEmpty(entries))
            {
                sb.append("certificate Profiles supported by CA " + caName).append("\n");

                List<String> sorted = new ArrayList<>(entries);
                Collections.sort(sorted);

                for(String entry  : sorted)
                {
                    sb.append("\t").append(entry).append("\n");
                }
            }
            else
            {
                sb.append("\tno profile for CA " + caName + " is configured");
            }
        }

        out(sb.toString());
        return null;
    }
}
