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

package org.xipki.ca.server.mgmt.qa.shell;

import java.rmi.UnexpectedException;

import org.apache.karaf.shell.commands.Command;
import org.xipki.ca.server.mgmt.api.CmpControlEntry;
import org.xipki.ca.server.mgmt.shell.CmpControlUpdateCommand;
import org.xipki.common.CmpUtf8Pairs;
import org.xipki.console.karaf.CmdFailure;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-caqa", name = "cmpcontrol-check", description="show information of CMP control (QA)")
public class CmpControlCheckCommand extends CmpControlUpdateCommand
{
    @Override
    protected Object _doExecute()
    throws Exception
    {
        CmpControlEntry c = caManager.getCmpControl(name);
        if(c == null)
        {
            throw new CmdFailure("no CMP control named '" + name + "' is configured");
        }

        CmpUtf8Pairs is = new CmpUtf8Pairs(c.getConf());
        CmpUtf8Pairs ex = new CmpUtf8Pairs(conf);
        if(is.equals(ex) == false)
        {
            throw new UnexpectedException("conf: is '" + is.getEncoded() +
                    "', but expected '" + ex.getEncoded() + "'");
        }
        out("checked CMP control " + name);
        return null;
    }
}
