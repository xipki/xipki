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

package org.xipki.console.karaf.impl;

import java.io.IOException;

import jline.console.ConsoleReader;

import org.apache.karaf.shell.commands.Argument;
import org.apache.karaf.shell.commands.Command;
import org.xipki.console.karaf.XipkiOsgiCommandSupport;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-cmd", name = "prompt", description="Prompt")
public class PromptCommand extends XipkiOsgiCommandSupport
{
    @Argument(index = 0, name = "message",
            required = true,
            description = "prompt message\n"
                    + "(required)")
    private String prompt;

    @Override
    protected Object _doExecute()
    throws Exception
    {
        ConsoleReader reader = (ConsoleReader) session.get(".jline.reader");

        boolean toContinue = confirm(reader, prompt + "\nDo you want to contine [yes/no]?");
        if(toContinue == false)
        {
            throw new Exception("User cancelled");
        }

        return null;
    }

    private boolean confirm(
            final ConsoleReader reader,
            final String prompt)
    throws IOException
    {
        out(prompt);
        String answer = reader.readLine();
        if(answer == null)
        {
            throw new IOException("interrupted");
        }

        int tries = 0;

        while(tries < 3)
        {
            if("yes".equalsIgnoreCase(answer))
            {
                return true;
            }
            else if("no".equalsIgnoreCase(answer))
            {
                return false;
            }
            else
            {
                tries++;
                out("Please answer with yes or no. ");
            }
        }

        return false;
    }

}
