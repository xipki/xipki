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

import java.io.File;
import java.io.IOException;

import jline.console.ConsoleReader;

import org.apache.karaf.shell.commands.Argument;
import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.xipki.console.karaf.XipkiOsgiCommandSupport;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-file", name = "rm", description="remove file or directory")
public class FileRmCommand extends XipkiOsgiCommandSupport
{
    @Argument(index = 0, name = "file",
            required = true,
            description = "file or directory to be deleted\n"
                    + "(required)")
    private String targetPath;

    @Option(name = "--recursive", aliases="-r",
            description = "remove directories and their contents recursively")
    private Boolean recursive = Boolean.FALSE;

    @Option(name = "--force", aliases="-f",
            description = "ignore nonexistent files, never prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object _doExecute()
    throws Exception
    {
        ConsoleReader reader = (ConsoleReader) session.get(".jline.reader");

        File target = new File(expandFilepath(targetPath));
        if(target.exists() == false)
        {
            return null;
        }

        if(target.isDirectory())
        {
            if(recursive == false)
            {
                err("Please use option --recursive to delete directory");
                return null;
            }

            if(force || confirm(reader, "remove directory " + targetPath))
            {
                FileUtils.deleteDirectory(target);
                out("removed directory " + targetPath);
            }
        }
        else
        {
            if(force || confirm(reader, "remove file " + targetPath))
            {
                target.delete();
                out("removed file " + targetPath);
            }
        }

        return null;
    }

    private boolean confirm(
            final ConsoleReader reader,
            final String prompt)
    throws IOException
    {
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
