/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
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

package org.xipki.console.karaf.command;

import java.io.File;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.console.karaf.XipkiCommandSupport;
import org.xipki.console.karaf.completer.DirPathCompleter;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.console.karaf.intern.FileUtils;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-cmd", name = "copy-file",
        description = "copy file")
@Service
public class CopyFileCmd extends XipkiCommandSupport {

    @Argument(index = 0, name = "source file",
            required = true,
            description = "file to be copied\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String source;

    @Argument(index = 1, name = "destination",
            required = true,
            description = "destination directory or file\n"
                    + "(required)")
    @Completion(DirPathCompleter.class)
    private String dest;

    @Option(name = "--recursive", aliases = "-r",
            description = "copy directories and their contents recursively")
    private Boolean recursive = Boolean.FALSE;

    @Override
    protected Object doExecute()
    throws Exception {
        File sourceFile = new File(expandFilepath(source));
        if (!sourceFile.exists()) {
            System.err.println(source + " does not exist");
            return null;
        }

        if (!sourceFile.isFile()) {
            System.err.println(source + " is not a file");
            return null;
        }

        File destFile = new File(dest);
        if (destFile.exists()) {
            if (!destFile.isFile()) {
                System.err.println("cannot override an existing directory by a file");
                return null;
            } else {
                if (!confirm("Do you want to override the file " + dest, 3)) {
                    return null;
                }
            }
        } else {
            File parent = destFile.getParentFile();
            if (parent != null) {
                parent.mkdirs();
            }
        }

        FileUtils.copyFile(sourceFile, destFile, true);

        return null;
    }

}
