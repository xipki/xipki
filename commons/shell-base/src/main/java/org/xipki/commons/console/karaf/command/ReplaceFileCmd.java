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

package org.xipki.commons.console.karaf.command;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.console.karaf.XipkiCommandSupport;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-cmd", name = "replace",
        description = "Replace text in file")
@Service
public class ReplaceFileCmd extends XipkiCommandSupport {

    @Argument(index = 0, name = "file",
            required = true,
            description = "file\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String source;

    @Option(name = "--old",
            required = true,
            description = "text to be replaced")
    private String oldText;

    @Option(name = "--new",
            required = true,
            description = "next text")
    private String newText;

    @Override
    protected Object doExecute() throws Exception {
        File sourceFile = new File(expandFilepath(source));
        if (!sourceFile.exists()) {
            System.err.println(source + " does not exist");
            return null;
        }

        if (!sourceFile.isFile()) {
            System.err.println(source + " is not a file");
            return null;
        }

        ParamUtil.requireNonBlank("old", oldText);

        replaceFile(sourceFile, oldText, newText);

        return null;
    }

    private void replaceFile(final File file, final String oldText, final String newText)
    throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader(file));

        ByteArrayOutputStream writer = new ByteArrayOutputStream();

        boolean changed = false;
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(oldText)) {
                    changed = true;
                    writer.write(line.replace(oldText, newText).getBytes());
                } else {
                    writer.write(line.getBytes());
                }
                writer.write('\n');
            }
        } finally {
            writer.close();
            reader.close();
        }

        if (changed) {
            File newFile = new File(file.getPath() + "-new");
            byte[] newBytes = writer.toByteArray();
            IoUtil.save(file, newBytes);
            newFile.renameTo(file);
        }
    }

}
