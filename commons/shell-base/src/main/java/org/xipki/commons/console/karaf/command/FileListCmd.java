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

package org.xipki.commons.console.karaf.command;

import java.io.File;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.commons.console.karaf.IllegalCmdParamException;
import org.xipki.commons.console.karaf.XipkiCommandSupport;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-cmd", name = "ls",
        description = "list directory contents")
@Service
public class FileListCmd extends XipkiCommandSupport {

    @Argument(index = 0, name = "file",
            required = true,
            description = "file or directory\n"
                    + "(required)")
    @Completion(FilePathCompleter.class)
    private String targetPath;

    @Override
    protected Object doExecute()
    throws Exception {
        File target = new File(expandFilepath(targetPath));
        if (!target.exists()) {
            throw new IllegalCmdParamException(
                    "could not access " + targetPath + ": no such file or directory");
        }

        if (!target.isDirectory()) {
            out(targetPath);
            return null;
        }

        List<String> l = new LinkedList<>();
        File[] children = target.listFiles();
        int maxLen = -1;
        for (File child : children) {
            String name = child.getName();
            if (child.isDirectory()) {
                name += File.separator;
            }
            l.add(name);
            maxLen = Math.max(maxLen, name.length());
        }

        if (isEmpty(l)) {
            return null;
        }

        Collections.sort(l);
        List<String> l2 = new LinkedList<>();

        for (String s : l) {
            String lS = s;
            int diffLen = maxLen - lS.length();
            if (diffLen > 0) {
                for (int i = 0; i < diffLen; i++) {
                    lS += " ";
                }
            }
            l2.add(lS);
        }

        int width = session.getTerminal().getWidth();

        int n = width / (maxLen + 1);
        if (n == 0) {
            for (String s :l2) {
                out(s);
            }
        } else {
            for (int i = 0; i < l2.size(); i += n) {
                StringBuilder sb = new StringBuilder();
                for (int j = i; j < Math.min(l2.size(), i + n); j++) {
                    sb.append(l2.get(j)).append(" ");
                }
                out(sb.toString());
            }
        }

        return null;
    }

}
