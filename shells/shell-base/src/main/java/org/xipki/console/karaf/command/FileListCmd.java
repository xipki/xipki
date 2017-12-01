/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.console.karaf.command;

import java.io.File;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.XipkiCommandSupport;
import org.xipki.console.karaf.completer.FilePathCompleter;

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
    protected Object execute0() throws Exception {
        File target = new File(expandFilepath(targetPath));
        if (!target.exists()) {
            throw new IllegalCmdParamException(
                    "could not access " + targetPath + ": no such file or directory");
        }

        if (!target.isDirectory()) {
            print(targetPath);
            return null;
        }

        List<String> list = new LinkedList<>();
        File[] children = target.listFiles();
        int maxLen = -1;

        if (children != null) {
            for (File child : children) {
                String name = child.getName();
                if (child.isDirectory()) {
                    name += File.separator;
                }
                list.add(name);
                maxLen = Math.max(maxLen, name.length());
            }
        }

        if (isEmpty(list)) {
            return null;
        }

        Collections.sort(list);
        List<String> l2 = new LinkedList<>();

        for (String s : list) {
            String tmpS = s;
            int diffLen = maxLen - tmpS.length();
            if (diffLen > 0) {
                for (int i = 0; i < diffLen; i++) {
                    tmpS += " ";
                }
            }
            l2.add(tmpS);
        }

        int width = session.getTerminal().getWidth();

        final int n = width / (maxLen + 1);
        if (n == 0) {
            for (String s :l2) {
                print(s);
            }
        } else {
            for (int i = 0; i < l2.size(); i += n) {
                StringBuilder sb = new StringBuilder();
                for (int j = i; j < Math.min(l2.size(), i + n); j++) {
                    sb.append(l2.get(j)).append(" ");
                }
                print(sb.toString());
            }
        }

        println("");

        return null;
    }

}
