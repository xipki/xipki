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

package org.xipki.console.karaf.completer;

import java.io.File;
import java.io.FilenameFilter;
import java.util.LinkedList;
import java.util.List;

import org.apache.karaf.shell.api.console.CommandLine;
import org.apache.karaf.shell.api.console.Completer;
import org.apache.karaf.shell.api.console.Session;
import org.xipki.console.karaf.intern.Configuration;
import org.xipki.console.karaf.intern.MyFilenameFilter;

/**
 * @author Lijun Liao
 */

abstract class AbstractPathCompleter implements Completer {

    protected abstract boolean isDirOnly();

    private static final boolean OS_IS_WINDOWS = Configuration.isWindows();

    private static final FilenameFilter filenameFilter = new MyFilenameFilter();

    @Override
    public int complete(
            Session session,
            final CommandLine commandLine,
            final List<String> candidates) {
        // buffer can be null
        if (candidates == null) {
            return 0;
        }

        String buffer = commandLine.getCursorArgument();
        buffer = (buffer != null)
                ? buffer.substring(0, commandLine.getArgumentPosition())
                : "";

        if (OS_IS_WINDOWS) {
            buffer = buffer.replace('/', '\\');
        }

        String translated = buffer;

        File homeDir = getUserHome();

        // Special character: ~ maps to the user's home directory
        if (translated.startsWith("~" + separator())) {
            translated = homeDir.getPath() + translated.substring(1);
        } else if (translated.startsWith("~")) {
            translated = homeDir.getParentFile().getAbsolutePath();
        } else if (!(new File(translated).isAbsolute())) {
            String cwd = getUserDir().getAbsolutePath();
            translated = cwd + separator() + translated;
        }

        File file = new File(translated);
        final File dir;

        if (translated.endsWith(separator())) {
            dir = file;
        } else {
            dir = file.getParentFile();
        }

        File[] entries = (dir == null)
                ? new File[0]
                : dir.listFiles(filenameFilter);
        if (isDirOnly()
                && entries != null
                && entries.length > 0) {
            List<File> list = new LinkedList<File>();
            for (File f : entries) {
                if (f.isDirectory()) {
                    list.add(f);
                }
            }
            entries = list.toArray(new File[0]);
        }

        return matchFiles(buffer, translated, entries, candidates)
                + commandLine.getBufferPosition()
                - commandLine.getArgumentPosition();
    }

    protected String separator() {
        return File.separator;
    }

    protected File getUserHome() {
        return Configuration.getUserHome();
    }

    protected File getUserDir() {
        return new File(".");
    }

    protected int matchFiles(
            final String buffer,
            final String translated,
            final File[] files,
            final List<String> candidates) {
        if (files == null) {
            return -1;
        }

        int matches = 0;

        // first pass: just count the matches
        for (File file : files) {
            if (file.getAbsolutePath().startsWith(translated)) {
                matches++;
            }
        }

        String sep = separator();
        for (File file : files) {
            if (file.getAbsolutePath().startsWith(translated)) {
                String name = file.getName();
                if (matches == 1 && file.isDirectory()) {
                    name += sep;
                    // this line prevent from appending whitespace
                    candidates.add(render(file, name).toString());
                } else {
                    name += " ";
                }
                candidates.add(render(file, name).toString());
            }
        }

        final int index = buffer.lastIndexOf(sep);

        return index + sep.length();
    }

    protected CharSequence render(
            final File file,
            final CharSequence name) {
        return name;
    }

}
