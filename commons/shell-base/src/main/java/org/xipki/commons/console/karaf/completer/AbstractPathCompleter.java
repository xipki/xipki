/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.commons.console.karaf.completer;

import java.io.File;
import java.io.FilenameFilter;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.karaf.shell.api.console.Candidate;
import org.apache.karaf.shell.api.console.CommandLine;
import org.apache.karaf.shell.api.console.Completer;
import org.apache.karaf.shell.api.console.Session;
import org.xipki.commons.console.karaf.intern.Configuration;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

abstract class AbstractPathCompleter implements Completer {
    private static final String SEP = File.separator;

    private static class MyFilenameFilter implements FilenameFilter {

        private static final Pattern IGNORE_PATTERN;

        static {
            String ignoreRegex = System.getProperty("org.xipki.console.ignore.regex");
            if (ignoreRegex == null) {
                if (!Configuration.isWindows()) {
                    ignoreRegex = "\\..*";
                }
            }

            IGNORE_PATTERN = (ignoreRegex == null || ignoreRegex.isEmpty()) ? null
                    : Pattern.compile(ignoreRegex);
        }

        @Override
        public boolean accept(final File dir, final String name) {
            if (IGNORE_PATTERN == null) {
                return true;
            }

            return !IGNORE_PATTERN.matcher(name).matches();
        }

    }

    private static final boolean OS_IS_WINDOWS = Configuration.isWindows();

    private static final FilenameFilter FILENAME_FILTER = new MyFilenameFilter();

    protected abstract boolean isDirOnly();

    @Override
    public int complete(final Session session, CommandLine commandLine,
            final List<String> candidates) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void completeCandidates(final Session session, CommandLine commandLine,
            final List<Candidate> candidates) {
        // buffer can be null
        if (candidates == null) {
            return;
        }

        String buffer = commandLine.getCursorArgument();
        buffer = buffer != null ? buffer.substring(0, commandLine.getArgumentPosition()) : "";

        if (OS_IS_WINDOWS) {
            buffer = buffer.replace('/', '\\');
        }

        String translated = buffer;
        File homeDir = getUserHome();

        // Special character: ~ maps to the user's home directory
        if (translated.startsWith("~" + SEP)) {
            translated = homeDir.getAbsolutePath() + translated.substring(1);
        } else if (translated.startsWith("~")) {
            translated = homeDir.getParentFile().getAbsolutePath();
        } else if (!(new File(translated).isAbsolute())) {
            String cwd = getUserDir().getAbsolutePath();
            translated = cwd + SEP + translated;
        }

        File file = new File(translated);
        final File dir = translated.endsWith(SEP) ? file : file.getParentFile();

        File[] entries = (dir == null) ? new File[0] : dir.listFiles(FILENAME_FILTER);
        if (isDirOnly() && entries != null && entries.length > 0) {
            List<File> list = new LinkedList<File>();
            for (File f : entries) {
                if (f.isDirectory()) {
                    list.add(f);
                }
            }
            entries = list.toArray(new File[0]);
        }

        matchFiles(buffer, translated, entries, candidates);
    }

    protected File getUserHome() {
        return Configuration.getUserHome();
    }

    protected File getUserDir() {
        return new File(".");
    }

    protected void matchFiles(final String buffer, final String translated, final File[] files,
            final List<Candidate> candidates) {
        if (files == null) {
            return;
        }

        for (File file : files) {
            if (file.getAbsolutePath().startsWith(translated)) {
                boolean dir = file.isDirectory();
                CharSequence name = file.toString();
                if (name.length() >= translated.length()) {
                    name = buffer + name.subSequence(translated.length(), name.length());
                }

                if (dir) {
                    name = name + SEP;
                }

                candidates.add(new Candidate(render(file, name).toString(), !dir));
            }
        }
    }

    protected CharSequence render(final File file, final CharSequence name) {
        return name;
    }

}
