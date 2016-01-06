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

package org.xipki.console.karaf;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.List;

import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.password.api.SecurePasswordInputPanel;

import jline.console.ConsoleReader;

/**
 * @author Lijun Liao
 */

public abstract class XipkiOsgiCommandSupport extends OsgiCommandSupport {
    private static final Logger LOG = LoggerFactory.getLogger(XipkiOsgiCommandSupport.class);

    protected abstract Object _doExecute()
    throws Exception;

    @Override
    protected Object doExecute()
    throws Exception {
        try {
            return _doExecute();
        } catch (Exception e) {
            LOG.debug("Exception caught while executing command", e);
            throw new Exception(e.getClass().getName() + ": " + e.getMessage());
        }
    }

    protected boolean isTrue(
            final Boolean b) {
        return b != null && b.booleanValue();
    }

    protected void saveVerbose(
            String promptPrefix,
            final File file,
            final byte[] encoded)
    throws IOException {
        ConsoleReader reader = (ConsoleReader) session.get(".jline.reader");
        File saveTo = expandFilepath(file);

        boolean randomSaveTo = false;
        if (saveTo.exists()) {
            try {
                boolean b = true;
                while (saveTo.exists()) {
                    if (b) {
                        out("A file named '" + saveTo.getPath()
                            + "' already exists. Do you want to replace it [yes/no]? ");
                    }

                    String answer = reader.readLine();
                    if (answer == null) {
                        throw new IOException("interrupted");
                    }

                    if ("yes".equalsIgnoreCase(answer)) {
                        break;
                    } else if ("no".equalsIgnoreCase(answer)) {
                        out("Enter name of file to save to ... ");
                        String newFn = null;
                        while (true) {
                            newFn = reader.readLine();
                            if (!newFn.trim().isEmpty()) {
                                break;
                            }
                        }

                        saveTo = new File(newFn);
                    } else {
                        out("Please answer with yes or no. ");
                        b = false;
                    }
                }
            } catch (IOException e) {
                saveTo = new File("tmp-" + randomHex(6));
                randomSaveTo = true;
            }
        }

        File parent = file.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        try {
            save(saveTo, encoded);
        } catch (IOException e) {
            if (!randomSaveTo) {
                saveTo = new File("tmp-" + randomHex(6));
                save(saveTo, encoded);
            }
        }

        if (promptPrefix == null || promptPrefix.isEmpty()) {
            promptPrefix = "saved to file";
        }

        out(promptPrefix + " " + saveTo.getPath());
    }

    protected void save(
            File file,
            final byte[] encoded)
    throws IOException {
        file = expandFilepath(file);
        File parent = file.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        FileOutputStream out = new FileOutputStream(file);
        try {
            out.write(encoded);
        } finally {
            out.close();
        }
    }

    private static String randomHex(
            final int n) {
        SecureRandom r = new SecureRandom();
        byte[] bytes = new byte[n];
        r.nextBytes(bytes);
        return new BigInteger(1, bytes).toString(16);
    }

    protected static Boolean isEnabled(
            final String enabledS,
            final String optionName) {
        if (enabledS == null) {
            return null;
        }
        return intern_isEnabled(enabledS, optionName);
    }

    protected static boolean isEnabled(
            final String enabledS,
            final boolean defaultEnabled,
            final String optionName) {
        if (enabledS == null) {
            return defaultEnabled;
        }

        return intern_isEnabled(enabledS, optionName);
    }

    private static boolean intern_isEnabled(
            final String enabledS,
            final String optionName) {
        if ("yes".equalsIgnoreCase(enabledS)
                || "enabled".equalsIgnoreCase(enabledS)
                || "true".equalsIgnoreCase(enabledS)) {
            return true;
        } else if ("no".equalsIgnoreCase(enabledS)
                || "disabled".equalsIgnoreCase(enabledS)
                || "false".equalsIgnoreCase(enabledS)) {
            return false;
        } else {
            throw new IllegalArgumentException("invalid option " + optionName + ": " + enabledS);
        }
    }

    protected char[] readPasswordIfNotSet(
            final String password) {
        if (password != null) {
            return password.toCharArray();
        }

        return readPassword("Enter the password");
    }

    protected char[] readPassword() {
        return readPassword("Enter the password");
    }

    protected char[] readPassword(
            final String prompt) {
        String passwordUi = System.getProperty("org.xipki.console.passwordui");
        if ("gui".equalsIgnoreCase(passwordUi)) {
            return SecurePasswordInputPanel.readPassword(prompt);
        } else {
            ConsoleReader reader = (ConsoleReader) session.get(".jline.reader");
            out(prompt);
            try {
                String pwd = reader.readLine('*');
                return pwd.toCharArray();
            } catch (IOException e) {
                return new char[0];
            }
        }
    }

    protected static String expandFilepath(
            final String path) {
        return IoUtil.expandFilepath(path);
    }

    protected static File expandFilepath(
            final File file) {
        return IoUtil.expandFilepath(file);
    }

    protected void out(
            final String message) {
        System.out.println(message);
    }

    protected static boolean isBlank(
            final String s) {
        return StringUtil.isBlank(s);
    }

    protected static boolean isNotBlank(
            final String s) {
        return StringUtil.isNotBlank(s);
    }

    protected static boolean isEmpty(
            final Collection<?> c) {
        return CollectionUtil.isEmpty(c);
    }

    protected static boolean isNotEmpty(
            final Collection<?> c) {
        return CollectionUtil.isNotEmpty(c);
    }

    protected static List<String> split(
            final String str,
            final String delim) {
        return StringUtil.split(str, delim);
    }

    protected static BigInteger toBigInt(
            String s) {
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {
            if (s.length() > 2) {
                return new BigInteger(s.substring(2), 16);
            } else {
                throw new NumberFormatException("invalid integer '" + s + "'");
            }
        }
        return new BigInteger(s);
    }
}
