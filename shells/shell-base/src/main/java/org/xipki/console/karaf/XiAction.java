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

package org.xipki.console.karaf;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.List;

import org.apache.karaf.shell.api.action.Action;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.console.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.password.SecurePasswordInputPanel;

/**
 * @author Lijun Liao
 * @since 3.0.1
 */

public abstract class XiAction implements Action {

    private static final Logger LOG = LoggerFactory.getLogger(XiAction.class);

    @Reference
    protected Session session;

    protected abstract Object execute0() throws Exception;

    @Override
    public Object execute() throws Exception {
        try {
            return execute0();
        } catch (Exception ex) {
            LOG.debug("Exception caught while executing command", ex);
            throw new Exception(ex.getClass().getName() + ": " + ex.getMessage());
        }
    }

    protected boolean isTrue(final Boolean bo) {
        return bo != null && bo.booleanValue();
    }

    protected void saveVerbose(final String promptPrefix, final File file, final byte[] encoded)
            throws IOException {
        File saveTo = expandFilepath(file);

        if (saveTo.exists()) {
            try {
                boolean bo = true;
                while (saveTo.exists()) {
                    String answer;
                    if (bo) {
                        answer = readPrompt("A file named '" + saveTo.getPath()
                            + "' already exists. Do you want to replace it [yes/no]? ");
                    } else {
                        answer = session.readLine(null, null);
                    }

                    if (answer == null) {
                        throw new IOException("interrupted");
                    }

                    if ("yes".equalsIgnoreCase(answer)) {
                        break;
                    } else if ("no".equalsIgnoreCase(answer)) {
                        String newFn;
                        while (true) {
                            newFn = readPrompt("Enter new path to save to ... ");
                            if (!newFn.trim().isEmpty()) {
                                break;
                            }
                        }

                        saveTo = new File(newFn);
                    } else {
                        readPrompt("Please answer with yes or no. ");
                        bo = false;
                    }
                } // end while
            } catch (IOException ex) {
                saveTo = new File("tmp-" + randomHex(6));
            }
        } // end if(saveTo.exists())

        int retries = 2;
        while(true) {
            try {
                save(saveTo, encoded);
                break;
            } catch (IOException ex) {
                if (retries > 0) {
                    String newFn;
                    while (true) {
                        newFn = readPrompt("Enter new path to save to ... ");
                        if (!newFn.trim().isEmpty()) {
                            break;
                        }
                    }
                    saveTo = new File(newFn);
                } else if (retries == 0) {
                    // save it to tmp file
                    saveTo = new File("tmp-" + randomHex(6));
                } else {
                    throw new IOException("could not save to file");
                }
            }
        }

        String tmpPromptPrefix = promptPrefix;
        if (promptPrefix == null || promptPrefix.isEmpty()) {
            tmpPromptPrefix = "saved to file";
        }

        println(tmpPromptPrefix + " " + saveTo.getPath());
    } // method saveVerbose

    protected void save(final File file, final byte[] encoded) throws IOException {
        File tmpFile = expandFilepath(file);
        File parent = tmpFile.getParentFile();
        if (parent != null) {
            if (parent.exists()) {
                if (!parent.isDirectory()) {
                    throw new IOException("The path " + parent.getPath() + " is not a directory.");
                }
            } else {
                parent.mkdirs();
            }
        }

        FileOutputStream out = new FileOutputStream(tmpFile);
        try {
            out.write(encoded);
        } finally {
            out.close();
        }
    }

    private static String randomHex(final int numOfBytes) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[numOfBytes];
        random.nextBytes(bytes);
        return new BigInteger(1, bytes).toString(16);
    }

    protected static boolean isEnabled(final String enabledS, final boolean defaultEnabled,
            final String optionName) {
        return (enabledS == null) ? defaultEnabled : isEnabled(enabledS, optionName);
    }

    private static boolean isEnabled(final String enabledS, final String optionName) {
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

    protected String readPrompt(final String prompt) throws IOException {
        String tmpPrompt = prompt;
        if (StringUtil.isNotBlank(prompt)) {
            if (!prompt.endsWith(" ")) {
                tmpPrompt += " ";
            }
        }
        return readLine(tmpPrompt, null);
    }

    protected char[] readPasswordIfNotSet(final String password) throws IOException {
        return readPasswordIfNotSet(null, password);
    }

    protected char[] readPasswordIfNotSet(final String prompt, final String password)
            throws IOException {
        if (password != null) {
            return password.toCharArray();
        }

        return readPassword(prompt);
    }

    protected char[] readPassword() throws IOException {
        return readPassword(null);
    }

    protected char[] readPassword(final String prompt) throws IOException {
        String tmpPrompt = (prompt == null) ? "Password:" : prompt.trim();

        if (!tmpPrompt.endsWith(":")) {
            tmpPrompt += ":";
        }

        String passwordUi = System.getProperty("org.xipki.console.passwordui");
        return "gui".equalsIgnoreCase(passwordUi)
                ? SecurePasswordInputPanel.readPassword(tmpPrompt)
                : readLine(tmpPrompt, '*').toCharArray();
    }

    private String readLine(String prompt, Character ch) throws IOException {
        Object oldIgnoreInterrupts = session.get(Session.IGNORE_INTERRUPTS);
        session.put(Session.IGNORE_INTERRUPTS, Boolean.TRUE);
        try {
            String line = session.readLine(prompt, ch);
            if (line == null) {
                throw new IOException("interrupted");
            }
            return line;
        } finally {
            session.put(Session.IGNORE_INTERRUPTS, oldIgnoreInterrupts);
        }
    }

    protected static String expandFilepath(final String path) {
        return IoUtil.expandFilepath(path);
    }

    protected static File expandFilepath(final File file) {
        return IoUtil.expandFilepath(file);
    }

    protected void println(final String message) {
        System.out.println(message);
    }

    protected void print(final String message) {
        System.out.print(message);
    }

    protected static boolean isBlank(final String str) {
        return StringUtil.isBlank(str);
    }

    protected static boolean isNotBlank(final String str) {
        return StringUtil.isNotBlank(str);
    }

    protected static boolean isEmpty(final Collection<?> col) {
        return CollectionUtil.isEmpty(col);
    }

    protected static boolean isNotEmpty(final Collection<?> col) {
        return CollectionUtil.isNonEmpty(col);
    }

    protected static List<String> split(final String str, final String delim) {
        return StringUtil.split(str, delim);
    }

    protected static BigInteger toBigInt(final String str) {
        return toBigInt(str, false);
    }

    protected static BigInteger toBigInt(final String str, boolean defaultHex) {
        String tmpStr = str.trim();

        if (tmpStr.startsWith("0x") || tmpStr.startsWith("0X")) {
            if (tmpStr.length() > 2) {
                return new BigInteger(tmpStr.substring(2), 16);
            } else {
                throw new NumberFormatException("invalid integer '" + tmpStr + "'");
            }
        }
        return new BigInteger(tmpStr, defaultHex ? 16 : 10);
    }

    protected boolean confirm(final String prompt, final int maxTries) throws IOException {
        String tmpPrompt;
        if (prompt == null || prompt.isEmpty()) {
            tmpPrompt = "[yes/no]? ";
        } else {
            if ('?' == prompt.charAt(prompt.length() - 1)) {
                tmpPrompt = prompt.substring(0, prompt.length() - 1);
            } else {
                tmpPrompt = prompt;
            }
            tmpPrompt += " [yes/no]? ";
        }

        String answer = readLine(tmpPrompt, null);
        if (answer == null) {
            throw new IOException("interrupted");
        }

        int tries = 1;

        while (tries < maxTries) {
            if ("yes".equalsIgnoreCase(answer)) {
                return true;
            } else if ("no".equalsIgnoreCase(answer)) {
                return false;
            } else {
                tries++;
            }
            answer = readLine("Please answer with yes or no: ", null);
        }

        return false;
    }

}
