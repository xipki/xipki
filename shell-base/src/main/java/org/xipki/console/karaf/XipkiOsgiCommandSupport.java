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

package org.xipki.console.karaf;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import jline.console.ConsoleReader;

import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Lijun Liao
 */

public abstract class XipkiOsgiCommandSupport extends OsgiCommandSupport
{
    private static final Logger LOG = LoggerFactory.getLogger(XipkiOsgiCommandSupport.class);

    protected abstract Object _doExecute()
    throws Exception;

    @Override
    protected Object doExecute()
    throws Exception
    {
        try
        {
            return _doExecute();
        } catch(Exception e)
        {
            LOG.debug("Exception caught while executing command", e);
            throw new Exception(e.getClass().getName() + ": " + e.getMessage());
        }
    }

    protected boolean isTrue(Boolean b)
    {
        return b != null && b.booleanValue();
    }

    protected void saveVerbose(String promptPrefix, File file, byte[] encoded)
    throws IOException
    {
        ConsoleReader reader = (ConsoleReader) session.get(".jline.reader");
        File saveTo = expandFilepath(file);

        boolean randomSaveTo = false;
        if(saveTo.exists())
        {
            try
            {
                boolean b = true;
                while(saveTo.exists())
                {
                    if(b)
                    {
                        out("A file named '" +
                                saveTo.getPath() + "' already exists. Do you want to replace it [yes/no]? ");
                    }

                    String answer = reader.readLine();
                    if(answer == null)
                    {
                        throw new IOException("interrupted");
                    }

                    if("yes".equalsIgnoreCase(answer))
                    {
                        break;
                    }
                    else if("no".equalsIgnoreCase(answer))
                    {
                        out("Enter name of file to save to ... ");
                        String newFn = null;
                        while(true)
                        {
                            newFn = reader.readLine();
                            if(newFn.trim().isEmpty() == false)
                            {
                                break;
                            }
                        }

                        saveTo = new File(newFn);
                    }
                    else
                    {
                        out("Please answer with yes or no. ");
                        b = false;
                    }
                }
            } catch(IOException e)
            {
                saveTo = new File("tmp-" + randomHex(6));
                randomSaveTo = true;
            }
        }

        File parent = file.getParentFile();
        if (parent != null && parent.exists() == false)
        {
            parent.mkdirs();
        }

        try
        {
            save(saveTo, encoded);
        } catch(IOException e)
        {
            if(randomSaveTo == false)
            {
                saveTo = new File("tmp-" + randomHex(6));
                save(saveTo, encoded);
            }
        }

        if(promptPrefix == null || promptPrefix.isEmpty())
        {
            promptPrefix = "Saved to file";
        }

        out(promptPrefix + " " + saveTo.getPath());
    }

    protected void save(File file, byte[] encoded)
    throws IOException
    {
        file = expandFilepath(file);
        File parent = file.getParentFile();
        if (parent != null && parent.exists() == false)
        {
            parent.mkdirs();
        }

        FileOutputStream out = new FileOutputStream(file);
        try
        {
            out.write(encoded);
        } finally
        {
            out.close();
        }
    }

    private static final String randomHex(int n)
    {
        SecureRandom r = new SecureRandom();
        byte[] bytes = new byte[n];
        r.nextBytes(bytes);
        return new BigInteger(1, bytes).toString(16);
    }

    protected static Boolean isEnabled(String enabledS, String optionName)
    {
        if(enabledS == null)
        {
            return null;
        }
        return intern_isEnabled(enabledS, optionName);
    }

    protected static boolean isEnabled(String enabledS, boolean defaultEnabled, String optionName)
    {
        if(enabledS == null)
        {
            return defaultEnabled;
        }

        return intern_isEnabled(enabledS, optionName);
    }

    private static boolean intern_isEnabled(String enabledS, String optionName)
    {
        if("yes".equalsIgnoreCase(enabledS) || "enabled".equalsIgnoreCase(enabledS) || "true".equalsIgnoreCase(enabledS))
        {
            return true;
        }
        else if("no".equalsIgnoreCase(enabledS) || "disabled".equalsIgnoreCase(enabledS) || "false".equalsIgnoreCase(enabledS))
        {
            return false;
        }
        else
        {
            throw new IllegalArgumentException("invalid option " + optionName + ": " + enabledS);
        }
    }

    protected char[] readPasswordIfNotSet(String password)
    {
        if(password != null)
        {
            return password.toCharArray();
        }

        return readPassword("Enter the password");
    }

    protected char[] readPassword()
    {
        return readPassword("Enter the password");
    }

    protected char[] readPassword(String prompt)
    {
        String passwordUi = System.getProperty("org.xipki.console.passwordui");
        if("gui".equalsIgnoreCase(passwordUi))
        {
            return SecurePasswordInputPanel.readPassword(prompt);
        }
        else
        {
            ConsoleReader reader = (ConsoleReader) session.get(".jline.reader");
            out(prompt);
            try
            {
                String pwd = reader.readLine('*');
                return pwd.toCharArray();
            }catch(IOException e)
            {
                return new char[0];
            }
        }
    }

    public static String expandFilepath(String path)
    {
        if (path.startsWith("~" + File.separator))
        {
            return System.getProperty("user.home") + path.substring(1);
        }
        else
        {
            return path;
        }
    }

    public static File expandFilepath(File file)
    {
        String path = file.getPath();
        String expandedPath = expandFilepath(path);
        if(path.equals(expandedPath) == false)
        {
            file = new File(expandedPath);
        }

        return file;
    }

    protected void err(String message)
    {
        System.err.println(message);
    }

    protected void out(String message)
    {
        System.out.println(message);
    }

}
