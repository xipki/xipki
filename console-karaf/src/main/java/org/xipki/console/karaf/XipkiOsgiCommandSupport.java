/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.console.karaf;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import jline.console.ConsoleReader;

import org.apache.karaf.shell.console.OsgiCommandSupport;

/**
 * @author Lijun Liao
 */

public abstract class XipkiOsgiCommandSupport extends OsgiCommandSupport
{
    protected boolean isTrue(Boolean b)
    {
        return b != null && b.booleanValue();
    }

    protected void saveVerbose(String promptPrefix, File file, byte[] encoded)
    throws IOException
    {
        ConsoleReader reader = (ConsoleReader) session.get(".jline.reader");

        File saveTo = file;
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
                        System.out.print("A file named '" +
                                saveTo.getPath() + "' already exists.  Do you want to replace it [yes/no]? ");
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
                        System.out.print("Enter name of file to save to ... ");
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
                        System.out.print("Please answer with yes or no. ");
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

        System.out.println(promptPrefix + " " + saveTo.getPath());
    }

    protected void save(File file, byte[] encoded)
    throws IOException
    {
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
            System.out.println(prompt);
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

}
