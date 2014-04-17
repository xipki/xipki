/*
 * Copyright 2014 xipki.org
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

package org.xipki.security;

import java.io.Console;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class PBETool {

    public static void main(String[] args)
    {
        if(args == null || args.length < 1 || args[0] == null)
        {
            printUsageAndExit("no command is specified");
        }

        String cmd = args[0];

        if("help".equals(cmd))
        {
            printUsageAndExit(null);
        }

        Map<String, String> _params = parseParameters(args, 1);

        if(Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        try {
            if("enc".equalsIgnoreCase(cmd))
            {
                char[] masterPassword = getPassword("Please enter the master password");
                char[] password = getPassword("Please enter the password to be encrypted");

                String passwordHint = PBEPasswordResolver.encryptPassword(masterPassword, password);
                System.out.println(passwordHint);
            }
            else if("dec".equalsIgnoreCase(cmd))
            {
                String passwordHint = _params.get("-c");
                if(passwordHint == null)
                {
                    printUsageAndExit("no encrypted password is specified");
                }

                char[] masterPassword = getPassword("Please enter the master password");
                char[] password = PBEPasswordResolver.resolvePassword(masterPassword, passwordHint);
                System.out.println(password);
            }
             else
            {
                 String msg = "unknown command: " + cmd;
                 printUsageAndExit(msg);
            }
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(1);
        }
    }

    private static char[] getPassword(String prompt)
    {
        Console console = System.console();
        if(console != null)
        {
            return console.readPassword(prompt);
        }
        else
        {
            JPanel panel = new JPanel();
            JLabel label = new JLabel(prompt);
            JPasswordField pass = new JPasswordField(10);
            panel.add(label);
            panel.add(pass);
            String[] options = new String[]{"OK"};
            int option = JOptionPane.showOptionDialog(null, panel, "Password required",
                                     JOptionPane.NO_OPTION, JOptionPane.PLAIN_MESSAGE,
                                     null, options, options[0]);
            if(option == 0) // pressing OK button
            {
                return pass.getPassword();
            }
            else
            {
                return null;
            }
        }
    }

    private static void printUsageAndExit(String prefix)
    {
         StringBuilder sb = new StringBuilder();
         if(prefix != null)
         {
             sb.append(prefix).append("\n");
         }
         sb.append("Usage: \n");
         String cmd = "  PBETool <command> [options]";
         sb.append(cmd);
         sb.append("\n\n");

         sb.append("  commands:\n");
         sb.append("      help                 print this help message\n");
         sb.append("      enc                  encrypt data\n");
         sb.append("      dec                  decrypt data\n");
         sb.append("\n");
         sb.append("  option for dec\n");
         sb.append("      -c arg               encrypted password\n");

         System.exit(0);
    }

    private static Map<String, String> parseParameters(String[] params, int startIndex)
    {
        Map<String, String> ret = new HashMap<String, String>();

        for (int i = startIndex; i < params.length;i++) {
            String arg = params[i];

            if(i+1 >= params.length)
            {
                printUsageAndExit("invalid parameters");
            }

            String argValue = params[i+1];

            if(arg.startsWith("-"))
            {
                ret.put(arg, argValue);
            }

            i++;
        }

        return ret;
    }
}
