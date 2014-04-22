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

package org.xipki.ca.server.mgmt;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.Arrays;

import org.xipki.security.common.IoCertUtil;

public class AddLicense
{

    private final static String licenseText =
     "/*\n" +
     " * Copyright 2014 xipki.org\n" +
     " *\n" +
     " * Licensed under the Apache License, Version 2.0 (the \"License\");\n" +
     " * you may not use this file except in compliance with the License.\n" +
     " * You may obtain a copy of the License at\n" +
     " *\n" +
     " *         http://www.apache.org/licenses/LICENSE-2.0\n" +
     " *\n" +
     " * Unless required by applicable law or agreed to in writing, software\n" +
     " * distributed under the License is distributed on an \"AS IS\" BASIS,\n" +
     " * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n" +
     " * See the License for the specific language governing permissions and\n" +
     " * limitations under the License\n" +
     " *\n" +
     " */\n\n";

    public static void main(String[] args)
    {
        try
        {
            String dirName = args[0];

            File dir = new File(dirName);
            addLicenseToDir(dir);
        }catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    private static void addLicenseToDir(File dir) throws Exception
    {
        File[] files = dir.listFiles();
        for(File file : files)
        {
            if(file.isDirectory())
            {
                if(file.getName().equals("target") == false)
                {
                    addLicenseToDir(file);
                }
            }
            else if(file.isFile() && file.getName().endsWith(".java"))
            {
                addLicenseToFile(file);
            }
        }
    }

    private static void addLicenseToFile(File file) throws Exception
    {
        BufferedReader reader = new BufferedReader(new FileReader(file));

        File newFile = new File(file.getPath() + "-new");
        BufferedWriter writer = new BufferedWriter(new FileWriter(newFile));

        try
        {
            String line;
            boolean skip = true;
            boolean lastLineEmpty = false;
            while((line = reader.readLine()) != null)
            {
                if(line.trim().startsWith("package "))
                {
                    writer.write(licenseText);
                    skip = false;
                }

                if(!skip)
                {
                    String canonicalizedLine = canonicalizeLine(line);
                    boolean addThisLine = true;
                    if(canonicalizedLine.isEmpty())
                    {
                        if(lastLineEmpty == false)
                        {
                            lastLineEmpty = true;
                        }
                        else
                        {
                            addThisLine = false;
                        }
                    }
                    else
                    {
                        lastLineEmpty = false;
                    }

                    if(addThisLine)
                    {
                        writer.write(canonicalizedLine);
                        writer.write('\n');
                    }
                }
            }
        }finally
        {
            writer.close();
            reader.close();
        }

        byte[] oldBytes = IoCertUtil.read(file);
        byte[] newBytes = IoCertUtil.read(newFile);
        if(Arrays.equals(oldBytes, newBytes) == false)
        {
            System.out.println(file.getPath());
            newFile.renameTo(file);
        }
        else
        {
            newFile.delete();
        }

    }

    /**
     * replace tab by 4 spaces, delete white spaces at the end
     * @param line
     * @return
     */
    private static String canonicalizeLine(String line)
    {
        StringBuilder sb = new StringBuilder();
        int len = line.length();

        int lastNonSpaceCharIndex = 0;
        int index = 0;
        for(int i = 0; i < len; i++)
        {
            char c = line.charAt(i);
            if(c == '\t')
            {
                sb.append("    ");
                index += 4;
            }
            else if(c == ' ')
            {
                sb.append(c);
                index++;
            }
            else
            {
                sb.append(c);
                index++;
                lastNonSpaceCharIndex = index;
            }
        }

        int numSpacesAtEnd = sb.length() - lastNonSpaceCharIndex;
        if(numSpacesAtEnd > 0)
        {
            sb.delete(lastNonSpaceCharIndex, sb.length());
        }

        boolean addNewLine = false;

        len = sb.length();
        if(len > 0 && sb.charAt(len-1) == '{')
        {
            for(int i = 0; i < len - 1; i++)
            {
                if(sb.charAt(i) != ' ')
                {
                    addNewLine = true;
                    break;
                }
            }
        }

        if(addNewLine == false)
        {
            return sb.toString();
        }

        sb.deleteCharAt(sb.length() - 1);
        while(sb.length() > 0 && sb.charAt(sb.length() - 1) == ' ')
        {
            sb.deleteCharAt(sb.length() - 1);
        }

        sb.append('\n');

        len = sb.length();
        for(int i = 0; i < len; i++)
        {
            if(sb.charAt(i) == ' ')
            {
                sb.append(' ');
            }
            else
            {
                break;
            }
        }
        sb.append('{');

        return sb.toString();
    }

}
