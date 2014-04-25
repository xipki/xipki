/*
 * Copyright (c) 2014 xipki.org
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
import java.util.LinkedList;
import java.util.List;

import org.xipki.security.common.IoCertUtil;

public class CanonicalizeCode
{

    private final static String licenseText =
     "/*\n" +
     " * Copyright (c) 2014 xipki.org\n" +
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

    private final static String THROWS_PREFIX = "    ";

    public static void main(String[] args)
    {
        try
        {
            String dirName = args[0];

            File dir = new File(dirName);
            canonicalizeDir(dir);

            checkWarningsInDir(dir);
        }catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    private static void canonicalizeDir(File dir)
    throws Exception
    {
        File[] files = dir.listFiles();
        for(File file : files)
        {
            if(file.isDirectory())
            {
                if(file.getName().equals("target") == false)
                {
                    canonicalizeDir(file);
                }
            }
            else if(file.isFile() && file.getName().endsWith(".java"))
            {
                canonicalizeFile(file);
            }
        }
    }

    private static void canonicalizeFile(File file)
    throws Exception
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

                if(skip == false)
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

    private static void checkWarningsInDir(File dir)
    throws Exception
    {
        File[] files = dir.listFiles();
        for(File file : files)
        {
            if(file.isDirectory())
            {
                if(file.getName().equals("target") == false)
                {
                    checkWarningsInDir(file);
                }
            }
            else if(file.isFile() && file.getName().endsWith(".java"))
            {
                checkWarningsInFile(file);
            }
        }
    }

    private static void checkWarningsInFile(File file)
    throws Exception
    {
        BufferedReader reader = new BufferedReader(new FileReader(file));

        List<Integer> lineNumbers = new LinkedList<Integer>();

        int lineNumber = 0;
        try
        {
            String lastLine = null;
            String line;
            while((line = reader.readLine()) != null)
            {
                lineNumber++;
                int idx = line.indexOf("throws");
                if(idx == -1)
                {
                    lastLine = line;
                    continue;
                }

                if(idx > 0 && line.charAt(idx-1) == '@' || line.charAt(idx-1) == '"' )
                {
                    lastLine = line;
                    continue;
                }

                String prefix = line.substring(0, idx);

                if(prefix.equals(THROWS_PREFIX) == false)
                {
                    // consider inner-class
                    if(prefix.equals(THROWS_PREFIX + THROWS_PREFIX))
                    {
                        if(lastLine != null)
                        {
                            String trimmedLastLine = lastLine.trim();
                            if(lastLine.indexOf(trimmedLastLine) == 2 * THROWS_PREFIX.length())
                            {
                                continue;
                            }
                        }
                    }
                    lineNumbers.add(lineNumber);
                }

                lastLine = line;
            }
        }finally
        {
            reader.close();
        }

        if(lineNumbers.isEmpty() == false)
        {
            System.out.println("Please check file " + file.getPath() +
                ": lines " + Arrays.toString(lineNumbers.toArray(new Integer[0])));
        }
    }

}
