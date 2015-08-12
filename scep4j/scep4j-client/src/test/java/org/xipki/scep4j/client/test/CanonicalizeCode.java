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

package org.xipki.scep4j.client.test;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Lijun Liao
 */

public class CanonicalizeCode
{

    private final static String licenseText =
            "/*\n" +
            " * Copyright (c) 2015 Lijun Liao\n" +
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

    public static void main(
            final String[] args)
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

    private static void canonicalizeDir(
            final File dir)
    throws Exception
    {
        File[] files = dir.listFiles();
        for(File file : files)
        {
            if(file.isDirectory())
            {
                if(file.getName().equals("target") == false && file.getName().equals("tbd") == false)
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

    private static void canonicalizeFile(
            final File file)
    throws Exception
    {
        BufferedReader reader = new BufferedReader(new FileReader(file));

        ByteArrayOutputStream writer = new ByteArrayOutputStream();

        try
        {
            String line;
            boolean skip = true;
            boolean lastLineEmpty = false;
            boolean licenseTextAdded = false;
            while((line = reader.readLine()) != null)
            {
                if(line.trim().startsWith("package ") || line.trim().startsWith("import "))
                {
                    if(licenseTextAdded == false)
                    {
                        writer.write(licenseText.getBytes());
                        licenseTextAdded = true;
                    }
                    skip = false;
                }

                if(skip)
                {
                    continue;
                }

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
                    writer.write(canonicalizedLine.getBytes());
                    writer.write('\n');
                }
            }
        }finally
        {
            writer.close();
            reader.close();
        }

        byte[] oldBytes = read(file);
        byte[] newBytes = writer.toByteArray();
        if(Arrays.equals(oldBytes, newBytes) == false)
        {
            File newFile = new File(file.getPath() + "-new");
            save(file, newBytes);
            newFile.renameTo(file);
            System.out.println(file.getPath());
        }
    }

    /**
     * replace tab by 4 spaces, delete white spaces at the end
     * @param line
     * @return
     */
    private static String canonicalizeLine(
            final String line)
    {
        if(line.trim().startsWith("//"))
        {
            // comments
            String nline = line.replace("\t", "    ");
            return removeTrailingSpaces(nline);
        }

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
        boolean isCommentLine = sb.toString().trim().startsWith("*");

        if(isCommentLine == false && len > 0 && sb.charAt(len-1) == '{')
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

    private static void checkWarningsInDir(
            final File dir)
    throws Exception
    {
        File[] files = dir.listFiles();
        for(File file : files)
        {
            if(file.isDirectory())
            {
                if(file.getName().equals("target") == false && file.getName().equals("tbd") == false)
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

    private static void checkWarningsInFile(
            final File file)
    throws Exception
    {
        BufferedReader reader = new BufferedReader(new FileReader(file));

        boolean authorsLineAvailable = false;
        List<Integer> lineNumbers = new LinkedList<Integer>();

        int lineNumber = 0;
        try
        {
            String lastLine = null;
            String line;
            while((line = reader.readLine()) != null)
            {
                if(authorsLineAvailable == false && line.contains("* @author"))
                {
                    authorsLineAvailable = true;
                }

                lineNumber++;
                int idx = line.indexOf("throws");
                if(idx == -1)
                {
                    lastLine = line;

                    if(line.length() > 128)
                    {
                        lineNumbers.add(lineNumber);
                    }
                    else
                    {
                        // check whether the number of leading spaces is multiple of 4
                        int numLeadingSpaces = 0;
                        char c = 'Z';
                        for(int i = 0; i < line.length(); i++)
                        {
                            if(line.charAt(i) == ' ')
                            {
                                numLeadingSpaces++;
                            }
                            else
                            {
                                c = line.charAt(i);
                                break;
                            }
                        }

                        if(c != '*' && numLeadingSpaces % 4 != 0)
                        {
                            lineNumbers.add(lineNumber);
                        }
                    }
                    continue;
                }

                if(idx > 0 && line.charAt(idx - 1) == '@' || line.charAt(idx - 1) == '"' )
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
                            int idx2 = lastLine.indexOf(trimmedLastLine);
                            if(idx2 == 2 * THROWS_PREFIX.length())
                            {
                                continue;
                            }

                            if(idx2 == 4 * THROWS_PREFIX.length() && trimmedLastLine.startsWith("final "))
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

        if(authorsLineAvailable == false)
        {
            System.out.println("Please check file " + file.getPath() +
                    ": no authors line");
        }

    }

    private static byte[] read(
            final File file)
    throws IOException
    {
        InputStream content = null;
        try
        {
            content = new FileInputStream(file);
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            int readed = 0;
            byte[] buffer = new byte[2048];
            while ((readed = content.read(buffer)) != -1)
            {
                bout.write(buffer, 0, readed);
            }

            return bout.toByteArray();
        } finally
        {
            if (content != null)
            {
                try
                {
                    content.close();
                } catch (IOException e)
                {
                }
            }
        }
    }

    private static String removeTrailingSpaces(
            final String line)
    {
        final int n = line.length();
        int i;
        for(i = n - 1; i >= 0; i--)
        {
            char c = line.charAt(i);
            if(c != ' ')
            {
                break;
            }
        }
        if(i == n - 1)
        {
            return line;
        }
        else
        {
            return line.substring(0, i + 1);
        }
    }

    private static void save(
            final File file,
            final byte[] encoded)
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

}
