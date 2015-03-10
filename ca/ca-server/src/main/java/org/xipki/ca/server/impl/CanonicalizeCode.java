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

package org.xipki.ca.server.impl;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.xipki.common.util.IoUtil;

/**
 * @author Lijun Liao
 */

public class CanonicalizeCode
{

    private final static String licenseText =
            "/*\n" +
            " *\n" +
            " * This file is part of the XiPKI project.\n" +
            " * Copyright (c) 2014 - 2015 Lijun Liao\n" +
            " * Author: Lijun Liao\n" +
            " *\n" +
            " * This program is free software; you can redistribute it and/or modify\n" +
            " * it under the terms of the GNU Affero General Public License version 3\n" +
            " * as published by the Free Software Foundation with the addition of the\n" +
            " * following permission added to Section 15 as permitted in Section 7(a):\n" +
            " * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY\n" +
            " * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT\n" +
            " * OF THIRD PARTY RIGHTS.\n" +
            " *\n" +
            " * This program is distributed in the hope that it will be useful,\n" +
            " * but WITHOUT ANY WARRANTY; without even the implied warranty of\n" +
            " * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the\n" +
            " * GNU Affero General Public License for more details.\n" +
            " *\n" +
            " * You should have received a copy of the GNU Affero General Public License\n" +
            " * along with this program.  If not, see <http://www.gnu.org/licenses/>.\n" +
            " *\n" +
            " * The interactive user interfaces in modified source and object code versions\n" +
            " * of this program must display Appropriate Legal Notices, as required under\n" +
            " * Section 5 of the GNU Affero General Public License.\n" +
            " *\n" +
            " * You can be released from the requirements of the license by purchasing\n" +
            " * a commercial license. Buying such a license is mandatory as soon as you\n" +
            " * develop commercial activities involving the XiPKI software without\n" +
            " * disclosing the source code of your own applications.\n" +
            " *\n" +
            " * For more information, please contact Lijun Liao at this\n" +
            " * address: lijun.liao@gmail.com\n" +
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

    private static void canonicalizeFile(File file)
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
                        writer.write(canonicalizedLine.getBytes());
                        writer.write('\n');
                    }
                }
            }
        }finally
        {
            writer.close();
            reader.close();
        }

        byte[] oldBytes = IoUtil.read(file);
        byte[] newBytes = writer.toByteArray();
        if(Arrays.equals(oldBytes, newBytes) == false)
        {
            File newFile = new File(file.getPath() + "-new");
            IoUtil.save(file, newBytes);
            newFile.renameTo(file);
            System.out.println(file.getPath());
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

    private static void checkWarningsInDir(File dir)
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

    private static void checkWarningsInFile(File file)
    throws Exception
    {
        BufferedReader reader = new BufferedReader(new FileReader(file));

        boolean authorsLineAvailable = false;
        List<Integer> lineNumbers = new LinkedList<>();

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

        if(authorsLineAvailable == false)
        {
            System.out.println("Please check file " + file.getPath() +
                    ": no authors line");
        }

    }

}
