/*
 * Copyright (c) 2015 Lijun Liao
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

package org.xipki.common.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * @author Lijun Liao
 */

public class StringUtil
{
    public static List<String> split(
            final String str,
            final String delim)
    {
        if(str == null)
        {
            return null;
        }

        if(str.isEmpty())
        {
            return Collections.emptyList();
        }

        StringTokenizer st = new StringTokenizer(str, delim);
        List<String> ret = new ArrayList<String>(st.countTokens());

        while(st.hasMoreTokens())
        {
            ret.add(st.nextToken());
        }

        return ret;
    }

    public static boolean isBlank(
            final String s)
    {
        return s == null || s.isEmpty();
    }

    public static boolean isNotBlank(
            final String s)
    {
        return s != null && s.isEmpty() == false;
    }

    public static Set<String> splitAsSet(
            final String str,
            final String delim)
    {
        if(str == null)
        {
            return null;
        }

        if(str.isEmpty())
        {
            return Collections.emptySet();
        }

        StringTokenizer st = new StringTokenizer(str, delim);
        Set<String> ret = new HashSet<String>(st.countTokens());

        while(st.hasMoreTokens())
        {
            ret.add(st.nextToken());
        }

        return ret;
    }

    public static String collectionAsString(
            final Collection<String> set,
            final String delim)
    {
        if(set == null)
        {
            return null;
        }

        StringBuilder sb = new StringBuilder();
        for(String m : set)
        {
            sb.append(m).append(delim);
        }
        int n = sb.length();
        if(n > 0)
        {
            sb.delete(n - delim.length(), n);
        }
        return sb.toString();
    }

    public static boolean startsWithIgnoreCase(
            final String s,
            final String prefix)
    {
        if(s.length() < prefix.length())
        {
            return false;
        }

        return prefix.equalsIgnoreCase(s.substring(0, prefix.length()));
    }

    public static boolean isNumber(
            final String s)
    {
        return isNumber(s, 10);
    }

    public static boolean isNumber(
            final String s,
            final int radix)
    {
        try
        {
            Integer.parseInt(s, radix);
            return true;
        }catch(NumberFormatException e)
        {
            return false;
        }
    }
}
