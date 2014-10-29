/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.common;

import java.util.ArrayList;
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
    public static List<String> split(String str, String delim)
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
        List<String> ret = new ArrayList<>(st.countTokens());

        while(st.hasMoreTokens())
        {
            ret.add(st.nextToken());
        }

        return ret;
    }

    public static Set<String> splitAsSet(String str, String delim)
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
        Set<String> ret = new HashSet<>(st.countTokens());

        while(st.hasMoreTokens())
        {
            ret.add(st.nextToken());
        }

        return ret;
    }
}
