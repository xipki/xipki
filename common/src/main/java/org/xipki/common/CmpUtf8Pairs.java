/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.common;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author Lijun Liao
 */

public class CmpUtf8Pairs
{
    public static final String KEY_CERT_PROFILE = "cert_profile";
    public static final String KEY_USER = "user";

    private static final char NAME_TERM = '?';
    private static final char TOKEN_TERM = '%';

    private final Map<String, String> pairs = new HashMap<>();

    public CmpUtf8Pairs(String name, String value)
    {
        putUtf8Pair(name, value);
    }

    public CmpUtf8Pairs()
    {
    }

    public CmpUtf8Pairs(String string)
    {
        if(string == null || string.length() < 2)
        {
            return;
        }

        // remove the ending '%'-symbols
        while(string.charAt(string.length() - 1) == TOKEN_TERM)
        {
            string = string.substring(0, string.length() - 1);
        }

        // find the position of terminators
        List<Integer> positions = new LinkedList<>();

        int idx = 1;
        int n = string.length();
        while(idx < n)
        {
            char c = string.charAt(idx++);
            if(c == TOKEN_TERM)
            {
                char b = string.charAt(idx);
                if(b < '0' || b > '9')
                {
                    positions.add(idx-1);
                }
            }
        }
        positions.add(string.length());

        // parse the token
        int beginIndex = 0;
        for(int i = 0; i < positions.size(); i++)
        {
            int endIndex = positions.get(i);
            String token = string.substring(beginIndex, endIndex);

            int sepIdx = token.indexOf(NAME_TERM);
            if(sepIdx == -1 || sepIdx == token.length() - 1)
            {
                throw new IllegalArgumentException("Invalid token: " + token);
            }
            String name = token.substring(0, sepIdx);
            name = decodeNameOrValue(name);
            String value = token.substring(sepIdx + 1);
            value = decodeNameOrValue(value);
            pairs.put(name, value);

            beginIndex = endIndex + 1;
        }
    }

    private static String encodeNameOrValue(String s)
    {
        if(s.indexOf("%") != -1)
        {
            s = s.replaceAll("%", "%25");
        }

        if(s.indexOf("?") != -1)
        {
            s = s.replaceAll("\\?", "%3f");
        }

        return s;
    }

    private static String decodeNameOrValue(String s)
    {
        int idx = s.indexOf(TOKEN_TERM);
        if(idx == -1)
        {
            return s;
        }

        StringBuilder newS = new StringBuilder();

        for(int i = 0; i < s.length();)
        {
            char c = s.charAt(i);
            if(c != TOKEN_TERM)
            {
                newS.append(c);
                i++;
            }
            else
            {
                if(i + 3 <= s.length())
                {
                    String hex = s.substring(i + 1, i + 3);
                    c = (char) Byte.parseByte(hex, 16);
                    newS.append(c);
                    i += 3;
                }
                else
                {
                    newS.append(s.substring(i));
                    break;
                }
            }
        }

        return newS.toString();
    }

    public void putUtf8Pair(String name, String value)
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotNull("value", value);

        char c = name.charAt(0);
        if(c >= '0' && c <= '9')
            throw new IllegalArgumentException("name begin with " + c);
        pairs.put(name, value);
    }

    public void removeUtf8Pair(String name)
    {
        pairs.remove(name);
    }

    public String getValue(String name)
    {
        return pairs.get(name);
    }

    public Set<String> getNames()
    {
        return Collections.unmodifiableSet(pairs.keySet());
    }

    public String getEncoded()
    {
        StringBuilder sb = new StringBuilder();
        List<String> names = new LinkedList<>();
        for(String name : pairs.keySet())
        {
            String value = pairs.get(name);
            if(value.length() <= 100)
            {
                names.add(name);
            }
        }
        Collections.sort(names);

        for(String name : pairs.keySet())
        {
            if(names.contains(name) == false)
            {
                names.add(name);
            }
        }

        for(String name : names)
        {
            String value = pairs.get(name);
            sb.append(encodeNameOrValue(name));
            sb.append(NAME_TERM);
            sb.append(value == null ? "" : encodeNameOrValue(value));
            sb.append(TOKEN_TERM);
        }

        return sb.toString();
    }

    @Override
    public String toString()
    {
        return getEncoded();
    }

    public static void main(String[] args)
    {
        try
        {
            CmpUtf8Pairs pairs = new CmpUtf8Pairs("key-a", "value-a");
            pairs.putUtf8Pair("key-b", "value-b");

            String encoded = pairs.getEncoded();
            System.out.println(encoded);
            pairs = new CmpUtf8Pairs(encoded);
            for(String name : pairs.getNames())
            {
                System.out.println(name + ": " + pairs.getValue(name));
            }

            System.out.println("--------------");
            pairs = new CmpUtf8Pairs("key-a?value-a");
            System.out.println(pairs.getEncoded());
            for(String name : pairs.getNames())
            {
                System.out.println(name + ": " + pairs.getValue(name));
            }

            System.out.println("--------------");
            pairs = new CmpUtf8Pairs("key-a?value-a%");
            System.out.println(pairs.getEncoded());
            for(String name : pairs.getNames())
            {
                System.out.println(name + ": " + pairs.getValue(name));
            }

            System.out.println("--------------");
            pairs = new CmpUtf8Pairs("key-a?value-a%3f%");
            System.out.println(pairs.getEncoded());
            for(String name : pairs.getNames())
            {
                System.out.println(name + ": " + pairs.getValue(name));
            }

            System.out.println("--------------");
            pairs = new CmpUtf8Pairs("key-a?value-a%3f%3f%25%");
            System.out.println(pairs.getEncoded());
            for(String name : pairs.getNames())
            {
                System.out.println(name + ": " + pairs.getValue(name));
            }

        }catch(Exception e)
        {
            e.printStackTrace();
        }
    }

}
