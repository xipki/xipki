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

package org.xipki.security.common;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class CmpUtf8Pairs {
	public static final String KEY_CERT_PROFILE = "cert_profile";
	public static final String KEY_ORIG_CERT_PROFILE = "orig_cert_profile";
	
	private static final char NAME_TERM = '?';
	private static final String NAME_TERM_s = "?";
	private static final char TOKEN_TERM = '%';
	private static final String TOKEN_TERM_s = "%";

	private final Map<String, String> pairs = new HashMap<String, String>();
	
	public CmpUtf8Pairs(String name, String value)
	{	
		putUtf8Pair(name, value);
	}
	
	public CmpUtf8Pairs(String string)
	{
		if(string.length() < 2) return;
		
		// find the position of terminators
		List<Integer> positions = new LinkedList<Integer>();
		//positions.add(0);

		int idx = 1;
		while(idx < string.length())
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
			if(sepIdx == -1 || sepIdx == token.length()-1)
			{
				throw new IllegalArgumentException("Invalid token: " + token); 
			}			
			String name = token.substring(0, sepIdx);
			name = decodeNameOrValue(name);
			String value = token.substring(sepIdx+1);
			value = decodeNameOrValue(value);
			pairs.put(name, value);
			
			beginIndex = endIndex + 1;
		}
	}
	
	private static String encodeNameOrValue(String s)
	{
		if(s.indexOf(TOKEN_TERM_s) != -1)
		{
			s = s.replace(TOKEN_TERM_s, "%25");
		}
		else if(s.indexOf(NAME_TERM_s) != -1)
		{
			s = s.replace(NAME_TERM_s, "%3f");	
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
		
		for(int i=0; i<s.length();)
		{
			char c = s.charAt(i);
			if(c != TOKEN_TERM)
			{
				newS.append(c);
				i++;
			}
			else
			{
				if(i+3 <= s.length())
				{
					String hex = s.substring(i+1, i+3);
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
		if(name == null || name.isEmpty())
			throw new IllegalArgumentException("name is null or empty");
		char c = name.charAt(0);
		if(c >= '0' && c <= '9')
			throw new IllegalArgumentException("name begin with " + c);
		pairs.put(name, value);
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
		boolean isFirst = true;
		for(String name : pairs.keySet())
		{
			if(! isFirst)
			{
				sb.append(TOKEN_TERM);
			}
			isFirst = false;
			sb.append(encodeNameOrValue(name));
			sb.append(NAME_TERM);
			String value = pairs.get(name);
			sb.append(value == null ? "" : encodeNameOrValue(value));
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
		try{
			CmpUtf8Pairs pairs = new CmpUtf8Pairs("key-a", "value-a");
			pairs.putUtf8Pair("key-b", "value-b");
			
			String encoded = pairs.getEncoded();
			CmpUtf8Pairs p2 = new CmpUtf8Pairs(encoded);
			for(String name : p2.getNames())
			{
				System.out.println(name + ": " + p2.getValue(name));
			}
		}catch(Exception e)
		{
			e.printStackTrace();
		}
		
	}
}
