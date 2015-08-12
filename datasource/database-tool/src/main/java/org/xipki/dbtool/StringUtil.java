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

package org.xipki.dbtool;

/**
 * @author Lijun Liao
 */

class StringUtil
{
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

}
