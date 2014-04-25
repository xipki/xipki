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

package org.xipki.security.common;

import java.util.Collection;

public class ParamChecker
{

    public static void assertNotNull(String parameterName, Object parameter)
    {
        if(parameter == null)
        {
            throw new IllegalArgumentException(parameterName + " could not be null");
        }
    }

    public static void assertNotEmpty(String parameterName, String parameter)
    {
        if(parameter == null)
        {
            throw new IllegalArgumentException(parameterName + " could not be null");
        }

        if(parameter.isEmpty())
        {
            throw new IllegalArgumentException(parameterName + " could not be empty");
        }
    }

    public static void assertNotEmpty(String parameterName, Collection<?> parameter)
    {
        if(parameter == null)
        {
            throw new IllegalArgumentException(parameterName + " could not be null");
        }

        if(parameter.isEmpty())
        {
            throw new IllegalArgumentException(parameterName + " could not be empty");
        }
    }

}
