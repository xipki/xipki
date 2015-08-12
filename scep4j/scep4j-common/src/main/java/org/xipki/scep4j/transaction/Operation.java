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

package org.xipki.scep4j.transaction;

/**
 * @author Lijun Liao
 */

public enum Operation
{
    GetCACaps("GetCACaps"),
    PKIOperation("PKIOperation"),
    GetCACert("GetCACert"),
    GetNextCACert("GetNextCACert");

    private final String code;

    private Operation(
            final String code)
    {
        this.code = code;
    }

    public String getCode()
    {
        return code;
    }

    public static Operation valueForCode(
            final String code)
    {
        for(Operation m : values())
        {
            if(code.equalsIgnoreCase(m.code))
            {
                return m;
            }
        }
        return null;
    }

}
