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

public enum FailInfo
{
    /**
     * Unrecognized or unsupported algorithm identifier
     */
    badAlg (0),

    /**
     * integrity check failed
     */
    badMessageCheck (1),

    /**
     * transaction not permitted or supported
     */
    badRequest (2),

    /**
     * The signingTime attribute from the CMS, authenticatedAttributes was not sufficiently
     * close to the system time
     */
    badTime (3),

    /**
     * No certificate could be identified matching the provided criteria
     */
    badCertId (4);

    private final int code;

    private FailInfo(int code)
    {
        this.code = code;
    }

    public int getCode()
    {
        return code;
    }

    public static FailInfo valueForCode(
            final int code)
    {
        for(FailInfo m : values())
        {
            if(m.code == code)
            {
                return m;
            }
        }
        return null;
    }

}
