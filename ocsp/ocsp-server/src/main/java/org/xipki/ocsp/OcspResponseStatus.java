/*
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ocsp;

/**
 * @author Lijun Liao
 */

public enum OcspResponseStatus
{
    successfull(0),
    malformedRequest(1),
    internalError(2),
    tryLater(3),
    sigRequired(5),
    unauthorized(6);

    private final int status;
    private OcspResponseStatus(int status)
    {
        this.status = status;
    }

    public static OcspResponseStatus getOCSPResponseStatus(int status)
    {
        for(OcspResponseStatus entry : values())
        {
            if(entry.status == status)
            {
                return entry;
            }
        }

        return null;
    }

    public int getStatus()
    {
        return status;
    }
}
