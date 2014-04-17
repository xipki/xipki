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

package org.xipki.ca.cmp.client.type;

import org.xipki.ca.common.PKIStatusInfo;
import org.xipki.security.common.ParamChecker;


public class ErrorResultEntryType extends ResultEntryType
{
    private final PKIStatusInfo statusInfo;

    public ErrorResultEntryType(String id, PKIStatusInfo statusInfo)
    {
        super(id);
        ParamChecker.assertNotNull("statusInfo", statusInfo);
        this.statusInfo = statusInfo;
    }

    public ErrorResultEntryType(String id, int status, int pkiFailureInfo, String statusMessage)
    {
        super(id);
        this.statusInfo = new PKIStatusInfo(status, pkiFailureInfo, statusMessage);
    }

    public ErrorResultEntryType(String id, int status)
    {
        super(id);
        this.statusInfo = new PKIStatusInfo(status);
    }

    public PKIStatusInfo getStatusInfo() {
        return statusInfo;
    }
}
