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

package org.xipki.ca.api.profile;

import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CertificatePolicyQualifier
{
    private final String cpsUri;
    private final String userNotice;

    private CertificatePolicyQualifier(String cpsUri, String userNotice)
    {
        this.cpsUri = cpsUri;
        this.userNotice = userNotice;
    }

    public static CertificatePolicyQualifier getInstanceForUserNotice(String userNotice)
    {
        ParamChecker.assertNotEmpty("userNotice", userNotice);
        return new CertificatePolicyQualifier(null, userNotice);
    }

    public static CertificatePolicyQualifier getInstanceForCpsUri(String cpsUri)
    {
        ParamChecker.assertNotEmpty("cpsUri", cpsUri);
        return new CertificatePolicyQualifier(cpsUri, null);
    }

    public String getCpsUri()
    {
        return cpsUri;
    }

    public String getUserNotice()
    {
        return userNotice;
    }

}
