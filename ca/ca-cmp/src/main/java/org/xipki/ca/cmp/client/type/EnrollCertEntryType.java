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

package org.xipki.ca.cmp.client.type;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class EnrollCertEntryType
{
    private final CertificationRequest p10Request;
    private final String profile;

    public EnrollCertEntryType(CertificationRequest p10Request, String profile)
    {
        ParamChecker.assertNotNull("p10Request", p10Request);
        ParamChecker.assertNotEmpty("profile", profile);

        this.p10Request = p10Request;
        this.profile = profile;
    }

    public CertificationRequest getP10Request()
    {
        return p10Request;
    }

    public String getProfile()
    {
        return profile;
    }

}
