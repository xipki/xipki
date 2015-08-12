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

package org.xipki.scep4j.serveremulator;

import org.xipki.scep4j.util.ParamUtil;

/**
 * @author Lijun Liao
 */

public class ScepControl
{

    private final boolean sendCACert;
    private final boolean pendingCert;
    private final boolean useInsecureAlg;
    private final boolean sendSignerCert;
    private final String secret;

    public ScepControl(
            final boolean sendCACert,
            final boolean pendingCert,
            final boolean sendSignerCert,
            final boolean useInsecureAlg,
            final String secret)
    {
        ParamUtil.assertNotBlank("secret", secret);
        this.sendCACert = sendCACert;
        this.pendingCert = pendingCert;
        this.sendSignerCert = sendSignerCert;
        this.useInsecureAlg = useInsecureAlg;
        this.secret = secret;
    }

    public boolean isSendCACert()
    {
        return sendCACert;
    }

    public boolean isPendingCert()
    {
        return pendingCert;
    }

    public boolean isUseInsecureAlg()
    {
        return useInsecureAlg;
    }

    public boolean isSendSignerCert()
    {
        return sendSignerCert;
    }

    public String getSecret()
    {
        return secret;
    }

}
