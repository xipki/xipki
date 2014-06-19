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

package org.xipki.security.provider;

import java.security.Security;

/**
 * @author Lijun Liao
 */

public class XiPKIProviderRegister
{
    public void regist()
    {
        if(Security.getProperty(XiPKIProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new XiPKIProvider());
        }
    }

    public void unregist()
    {
        if(Security.getProperty(XiPKIProvider.PROVIDER_NAME) != null)
        {
            Security.removeProvider(XiPKIProvider.PROVIDER_NAME);
        }
    }

    public void setPkcs11Module(String pkcs11Module)
    {
        XiPKIKeyStoreSpi.setDefaultPkcs11Module(pkcs11Module);
    }

    public void setPkcs11Provider(String pkcs11Provider)
    {
        XiPKIKeyStoreSpi.setDefaultPkcs11Provider(pkcs11Provider);
    }

}
