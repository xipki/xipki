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

package org.xipki.security.p11.nss;

import java.security.Security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Lijun Liao
 */

public class XipkiNSSProviderRegister
{
    private static Logger LOG = LoggerFactory.getLogger(XipkiNSSProviderRegister.class);
    public void regist()
    {
        if(Security.getProvider(XipkiNSSProvider.PROVIDER_NAME) == null)
        {
            try
            {
                XipkiNSSProvider provider = new XipkiNSSProvider();
                Security.addProvider(provider);
            }catch(Throwable t)
            {
                LOG.error("Could not add provider {}: {}", XipkiNSSProvider.PROVIDER_NAME, t.getMessage());
                LOG.debug("Could not add provider " + XipkiNSSProvider.PROVIDER_NAME, t);
            }
        }
    }

    public void unregist()
    {
        if(Security.getProperty(XipkiNSSProvider.PROVIDER_NAME) != null)
        {
            Security.removeProvider(XipkiNSSProvider.PROVIDER_NAME);
        }
    }

}
