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

package org.xipki.remotep11.server;

import java.security.Security;
import java.util.HashSet;
import java.util.Set;
import java.util.StringTokenizer;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.api.P11CryptService;
import org.xipki.security.api.P11CryptServiceFactory;
import org.xipki.security.api.SignerException;

public class LocalP11CryptService
{
    private static final Logger LOG = LoggerFactory.getLogger(LocalP11CryptService.class);

    public static final int version = 1;

    private String pkcs11Provider;
    private String pkcs11Module;
    private String pkcs11Password;
    private P11CryptService p11CryptService;
    private Set<Integer> pkcs11IncludeSlots;
    private Set<Integer> pkcs11ExcludeSlots;

    public LocalP11CryptService()
    {
    }

    public void setPkcs11Provider(String pkcs11Provider)
    {
        if(pkcs11Provider != null && pkcs11Provider.equals(this.pkcs11Provider) == false)
        {
            p11CryptService = null;
        }

        this.pkcs11Provider = pkcs11Provider;
    }

    public void setPkcs11Module(String pkcs11Module)
    {
        if(pkcs11Module != null && pkcs11Module.equals(this.pkcs11Module) == false)
        {
            p11CryptService = null;
        }
        this.pkcs11Module = pkcs11Module;
    }

    public void setPkcs11Password(String pkcs11Password)
    {
        this.pkcs11Password = pkcs11Password;
    }

    private boolean initialized = false;
    public void init()
    throws Exception
    {
        if(initialized)
        {
            return;
        }

        if(Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        try
        {
            if(pkcs11Module == null)
            {
                throw new IllegalStateException("pkcs11Module is not configured");
            }

            char[] password = (pkcs11Password == null || pkcs11Password.isEmpty()) ?
                    "dummy".toCharArray() : pkcs11Password.toCharArray();

            Object p11Provider;
            try
            {
                Class<?> clazz = Class.forName(pkcs11Provider);
                p11Provider = clazz.newInstance();
            }catch(Exception e)
            {
                throw new SignerException(e.getMessage(), e);
            }

            if(p11Provider instanceof P11CryptServiceFactory)
            {
                P11CryptServiceFactory p11CryptServiceFact = (P11CryptServiceFactory) p11Provider;
                p11CryptService = p11CryptServiceFact.createP11CryptService(pkcs11Module, password,
                        pkcs11IncludeSlots, pkcs11ExcludeSlots);
            }
            else
            {
                throw new SignerException(pkcs11Module + " is not instanceof " + P11CryptServiceFactory.class.getName());
            }

            initialized = true;
        }catch(Exception e)
        {
            LOG.error("Exception thrown. {}: {}", e.getClass().getName(), e.getMessage());
            LOG.debug("Exception thrown", e);
            throw e;
        }
    }

    public P11CryptService getP11CryptService()
    {
        return p11CryptService;
    }

    public int getVersion()
    {
        return version;
    }

    public void setPkcs11IncludeSlots(String indexes)
    {
        if(indexes == null || indexes.trim().isEmpty())
        {
            this.pkcs11IncludeSlots = null;
        }

        StringTokenizer st = new StringTokenizer(indexes.trim(), ", ");
        this.pkcs11IncludeSlots = new HashSet<Integer>();
        while(st.hasMoreTokens())
        {
            this.pkcs11IncludeSlots.add(Integer.parseInt(st.nextToken()));
        }
    }
    
    public void setPkcs11ExcludeSlots(String indexes)
    {
        if(indexes == null || indexes.trim().isEmpty())
        {
            this.pkcs11ExcludeSlots = null;
        }

        StringTokenizer st = new StringTokenizer(indexes.trim(), ", ");
        this.pkcs11ExcludeSlots = new HashSet<Integer>();
        while(st.hasMoreTokens())
        {
            this.pkcs11ExcludeSlots.add(Integer.parseInt(st.nextToken()));
        }    	
    }


}
