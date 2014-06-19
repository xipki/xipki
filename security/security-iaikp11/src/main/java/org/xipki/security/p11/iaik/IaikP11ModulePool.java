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

package org.xipki.security.p11.iaik;

import iaik.pkcs.pkcs11.DefaultInitializeArgs;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public class IaikP11ModulePool
{
    private static final Logger LOG = LoggerFactory.getLogger(IaikP11ModulePool.class);

    private final Map<String, IaikExtendedModule> modules = new HashMap<>();

    private static IaikP11ModulePool INSTANCE = new IaikP11ModulePool();

    public static IaikP11ModulePool getInstance()
    {
        return INSTANCE;
    }

    public synchronized void removeModule(String pkcs11Lib)
    {
        IaikExtendedModule module = modules.remove(pkcs11Lib);
        if(module == null)
        {
            return;
        }

        try
        {
            LOG.info("Removed module {}", pkcs11Lib);
            module.getModule().finalize();
            LOG.info("Finalized module {}", pkcs11Lib);
        }catch(Throwable t)
        {
            String text = IaikP11Util.eraseSensitiveInfo(pkcs11Lib);
            LOG.warn("Could not finalize the module {}", text);
            LOG.debug("Could not finalize the module " + text, t);
        }
    }

    public synchronized IaikExtendedModule getModule(String pkcs11Lib)
    throws SignerException
    {
        IaikExtendedModule extModule = modules.get(pkcs11Lib);
        if(extModule != null)
        {
            return extModule;
        }

        Module module;

        try
        {
            module = Module.getInstance(pkcs11Lib);
        }catch(IOException e)
        {
            LOG.error("IOException: {}", e.getMessage());
            LOG.debug("IOException: " + e.getMessage(), e);
            throw new SignerException("Could not load the PKCS#11 library " +
                    IaikP11Util.eraseSensitiveInfo(pkcs11Lib));
        }

        try
        {
            module.initialize(new DefaultInitializeArgs());
        }
        catch (iaik.pkcs.pkcs11.wrapper.PKCS11Exception e)
        {
            if (e.getErrorCode() != PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED)
            {
                LOG.error("PKCS11Exception: {}", e.getMessage());
                LOG.debug("PKCS11Exception: " + e.getMessage(), e);
                close(module);
                throw new SignerException(e.getMessage());
            }
            else
            {
                LOG.info("PKCS#11 module already initialized");
                if(LOG.isInfoEnabled())
                {
                    try
                    {
                        LOG.info("pkcs11.getInfo():\n{}", module.getInfo());
                    } catch (TokenException e2)
                    {
                        LOG.debug("module.getInfo()", e2);
                    }
                }
            }
        }
        catch (Throwable t)
        {
            LOG.error("Unexpected Exception. {}: {}", t.getClass().getName(), t.getMessage());
            LOG.debug("Unexpected Exception: ", t.getMessage(), t);
            close(module);
            throw new SignerException(t.getMessage());
        }

        extModule = new IaikExtendedModule(module);
        modules.put(pkcs11Lib, extModule);

        return extModule;
    }

    @Override
    protected void finalize()
    throws Throwable
    {
        super.finalize();
        shutdown();
    }

    public synchronized void shutdown()
    {
        for(String pk11Lib : modules.keySet())
        {
            modules.get(pk11Lib).close();
        }
        modules.clear();
    }

    private static void close(Module module)
    {
        if (module != null)
        {
            LOG.info( "close", "close pkcs11 module: {}", module );
            try
            {
                module.finalize(null);
            }
            catch (Throwable t)
            {
                LOG.error("error while module.finalize(). {}: {}", t.getClass().getName(), t.getMessage());
                LOG.debug("error while module.finalize(): " + t.getMessage(), t);
            }
        }
    }
}
