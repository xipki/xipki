/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
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
import org.xipki.security.common.LogUtil;

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
            final String message = "Could not finalize the module " + text;
            if(LOG.isWarnEnabled())
            {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
            }
            LOG.debug(message, t);
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
            final String msg = "Could not load the PKCS#11 library " + IaikP11Util.eraseSensitiveInfo(pkcs11Lib);
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(msg), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(msg, e);
            throw new SignerException(msg);
        }

        try
        {
            module.initialize(new DefaultInitializeArgs());
        }
        catch (iaik.pkcs.pkcs11.wrapper.PKCS11Exception e)
        {
            if (e.getErrorCode() != PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED)
            {
                final String message = "PKCS11Exception";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);
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
            final String message = "Unexpected Exception: ";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
            }
            LOG.debug(message, t);
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
                final String message = "error while module.finalize()";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
                }
                LOG.debug(message, t);
            }
        }
    }
}
