/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Lijun Liao
 */

public class SshdBcBugfix
{
    private static final Logger LOG = LoggerFactory.getLogger(SshdBcBugfix.class);

    private final static String classname_SecurityUtils = "org.apache.sshd.common.util.SecurityUtils";

    public SshdBcBugfix()
    {
        Class<?> clazz = null;
        try
        {
            clazz = Class.forName(classname_SecurityUtils);
        }catch(ClassNotFoundException e)
        {
            LOG.info("Could not find class " + classname_SecurityUtils);
            return;
        }

        Method method = getMethod(clazz, "setRegisterBouncyCastle", new Class<?>[]{boolean.class});
        if(method == null)
        {
            return;
        }

        String errorMsgPrefix = "SecurityUtils.setRegisterBouncyCastle(false): ";

        try
        {
            method.invoke(null, new Object[]{false});
        } catch (IllegalArgumentException | IllegalAccessException | InvocationTargetException e)
        {
            LOG.warn(errorMsgPrefix + "{}: {}", e.getClass().getName(), e.getMessage());
        }

        LOG.info("Fixed SSH BouncyCastle Bug");
    }

    private static final Method getMethod(
            Class<?> clz,
            String methodName,
            Class<?>[] params)
    {
        Method serviceMethod = null;
        final String desc = "Method " + clz.getName() + "." + methodName;

        try
        {
            if(params == null)
            {
                serviceMethod = clz.getDeclaredMethod(methodName);
            }
            else
            {
                serviceMethod = clz.getDeclaredMethod(methodName, params);
            }
            serviceMethod.setAccessible(true);
            return serviceMethod;
        } catch (SecurityException | NoSuchMethodException e)
        {
            LOG.warn("Could not get " + desc + ", {}: {}", e.getClass().getName(), e.getMessage());
            LOG.debug("Could not get " + desc, e);
        }

        return null;
    }

}
