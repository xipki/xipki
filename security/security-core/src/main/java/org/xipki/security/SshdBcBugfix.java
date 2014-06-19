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
        } catch (IllegalArgumentException e)
        {
            LOG.warn(errorMsgPrefix + "IllegalArgumentException {}", e.getMessage());
        } catch (IllegalAccessException e)
        {
            LOG.warn(errorMsgPrefix + "IllegalAccessException {}", e.getMessage());
        } catch (InvocationTargetException e)
        {
            LOG.warn(errorMsgPrefix + "InvocationTargetException {}", e.getMessage());
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
        } catch (SecurityException e)
        {
            LOG.warn("Could not get " + desc + ", SecuirtyException: {}", e.getMessage());
            LOG.debug("Could not get " + desc, e);
        } catch (NoSuchMethodException e)
        {
            LOG.warn("Could not get " + desc + ", NoSuchMethodException: {}", e.getMessage());
            LOG.debug("Could not get " + desc, e);
        }

        return null;
    }

}
