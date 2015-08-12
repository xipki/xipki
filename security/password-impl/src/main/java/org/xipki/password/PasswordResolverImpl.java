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

package org.xipki.password;

import java.util.concurrent.ConcurrentLinkedQueue;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.api.PasswordResolver;
import org.xipki.password.api.PasswordResolverException;
import org.xipki.password.api.SinglePasswordResolver;

/**
 * @author Lijun Liao
 */

public class PasswordResolverImpl implements PasswordResolver
{
    private static final Logger LOG = LoggerFactory.getLogger(PasswordResolverImpl.class);

    private ConcurrentLinkedQueue<SinglePasswordResolver> resolvers =
            new ConcurrentLinkedQueue<SinglePasswordResolver>();

    public PasswordResolverImpl()
    {
    }

    public void bindService(
            final SinglePasswordResolver service)
    {
        //might be null if dependency is optional
        if (service == null)
        {
            LOG.debug("bindService invoked with null.");
            return;
        }

        boolean replaced = resolvers.remove(service);
        resolvers.add(service);
        LOG.debug("{} SinglePasswordResolver binding for {}", (replaced ? "replaced" : "added"), service);
    }

    public void unbindService(
            final SinglePasswordResolver service)
    {
        //might be null if dependency is optional
        if (service == null)
        {
            LOG.debug("unbindService invoked with null.");
            return;
        }

        try
        {
            if(resolvers.remove(service))
            {
                LOG.debug("removed SinglePasswordResolver binding for {}", service);
            }
            else
            {
                LOG.debug("no SinglePasswordResolver binding found to remove for '{}'", service);
            }
        } catch (Exception e)
        {
            LOG.debug("caught Exception({}). service is probably destroyed.", e.getMessage());
        }
    }

    @Override
    public char[] resolvePassword(
            final String passwordHint)
    throws PasswordResolverException
    {
        int index = passwordHint.indexOf(':');
        if(index == -1)
        {
            return passwordHint.toCharArray();
        }

        String protocol = passwordHint.substring(0, index);

        for(SinglePasswordResolver resolver : resolvers)
        {
            if(resolver.canResolveProtocol(protocol))
            {
                return resolver.resolvePassword(passwordHint);
            }
        }

        return passwordHint.toCharArray();
    }

}
