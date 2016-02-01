/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.commons.password;

import java.util.concurrent.ConcurrentLinkedQueue;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.password.api.PasswordResolver;
import org.xipki.commons.password.api.PasswordResolverException;
import org.xipki.commons.password.api.SinglePasswordResolver;

/**
 * @author Lijun Liao
 */

public class PasswordResolverImpl implements PasswordResolver {

    private static final Logger LOG = LoggerFactory.getLogger(PasswordResolverImpl.class);

    private ConcurrentLinkedQueue<SinglePasswordResolver> resolvers =
            new ConcurrentLinkedQueue<SinglePasswordResolver>();

    public PasswordResolverImpl() {
    }

    public void bindService(
            final SinglePasswordResolver service) {
        //might be null if dependency is optional
        if (service == null) {
            LOG.debug("bindService invoked with null.");
            return;
        }

        boolean replaced = resolvers.remove(service);
        resolvers.add(service);
        String txt = replaced
                ? "replaced"
                : "added";
        LOG.debug("{} SinglePasswordResolver binding for {}",
                txt, service);
    }

    public void unbindService(
            final SinglePasswordResolver service) {
        //might be null if dependency is optional
        if (service == null) {
            LOG.debug("unbindService invoked with null.");
            return;
        }

        try {
            if (resolvers.remove(service)) {
                LOG.debug("removed SinglePasswordResolver binding for {}", service);
            } else {
                LOG.debug("no SinglePasswordResolver binding found to remove for '{}'", service);
            }
        } catch (Exception e) {
            LOG.debug("caught Exception({}). service is probably destroyed.", e.getMessage());
        }
    }

    @Override
    public char[] resolvePassword(
            final String passwordHint)
    throws PasswordResolverException {
        int index = passwordHint.indexOf(':');
        if (index == -1) {
            return passwordHint.toCharArray();
        }

        String protocol = passwordHint.substring(0, index);

        for (SinglePasswordResolver resolver : resolvers) {
            if (resolver.canResolveProtocol(protocol)) {
                return resolver.resolvePassword(passwordHint);
            }
        }

        return passwordHint.toCharArray();
    }

}
