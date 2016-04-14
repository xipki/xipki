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
 *
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.commons.password.api.internal;

import java.util.Objects;
import java.util.concurrent.ConcurrentLinkedDeque;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.password.api.PasswordCallback;
import org.xipki.commons.password.api.PasswordCallbackFactory;
import org.xipki.commons.password.api.PasswordCallbackFactoryRegister;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class PasswordCallbackFactoryRegisterImpl implements PasswordCallbackFactoryRegister {

    private static final Logger LOG = LoggerFactory.getLogger(
            PasswordCallbackFactoryRegisterImpl.class);

    private ConcurrentLinkedDeque<PasswordCallbackFactory> services =
            new ConcurrentLinkedDeque<PasswordCallbackFactory>();

    @Override
    public PasswordCallback newPasswordCallback(
            final String type,
            final long timeout) {
        Objects.requireNonNull(type, "type could not be null");
        if (timeout < 0) {
            throw new IllegalArgumentException("timeout is invalid: " + timeout);
        }

        long start = System.currentTimeMillis();

        while (true) {
            long duration = System.currentTimeMillis() - start;
            for (PasswordCallbackFactory service : services) {
                if (service.canCreatePasswordCallback(type)) {
                    LOG.info("fould Factory to create PasswordCallback of type '" + type + "' @"
                            + duration + "ms");
                    return service.newPasswordCallback(type);
                }
            }

            duration = System.currentTimeMillis() - start;
            if (timeout != 0 && duration > timeout) {
                throw new RuntimeException(
                        "could not find Factory to create PasswordCallback of type '" + type
                        + "' @" + duration + "ms");
            }

            try {
                Thread.sleep(100);
            } catch (InterruptedException ex) {// CHECKSTYLE:SKIP
            }
        }
    }

    public void bindService(
            final PasswordCallbackFactory service) {
        //might be null if dependency is optional
        if (service == null) {
            LOG.info("bindService invoked with null.");
            return;
        }

        boolean replaced = services.remove(service);
        services.add(service);

        String action = replaced
                ? "replaced"
                : "added";
        LOG.info("{} PasswordCallbackFactory binding for {}", action, service);
    }

    public void unbindService(
            final PasswordCallbackFactory service) {
        //might be null if dependency is optional
        if (service == null) {
            LOG.info("unbindService invoked with null.");
            return;
        }

        if (services.remove(service)) {
            LOG.info("removed PasswordCallbackFactory binding for {}", service);
        } else {
            LOG.info("no PasswordCallbackFactory binding found to remove for '{}'", service);
        }
    }

}
