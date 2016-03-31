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

package org.xipki.commons.password.api;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class PasswordProducer {

    private static final Logger LOG = LoggerFactory.getLogger(PasswordProducer.class);

    private static ConcurrentHashMap<String, BlockingQueue<char[]>> namePasswordsMap =
            new ConcurrentHashMap<>();

    public static void registerPasswordConsumer(
            final String name) {
        assertNameNotBlank(name);
        BlockingQueue<char[]> queue = new LinkedBlockingQueue<>(1);
        namePasswordsMap.put(name, queue);
        LOG.info("registered passoword consumer '{}'", name);
    }

    public static void unregisterPasswordConsumer(
            final String name) {
        assertNameNotBlank(name);
        namePasswordsMap.remove(name);
        LOG.info("unregistered passoword consumer '{}'", name);
    }

    public static char[] takePassword(
            final String name)
    throws InterruptedException, PasswordResolverException {
        assertNameNotBlank(name);
        if (!namePasswordsMap.containsKey(name)) {
            throw new PasswordResolverException("password consumer '" + name
                    + "' is not registered ");
        }
        return namePasswordsMap.get(name).take();
    }

    public static void putPassword(
            final String name,
            final char[] password)
    throws InterruptedException, PasswordResolverException {
        assertNameNotBlank(name);
        if (!namePasswordsMap.containsKey(name)) {
            throw new PasswordResolverException("password consumer '" + name
                    + "' is not registered ");
        }

        namePasswordsMap.get(name).put(password);
        LOG.info("provided passoword for consumer '{}'", name);
    }

    public static boolean needsPassword(
            final String name) {
        assertNameNotBlank(name);
        if (!namePasswordsMap.containsKey(name)) {
            return false;
        }
        return namePasswordsMap.get(name).isEmpty();
    }

    public static Set<String> getNames() {
        return Collections.unmodifiableSet(namePasswordsMap.keySet());
    }

    private static void assertNameNotBlank(
            final String name) {
        if (name == null) {
            throw new NullPointerException("name must not be null");
        }

        if (name.isEmpty()) {
            throw new IllegalArgumentException("name must not be empty");
        }
    }
}
