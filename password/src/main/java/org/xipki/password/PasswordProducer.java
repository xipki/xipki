/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.password;

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

    private static ConcurrentHashMap<String, Boolean> nameResultMap =
            new ConcurrentHashMap<>();

    public static void registerPasswordConsumer(final String name) {
        assertNameNotBlank(name);
        BlockingQueue<char[]> queue = new LinkedBlockingQueue<>(1);
        nameResultMap.remove(name);
        namePasswordsMap.put(name, queue);
        final String str = "registered password consumer " + name;
        System.out.println(str);
        LOG.info(str);
    }

    public static void unregisterPasswordConsumer(final String name) {
        assertNameNotBlank(name);
        namePasswordsMap.remove(name);
        final String str = "unregistered password consumer " + name;
        System.out.println(str);
        LOG.info(str);
    }

    public static void setPasswordCorrect(final String name, final boolean correct) {
        assertNameNotBlank(name);
        nameResultMap.put(name, correct);
        final String str = "set result of password consumer " + name + ": "
                + (correct ? "valid" : "invalid");
        System.out.println(str);
        LOG.info(str);
    }

    public static Boolean removePasswordCorrect(final String name) {
        return nameResultMap.remove(name);
    }

    public static char[] takePassword(final String name)
            throws InterruptedException, PasswordResolverException {
        assertNameNotBlank(name);
        if (!namePasswordsMap.containsKey(name)) {
            throw new PasswordResolverException("password consumer '" + name
                    + "' is not registered ");
        }
        char[] pwd = namePasswordsMap.get(name).take();
        final String str = "took password consumer " + name;
        System.out.println(str);
        return pwd;
    }

    public static void putPassword(final String name, final char[] password)
            throws InterruptedException, PasswordResolverException {
        assertNameNotBlank(name);
        if (!namePasswordsMap.containsKey(name)) {
            throw new PasswordResolverException("password consumer '" + name
                    + "' is not registered ");
        }

        nameResultMap.remove(name);
        namePasswordsMap.get(name).put(password);
        final String str = "provided password consumer " + name;
        System.out.println(str);
    }

    public static boolean needsPassword(final String name) {
        assertNameNotBlank(name);
        if (!namePasswordsMap.containsKey(name)) {
            return false;
        }
        return namePasswordsMap.get(name).isEmpty();
    }

    public static Set<String> getNames() {
        return Collections.unmodifiableSet(namePasswordsMap.keySet());
    }

    private static void assertNameNotBlank(final String name) {
        if (name == null) {
            throw new NullPointerException("name must not be null");
        }

        if (name.isEmpty()) {
            throw new IllegalArgumentException("name must not be empty");
        }
    }
}
