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

package org.xipki.common.concurrent;

import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;

import org.xipki.common.concurrent.ConcurrentBag.IConcurrentBagEntry;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class ConcurrentBagEntry<T> implements IConcurrentBagEntry {

    @SuppressWarnings("rawtypes")
    private static final AtomicIntegerFieldUpdater<ConcurrentBagEntry> stateUpdater;

    // this field is used by the stateUpdater
    @SuppressWarnings("unused")
    private volatile int state = 0;

    private final T value;

    static {
        stateUpdater = AtomicIntegerFieldUpdater.newUpdater(ConcurrentBagEntry.class, "state");
    }

    public ConcurrentBagEntry(T value) {
        this.value = value;
    }

    public T value() {
        return value;
    }

    /** {@inheritDoc} */
    @Override
    public int getState() {
        return stateUpdater.get(this);
    }

    /** {@inheritDoc} */
    @Override
    public boolean compareAndSet(int expect, int update) {
        return stateUpdater.compareAndSet(this, expect, update);
    }

    /** {@inheritDoc} */
    @Override
    public void setState(int update) {
        stateUpdater.set(this, update);
    }

}
