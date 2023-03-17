// #THIRDPARTY# HikariCP

/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao (xipki)
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

package org.xipki.util.concurrent;

import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;

/**
 * ConcurrentBagEntry.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public class ConcurrentBagEntry<T> {

  @SuppressWarnings({ "unused" })
  private volatile int state = 0; // Don't delete me, will be used by the stateUpdater

  private static final AtomicIntegerFieldUpdater<ConcurrentBagEntry> stateUpdater;

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

  public int getState() {
    return stateUpdater.get(this);
  }

  public boolean compareAndSet(int expect, int update) {
    return stateUpdater.compareAndSet(this, expect, update);
  }

  public void setState(int update) {
    stateUpdater.set(this, update);
  }

}
