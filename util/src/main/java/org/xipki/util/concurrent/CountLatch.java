/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.AbstractQueuedSynchronizer;

/**
 * Count latch.
 *
 * @author Lijun Liao
 * @since 2.2.0
 */

public class CountLatch {

  private class Sync extends AbstractQueuedSynchronizer {
    private static final long serialVersionUID = 1L;

    public Sync() {
    }

    @Override
    protected int tryAcquireShared(int arg) {
      return count.get() == releaseValue ? 1 : -1;
    }

    @Override
    protected boolean tryReleaseShared(int arg) {
      return true;
    }
  }

  private final Sync sync;
  private final AtomicLong count;
  private volatile long releaseValue;

  public CountLatch(long initial, long releaseValue) {
    this.releaseValue = releaseValue;
    this.count = new AtomicLong(initial);
    this.sync = new Sync();
  }

  public void await()
      throws InterruptedException {
    sync.acquireSharedInterruptibly(1);
  }

  public boolean await(long timeout, TimeUnit unit)
      throws InterruptedException {
    return sync.tryAcquireSharedNanos(1, unit.toNanos(timeout));
  }

  public long countUp() {
    final long current = count.incrementAndGet();
    if (current == releaseValue) {
      sync.releaseShared(0);
    }
    return current;
  }

  public long countDown() {
    final long current = count.decrementAndGet();
    if (current == releaseValue) {
      sync.releaseShared(0);
    }
    return current;
  }

  public long getCount() {
    return count.get();
  }
}
