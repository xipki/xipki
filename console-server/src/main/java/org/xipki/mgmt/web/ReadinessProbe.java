// License Apache License 2.0

package org.xipki.mgmt.web;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;

/**
 * Bounds dependency checks triggered by the public readiness endpoint.
 *
 * @author palos
 */
final class ReadinessProbe {
  private final BooleanSupplier database;
  private final BooleanSupplier ca;
  private final long ttlNanos;
  private final LongSupplier clock;
  private final AtomicBoolean refreshing = new AtomicBoolean();
  private volatile boolean checked;
  private volatile boolean ready;
  private volatile long checkedAt;

  ReadinessProbe(BooleanSupplier database, BooleanSupplier ca, Duration ttl, LongSupplier clock) {
    this.database = database;
    this.ca = ca;
    this.ttlNanos = ttl.toNanos();
    this.clock = clock;
  }

  boolean isReady() {
    long now = clock.getAsLong();
    if (checked && now - checkedAt < ttlNanos) {
      return ready;
    }
    if (!refreshing.compareAndSet(false, true)) {
      return false;
    }
    try {
      if (checked && clock.getAsLong() - checkedAt < ttlNanos) {
        return ready;
      }
      boolean result;
      try {
        result = database.getAsBoolean() && ca.getAsBoolean();
      } catch (RuntimeException ex) {
        result = false;
      }
      ready = result;
      checkedAt = clock.getAsLong();
      checked = true;
      return result;
    } finally {
      refreshing.set(false);
    }
  }
}
