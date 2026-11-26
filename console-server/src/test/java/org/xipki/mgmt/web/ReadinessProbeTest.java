// License Apache License 2.0

package org.xipki.mgmt.web;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

/**
 * @author palos
 */
class ReadinessProbeTest {
  @Test
  void cachesSuccessAndFailureUntilTheNextRefresh() {
    var now = new AtomicLong();
    var checks = new AtomicInteger();
    var ready = new AtomicBoolean(true);
    var probe =
        new ReadinessProbe(
            () -> {
              checks.incrementAndGet();
              return ready.get();
            },
            () -> true,
            Duration.ofSeconds(5),
            now::get);

    assertTrue(probe.isReady());
    ready.set(false);
    assertTrue(probe.isReady());
    assertEquals(1, checks.get());
    now.set(Duration.ofSeconds(5).toNanos());
    assertFalse(probe.isReady());
    assertFalse(probe.isReady());
    assertEquals(2, checks.get());
  }

  @Test
  void concurrentRequestsDoNotQueueBehindASlowDependency() throws Exception {
    var entered = new CountDownLatch(1);
    var release = new CountDownLatch(1);
    var checks = new AtomicInteger();
    var probe =
        new ReadinessProbe(
            () -> {
              checks.incrementAndGet();
              entered.countDown();
              try {
                release.await();
              } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return false;
              }
              return true;
            },
            () -> true,
            Duration.ofSeconds(5),
            System::nanoTime);
    var first = new Thread(probe::isReady);
    first.start();
    try {
      assertTrue(entered.await(5, TimeUnit.SECONDS));
      assertFalse(probe.isReady());
      assertEquals(1, checks.get());
    } finally {
      release.countDown();
      first.join(5000);
    }
    assertTrue(probe.isReady());
  }
}
