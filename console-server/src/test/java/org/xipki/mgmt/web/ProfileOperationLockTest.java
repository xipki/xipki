// License Apache License 2.0

package org.xipki.mgmt.web;

import static org.junit.jupiter.api.Assertions.*;

import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.xipki.mgmt.web.service.ProfileOperationLock;

/**
 * @author palos
 */
class ProfileOperationLockTest {
  @Test
  void profileMutationWaitsForIssuanceToComplete() throws Exception {
    var executor = Executors.newSingleThreadExecutor();
    var started = new CountDownLatch(1);
    Future<Boolean> mutation;
    try {
      try (var held = ProfileOperationLock.issuance()) {
        mutation =
            executor.submit(
                () -> {
                  started.countDown();
                  try (var write = ProfileOperationLock.mutation()) {
                    return true;
                  }
                });
        assertTrue(started.await(2, TimeUnit.SECONDS));
        assertThrows(TimeoutException.class, () -> mutation.get(100, TimeUnit.MILLISECONDS));
      }
      assertTrue(mutation.get(2, TimeUnit.SECONDS));
    } finally {
      executor.shutdownNow();
    }
  }
}
