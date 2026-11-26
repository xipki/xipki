// License Apache License 2.0

package org.xipki.mgmt.web.service;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.xipki.mgmt.web.core.*;

/**
 * Coordinates profile checks and engine writes within the single Web deployment.
 *
 * @author palos
 */
public final class ProfileOperationLock implements AutoCloseable {
  private static final ReentrantReadWriteLock LOCK = new ReentrantReadWriteLock(true);
  private final Lock held;

  private ProfileOperationLock(Lock held) {
    this.held = held;
    held.lock();
  }

  public static ProfileOperationLock issuance() {
    return new ProfileOperationLock(LOCK.readLock());
  }

  public static ProfileOperationLock mutation() {
    return new ProfileOperationLock(LOCK.writeLock());
  }

  @Override
  public void close() {
    held.unlock();
  }
}
