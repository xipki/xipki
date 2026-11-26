// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.xipki.mgmt.web.ca.CaDomain.CaMgmtException;
import org.xipki.mgmt.web.ca.CaManager;

/**
 * @author palos
 */
class CaRemovalTest {
  @Test
  void failedRemoteRemovalKeepsLocalBindings() {
    var cleanup = new AtomicInteger();
    CaManager manager = manager(false);
    assertThrows(
        CaMgmtException.class, () -> CaRemoval.remove(manager, "parent", cleanup::incrementAndGet));
    assertEquals(0, cleanup.get());
  }

  @Test
  void confirmedRemoteRemovalThenRevokesBindings() throws Exception {
    var cleanup = new AtomicInteger();
    CaRemoval.remove(manager(true), "parent", cleanup::incrementAndGet);
    assertEquals(1, cleanup.get());
  }

  @Test
  void uncertainResponseReconcilesOnlyWhenCaIsAbsent() throws Exception {
    var cleanup = new AtomicInteger();
    CaManager manager =
        (CaManager)
            Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] {CaManager.class},
                (proxy, method, args) -> {
                  if (method.getName().equals("removeCa")) {
                    throw new CaMgmtException(new IOException("lost response"));
                  }
                  if (method.getName().equals("getCaNames")) {
                    return Set.of();
                  }
                  throw new UnsupportedOperationException(method.getName());
                });
    CaRemoval.remove(manager, "parent", cleanup::incrementAndGet);
    assertEquals(1, cleanup.get());
  }

  @Test
  void uncertainResponseKeepsBindingsWhileCaStillExists() {
    var cleanup = new AtomicInteger();
    CaManager manager =
        (CaManager)
            Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] {CaManager.class},
                (proxy, method, args) -> {
                  if (method.getName().equals("removeCa")) {
                    throw new CaMgmtException(new IOException("lost response"));
                  }
                  if (method.getName().equals("getCaNames")) {
                    return Set.of("parent");
                  }
                  throw new UnsupportedOperationException(method.getName());
                });
    assertThrows(
        CaMgmtException.class, () -> CaRemoval.remove(manager, "parent", cleanup::incrementAndGet));
    assertEquals(0, cleanup.get());
  }

  private static CaManager manager(boolean success) {
    return (CaManager)
        Proxy.newProxyInstance(
            CaRemovalTest.class.getClassLoader(),
            new Class<?>[] {CaManager.class},
            (proxy, method, args) -> {
              if (method.getName().equals("removeCa")) {
                if (!success) {
                  throw new CaMgmtException("rejected");
                }
                return null;
              }
              if (method.getName().equals("getCaNames")) {
                return Set.of("parent");
              }
              throw new UnsupportedOperationException(method.getName());
            });
  }
}
