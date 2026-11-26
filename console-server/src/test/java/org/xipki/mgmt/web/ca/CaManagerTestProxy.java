// License Apache License 2.0

package org.xipki.mgmt.web.ca;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/** Creates focused CaManager test doubles without a second production protocol implementation. */
public final class CaManagerTestProxy {
  @FunctionalInterface
  public interface Handler {
    Object invoke(Method method, Object[] arguments) throws Throwable;
  }

  /** Returns a proxy that delegates each management operation to the supplied test handler. */
  public static CaManager create(Handler handler) {
    return (CaManager)
        Proxy.newProxyInstance(
            CaManager.class.getClassLoader(),
            new Class<?>[] {CaManager.class},
            (proxy, method, arguments) -> handler.invoke(method, arguments));
  }

  private CaManagerTestProxy() {}
}
