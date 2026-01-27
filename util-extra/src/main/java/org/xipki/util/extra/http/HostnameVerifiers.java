// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.http;

import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.extra.misc.ReflectiveUtil;
import org.xipki.util.misc.StringUtil;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

/**
 * Utility class to create {@link HostnameVerifier}.
 *
 * @author Lijun Liao (xipki)
 */
public class HostnameVerifiers {

  public static final HostnameVerifier NO_OP = new NoopHostnameVerifier();

  private static class NoopHostnameVerifier implements HostnameVerifier {

    @Override
    public boolean verify(final String s, final SSLSession sslSession) {
      return true;
    }

    @Override
    public final String toString() {
      return "NO_OP";
    }

  }

  /**
   * Create HostnameVerifier.
   * @param hostnameVerifierType valid values are no_op, default, or
   *           java:{qualified class name} (without the brackets)
   * @return HostnameVerifier instance
   * @throws ObjectCreationException If could not create HostnameVerifier
   */
  public static HostnameVerifier createHostnameVerifier(
      String hostnameVerifierType)
      throws ObjectCreationException {
    if (StringUtil.isBlank(hostnameVerifierType)
        || "default".equalsIgnoreCase(hostnameVerifierType)) {
      return null; // not need to specify explicitly.
      // return HttpsURLConnection.getDefaultHostnameVerifier();
    } else if ("no_op".equalsIgnoreCase(hostnameVerifierType)) {
      return NO_OP;
    } else if (hostnameVerifierType.startsWith("java:")) {
      String className = hostnameVerifierType.substring("java:".length());
      return ReflectiveUtil.newInstance(className,
          HostnameVerifiers.class.getClassLoader());
    } else {
      throw new IllegalArgumentException(
          "invalid hostnameVerifierType " + hostnameVerifierType);
    }
  } // method createHostnameVerifier

}
