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

package org.xipki.util.http;

import org.xipki.util.StringUtil;
import org.xipki.util.exception.ObjectCreationException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import java.lang.reflect.InvocationTargetException;

/**
 * Utility class to create {@link HostnameVerifier}.
 *
 * @author Lijun Liao
 */
public class HostnameVerifiers {

  public static final NoopHostnameVerifier NO_OP = new NoopHostnameVerifier();

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
  public static HostnameVerifier createHostnameVerifier(String hostnameVerifierType)
      throws ObjectCreationException {
    if (StringUtil.isBlank(hostnameVerifierType) || "default".equalsIgnoreCase(hostnameVerifierType)) {
      return null; // not need to specify explicitly.
      // return HttpsURLConnection.getDefaultHostnameVerifier();
    } else if ("no_op".equalsIgnoreCase(hostnameVerifierType)) {
      return NO_OP;
    } else if (hostnameVerifierType.startsWith("java:")) {
      String className = hostnameVerifierType.substring("java:".length());
      try {
        Class<?> clazz = Class.forName(className, true, HostnameVerifiers.class.getClassLoader());
        return (HostnameVerifier) clazz.getDeclaredConstructor().newInstance();
      } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException |
               InvocationTargetException ex) {
        throw new ObjectCreationException("create not create HostnameVerifier from "
            + className + ": " + ex.getMessage(), ex);
      }
    } else {
      throw new IllegalArgumentException("invalid hostnameVerifierType " + hostnameVerifierType);
    }
  } // method createHostnameVerifier

}
