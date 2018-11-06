/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.util.http.ssl;

import javax.net.ssl.HostnameVerifier;

import org.xipki.util.ObjectCreationException;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public class SslUtil {

  /**
   * Create HostnameVerifier.
   * @param hostnameVerifierType valid values are no_op, default, or
   *           java:{qualified class name} (without the brackets)
   * @return HostnameVerifier instance
   * @throws ObjectCreationException if could not create HostnameVerifier
   */
  public static HostnameVerifier createHostnameVerifier(String hostnameVerifierType)
      throws ObjectCreationException {
    if (StringUtil.isBlank(hostnameVerifierType)
        || "default".equalsIgnoreCase(hostnameVerifierType)) {
      return null; // not need to specify explicitly.
      // return HttpsURLConnection.getDefaultHostnameVerifier();
    } else if ("no_op".equalsIgnoreCase(hostnameVerifierType)) {
      return NoopHostnameVerifier.INSTANCE;
    } else if (hostnameVerifierType.startsWith("java:")) {
      String className = hostnameVerifierType.substring("java:".length());
      try {
        Class<?> clazz = Class.forName(className, true, SslUtil.class.getClassLoader());
        return (HostnameVerifier) clazz.newInstance();
      } catch (ClassNotFoundException | InstantiationException | IllegalAccessException
          | ClassCastException ex) {
        throw new ObjectCreationException("create not create HostnameVerifier from "
            + className + ": " + ex.getMessage(), ex);
      }
    } else {
      throw new IllegalArgumentException("invalid hostnameVerifierType " + hostnameVerifierType);
    }
  }

}
