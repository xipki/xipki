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

package org.xipki.scep.message;

import java.security.cert.X509Certificate;

/**
 * TODO.
 * @author Lijun Liao
 */

public interface CertificateValidator {

  /**
   * TODO.
   * @param target
   *          The certificate to be verified. Must not be {@code null}.
   * @param otherCerts
   *          Additional certificate that may be used. Could be {@code null}.
   * @return whether the target certificate is trusted.
   */
  boolean trustCertificate(X509Certificate target, X509Certificate[] otherCerts);

}
