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

package org.xipki.qa.ca;

import java.io.Closeable;
import java.util.Set;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface CaQaSystemManager extends Closeable {

  boolean init();

  Set<String> getIssuerNames();

  /**
   * Returns the issuer information.
   * @param issuerName
   *          Name of the issuer
   * @return the issuer
   */
  IssuerInfo getIssuer(String issuerName);

  Set<String> getCertprofileNames();

  /**
   * TODO.
   * @param certprofileName
   *          Name of the cert profile.
   * @return the cert profile.
   */
  CertprofileQa getCertprofile(String certprofileName);

}
