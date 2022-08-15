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

package org.xipki.license.api;

/**
 * CM License Feature.
 *
 * @author Lijun Liao
 */
public interface CmLicense {

  /**
   * Whether the license is valid. The criteria may be the validity period,
   * license signature, or any other criteria.
   */
  boolean isValid();

  boolean grantAllCAs();

  /**
   * The CA subject in BC style.
   * Output of org.bouncycastle.asn1.x500.style.BCStyle.INSTANCE.toString(X500Name name)
   * @param caSubject the CA's subject
   * @return whether OCSP service for the given CA is allowed.
   */
  boolean grant(String caSubject);

  /**
   * Regulate the speed.
   */
  void regulateSpeed();

  /**
   * Returns maximal number of certificates.
   * @return maximal number of certificates, negative value if unlimited.
   */
  long getMaxNumberOfCerts();

}
