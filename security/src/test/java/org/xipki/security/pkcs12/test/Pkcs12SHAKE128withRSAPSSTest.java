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

package org.xipki.security.pkcs12.test;

import org.xipki.security.SignAlgo;

/**
 * JUnit tests to test the signature creation and verification of PKCS#12 token
 * for the signature algorithm SHA256withRSA.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class Pkcs12SHAKE128withRSAPSSTest extends Pkcs12SignVerifyTest {

  @Override
  protected String getPkcs12File() {
    return "src/test/resources/pkcs12test/test1.p12";
  }

  @Override
  protected String getCertificateFile() {
    return "src/test/resources/pkcs12test/test1.der";
  }

  @Override
  protected SignAlgo getSignatureAlgorithm() {
    return SignAlgo.RSAPSS_SHAKE128;
  }

}
