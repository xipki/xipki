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

package org.xipki.ca.api.profile;

import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * Extension SubjectKeyIdentifierControl.
 *
 * @author Lijun Liao
 */

public class SubjectKeyIdentifierControl extends ValidatableConf {

  public enum SubjectKeyIdentifierMethod {
    // RFC5280, 4.2.1.2 Method 1: 160 bit SHA1
    METHOD_1,
    // RFC5280, 4.2.1.2 Method 1: 0100_2 || 60 bit LSB of SHA1
    METHOD_2
  }

  private SubjectKeyIdentifierMethod method;

  private String hashAlgo;

  public SubjectKeyIdentifierMethod getMethod() {
    return method;
  }

  public void setMethod(SubjectKeyIdentifierMethod method) {
    this.method = method;
  }

  public String getHashAlgo() {
    return hashAlgo;
  }

  public void setHashAlgo(String hashAlgo) {
    this.hashAlgo = hashAlgo;
  }

  @Override
  public void validate()
      throws InvalidConfException {
  }

} // class AuthorityKeyIdentifier
