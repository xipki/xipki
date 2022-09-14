/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.ca.gateway.dummy;

import org.xipki.ca.gateway.Requestor;
import org.xipki.security.X509Cert;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class DummyCertRequestor implements Requestor {

  private X509Cert cert;

  static {
    System.err.println("DO NOT USE " + DummyCertRequestor.class.getName() + " IN THE PRODUCT ENVIRONMENT");
  }

  public DummyCertRequestor(X509Cert cert) {
    this.cert = cert;
  }

  @Override
  public String getName() {
    return cert.getCommonName();
  }

  @Override
  public char[] getPassword() {
    throw new UnsupportedOperationException("getPassword() unsupported");
  }

  @Override
  public byte[] getKeyId() {
    return cert.getSubjectKeyId();
  }

  @Override
  public X509Cert getCert() {
    return cert;
  }

  @Override
  public boolean authenticate(char[] password) {
    throw new UnsupportedOperationException("authenticate(byte[]) unsupported");
  }

  @Override
  public boolean authenticate(byte[] password) {
    throw new UnsupportedOperationException("authenticate(byte[]) unsupported");
  }

  @Override
  public boolean isCertprofilePermitted(String certprofile) {
    return true;
  }

  @Override
  public boolean isPermitted(int permission) {
    return true;
  }
}
