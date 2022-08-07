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

package org.xipki.ca.gateway;

import org.xipki.security.X509Cert;

/**
 * Requestor info interface.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public interface Requestor {

  String getName();

  char[] getPassword();

  byte[] getKeyId();

  X509Cert getCert();

  boolean authenticate(char[] password);

  boolean authenticate(byte[] password);

  boolean isCertprofilePermitted(String certprofile);

  boolean isPermitted(int permission);

}
