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

package org.xipki.scep.serveremulator;

import org.xipki.security.X509Cert;
import org.xipki.util.Args;

/**
 * Contains the next CA certificate and next RA certificate.
 *
 * @author Lijun Liao
 */

public class NextCaAndRa {

  private final X509Cert caCert;

  private final X509Cert raCert;

  public NextCaAndRa(X509Cert caCert, X509Cert raCert) {
    this.caCert = Args.notNull(caCert, "caCert");
    this.raCert = raCert;
  }

  public X509Cert getCaCert() {
    return caCert;
  }

  public X509Cert getRaCert() {
    return raCert;
  }

}
