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

package org.xipki.scep.serveremulator;

import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.scep.util.ScepUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public class NextCaAndRa {

  private final Certificate caCert;

  private final Certificate raCert;

  public NextCaAndRa(Certificate caCert, Certificate raCert) {
    this.caCert = ScepUtil.requireNonNull("caCert", caCert);
    this.raCert = raCert;
  }

  public Certificate getCaCert() {
    return caCert;
  }

  public Certificate getRaCert() {
    return raCert;
  }

}
