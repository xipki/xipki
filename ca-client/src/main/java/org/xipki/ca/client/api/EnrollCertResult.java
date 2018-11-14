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

package org.xipki.ca.client.api;

import java.security.cert.Certificate;
import java.util.Map;
import java.util.Set;

import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class EnrollCertResult {

  private final Certificate caCert;

  private final Map<String, CertifiedKeyPairOrError> certsOrErrors;

  public EnrollCertResult(Certificate caCert, Map<String, CertifiedKeyPairOrError> certsOrErrors) {
    this.certsOrErrors = Args.notEmpty(certsOrErrors, "certsOrErrors");
    this.caCert = caCert;
  }

  public Certificate getCaCert() {
    return caCert;
  }

  public CertifiedKeyPairOrError getCertOrError(String id) {
    Args.notBlank(id, "id");
    return certsOrErrors.get(id);
  }

  public Set<String> getAllIds() {
    return certsOrErrors.keySet();
  }

}
