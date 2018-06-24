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

package org.xipki.security.pkcs11;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.xipki.security.X509Cert;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11SlotRefreshResult {

  private final Map<P11ObjectIdentifier, P11Identity> identities = new HashMap<>();

  private final Map<P11ObjectIdentifier, X509Cert> certificates = new HashMap<>();

  private final Set<Long> mechanisms = new HashSet<>();

  public P11SlotRefreshResult() {
  }

  public Map<P11ObjectIdentifier, P11Identity> getIdentities() {
    return identities;
  }

  public Map<P11ObjectIdentifier, X509Cert> getCertificates() {
    return certificates;
  }

  public Set<Long> getMechanisms() {
    return mechanisms;
  }

  public void addIdentity(P11Identity identity) {
    ParamUtil.requireNonNull("identity", identity);
    this.identities.put(identity.getIdentityId().getKeyId(), identity);
  }

  public void addMechanism(long mechanism) {
    this.mechanisms.add(mechanism);
  }

  public void addCertificate(P11ObjectIdentifier objectId, X509Cert certificate) {
    ParamUtil.requireNonNull("objectId", objectId);
    ParamUtil.requireNonNull("certificate", certificate);
    this.certificates.put(objectId, certificate);
  }

  /**
   * Returns the certificate of the given identifier {@code id}.
   * @param id
   *          Identifier. Must not be {@code null}.
   * @return the certificate of the given identifier.
   */
  public X509Cert getCertForId(byte[] id) {
    for (P11ObjectIdentifier objId : certificates.keySet()) {
      if (objId.matchesId(id)) {
        return certificates.get(objId);
      }
    }
    return null;
  }

  /**
   * Returns the PKCS#11 label for certificate of the given {@code id}.
   * @param id
   *          Identifier. Must not be {@code null}.
   * @return the label.
   */
  public String getCertLabelForId(byte[] id) {
    for (P11ObjectIdentifier objId : certificates.keySet()) {
      if (objId.matchesId(id)) {
        return objId.getLabel();
      }
    }
    return null;
  }

}
