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

package org.xipki.ca.client.api.dto;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class UnrevokeOrRemoveCertEntry extends IssuerSerialEntry {

  private byte[] authorityKeyIdentifier;

  public UnrevokeOrRemoveCertEntry(String id, X509Certificate cert) {
    this(id, X500Name.getInstance(cert.getIssuerX500Principal().getEncoded()),
        cert.getSerialNumber());
  }

  public UnrevokeOrRemoveCertEntry(String id, X500Name issuer, BigInteger serialNumber) {
    super(id, issuer, serialNumber);
  }

  public byte[] getAuthorityKeyIdentifier() {
    return authorityKeyIdentifier;
  }

  public void setAuthorityKeyIdentifier(byte[] authorityKeyIdentifier) {
    this.authorityKeyIdentifier = authorityKeyIdentifier;
  }

}
