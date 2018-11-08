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

package org.xipki.ca.client.impl;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.AlgorithmUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.1.0
 */

class PbmMacClientCmpResponder implements ClientCmpResponder {

  private final GeneralName name;

  private final List<ASN1ObjectIdentifier> owfAlgos;

  private final List<ASN1ObjectIdentifier> macAlgos;

  public PbmMacClientCmpResponder(X500Name x500Name, List<String> owfs, List<String> macs) {
    this.name = new GeneralName(x500Name);

    this.owfAlgos = new ArrayList<>(owfs.size());

    for (int i = 0; i < owfs.size(); i++) {
      String algo = owfs.get(i);
      HashAlgo ha;
      try {
        ha = HashAlgo.getNonNullInstance(algo);
      } catch (Exception ex) {
        throw new IllegalArgumentException("invalid owf " + algo, ex);
      }
      owfAlgos.add(ha.getOid());
    }

    this.macAlgos = new ArrayList<>(macs.size());
    for (int i = 0; i < macs.size(); i++) {
      String algo = macs.get(i);
      AlgorithmIdentifier algId;
      try {
        algId = AlgorithmUtil.getMacAlgId(algo);
      } catch (NoSuchAlgorithmException ex) {
        throw new IllegalArgumentException("invalid mac" + algo, ex);
      }
      macAlgos.add(algId.getAlgorithm());
    }

  }

  public boolean isPbmOwfPermitted(AlgorithmIdentifier pbmOwf) {
    ASN1ObjectIdentifier owfOid = pbmOwf.getAlgorithm();
    for (ASN1ObjectIdentifier oid : owfAlgos) {
      if (oid.equals(owfOid)) {
        return true;
      }
    }
    return false;
  }

  public boolean isPbmMacPermitted(AlgorithmIdentifier pbmMac) {
    ASN1ObjectIdentifier macOid = pbmMac.getAlgorithm();
    for (ASN1ObjectIdentifier oid : macAlgos) {
      if (oid.equals(macOid)) {
        return true;
      }
    }
    return false;
  }

  @Override
  public GeneralName getName() {
    return name;
  }

}
