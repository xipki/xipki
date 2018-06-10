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

package org.xipki.security.speed.pkcs12;

import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.security.SecurityFactory;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.KeyUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class P12ECKeyGenSpeed extends P12KeyGenSpeed {

  private final ASN1ObjectIdentifier curveOid;

  public P12ECKeyGenSpeed(String curveNameOrOid, SecurityFactory securityFactory)
      throws Exception {
    super("PKCS#12 EC key generation\ncurve: " + curveNameOrOid, securityFactory);

    ASN1ObjectIdentifier oid = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveNameOrOid);
    if (oid == null) {
      throw new IllegalArgumentException("invalid curve name or OID " + curveNameOrOid);
    }

    this.curveOid = oid;
  }

  @Override
  protected void generateKeypair(SecureRandom random) throws Exception {
    KeyUtil.generateECKeypair(curveOid, random);

  }

}
