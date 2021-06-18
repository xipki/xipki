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

package org.xipki.ca.certprofile.demo;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.Pack;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.util.ConfPairs;
import org.xipki.util.Hex;

import java.math.BigInteger;

/**
 * Example Certprofile for CDRM Client.
 *
 * @author Lijun Liao
 */

public class CdrmClientCertprofile extends XijsonCertprofile {

  private static final String CDRM_CAID = "cdrm.caid";
  private static final ASN1ObjectIdentifier batchNumberOid =
          ObjectIdentifiers.DN.generationQualifier;

  @Override
  public String getSerialNumberMode() {
    return "PROFILE";
  }

  /*
   * Byte 1-2: CA Id
   * Byte 3-6: Batch Number
   * Byte 7-20: the rightest 14 bytes of SM2(PublicKeyInfo)
   */
  @Override
  public BigInteger generateSerialNumber(
          X500Name caSubject,
          SubjectPublicKeyInfo caPublicKeyInfo,
          X500Name requestSubject,
          SubjectPublicKeyInfo publicKeyInfo,
          ConfPairs caExtraControl)
          throws CertprofileException {
    String str = caExtraControl.value(CDRM_CAID);
    if (str == null) {
      throw new CertprofileException("CA is not configured with " + CDRM_CAID);
    }

    short caId = Short.parseShort(str);
    // assert that the highest bit is 0.
    if (caId < 0) {
      throw new CertprofileException("invalid " + CDRM_CAID + ": '" + str + "'");
    }

    RDN[] rdns = requestSubject.getRDNs(batchNumberOid);
    int n = rdns == null ? 0 : rdns.length;
    if (n != 1) {
      throw new CertprofileException("requested subject contains " + n + " RDNS "
              + batchNumberOid.getId() + ", but 1 is expected");
    }
    str = IETFUtils.valueToString(rdns[0].getFirst().getValue());

    byte[] batchNumber = Hex.decode(str);
    if (batchNumber.length != 4) {
      throw new CertprofileException("invalid batch number: '" + str + "'");
    }

    byte[] sm3Hash = HashAlgo.SM3.hash(
                        Pack.longToBigEndian(System.currentTimeMillis()),
                        publicKeyInfo.getPublicKeyData().getBytes());
    byte[] serial = new byte[20];
    byte[] caIdBytes = Pack.shortToBigEndian(caId);
    System.arraycopy(caIdBytes, 0, serial, 0, 2);
    System.arraycopy(batchNumber, 0, serial, 2, 4);
    System.arraycopy(sm3Hash, 32 - 14, serial, 6, 14);
    return new BigInteger(serial);
  }

}
