// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.ca.certprofile.xijson.conf.extn.BiometricInfo;
import org.xipki.ca.certprofile.xijson.conf.extn.BiometricInfo.BiometricTypeType;
import org.xipki.security.HashAlgo;
import org.xipki.util.Args;
import org.xipki.util.TripleState;

import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

/**
 * Control of the extension BiometricInfo.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class BiometricInfoOption {

  private final Set<Integer> predefinedTypes;

  private final Set<ASN1ObjectIdentifier> idTypes;

  private final Set<HashAlgo> hashAlgorithms;

  private final TripleState sourceDataUriOccurrence;

  public BiometricInfoOption(BiometricInfo value) throws NoSuchAlgorithmException {
    Args.notNull(value, "value");

    this.sourceDataUriOccurrence = value.getIncludeSourceDataUri();
    this.hashAlgorithms = new HashSet<>();
    for (DescribableOid doid : value.getHashAlgorithms()) {
      hashAlgorithms.add(HashAlgo.getInstance(doid.getOid()));
    }

    this.predefinedTypes = new HashSet<>();
    this.idTypes = new HashSet<>();
    for (BiometricTypeType m : value.getTypes()) {
      if (m.getPredefined() != null) {
        predefinedTypes.add(m.getPredefined().getValue());
      } else if (m.getOid() != null) {
        idTypes.add(new ASN1ObjectIdentifier(m.getOid().getOid()));
      } else {
        throw new IllegalStateException("should not reach here, invalid biometricType");
      }
    }
  } // constructor

  public boolean isTypePermitted(TypeOfBiometricData type) {
    return Args.notNull(type, "type").isPredefined()
      ? predefinedTypes.contains(type.getPredefinedBiometricType())
      : idTypes.contains(type.getBiometricDataOid());
  }

  public boolean isHashAlgorithmPermitted(HashAlgo hashAlgorithm) {
    return hashAlgorithms.contains(Args.notNull(hashAlgorithm, "hashAlgorithm"));
  }

  public TripleState getSourceDataUriOccurrence() {
    return sourceDataUriOccurrence;
  }

}
