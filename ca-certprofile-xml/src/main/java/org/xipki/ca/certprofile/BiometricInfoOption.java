/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.ca.certprofile;

import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.xipki.ca.certprofile.x509.jaxb.BiometricInfo;
import org.xipki.ca.certprofile.x509.jaxb.BiometricTypeType;
import org.xipki.ca.certprofile.x509.jaxb.TripleState;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.util.AlgorithmUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class BiometricInfoOption {

    private final Set<Integer> predefinedTypes;

    private final Set<ASN1ObjectIdentifier> idTypes;

    private final Set<ASN1ObjectIdentifier> hashAlgorithms;

    private final TripleState sourceDataUriOccurrence;

    public BiometricInfoOption(final BiometricInfo jaxb) throws NoSuchAlgorithmException {
        ParamUtil.requireNonNull("jaxb", jaxb);

        this.sourceDataUriOccurrence = jaxb.getIncludeSourceDataUri();
        this.hashAlgorithms = XmlX509CertprofileUtil.toOidSet(jaxb.getHashAlgorithm());

        for (ASN1ObjectIdentifier m : hashAlgorithms) {
            AlgorithmUtil.getHashOutputSizeInOctets(m);
        }

        this.predefinedTypes = new HashSet<>();
        this.idTypes = new HashSet<>();
        for (BiometricTypeType m : jaxb.getType()) {
            if (m.getPredefined() != null) {
                predefinedTypes.add(m.getPredefined().getValue());
            } else if (m.getOid() != null) {
                idTypes.add(new ASN1ObjectIdentifier(m.getOid().getValue()));
            } else {
                throw new RuntimeException("should not reach here, invalid biometricType");
            }
        }
    }

    public boolean isTypePermitted(final TypeOfBiometricData type) {
        ParamUtil.requireNonNull("type", type);

        if (type.isPredefined()) {
            return predefinedTypes.contains(type.getPredefinedBiometricType());
        } else {
            return idTypes.contains(type.getBiometricDataOid());
        }
    }

    public boolean isHashAlgorithmPermitted(final ASN1ObjectIdentifier hashAlgorithm) {
        ParamUtil.requireNonNull("hashAlgorithm", hashAlgorithm);
        return hashAlgorithms.contains(hashAlgorithm);
    }

    public TripleState sourceDataUriOccurrence() {
        return sourceDataUriOccurrence;
    }

}
