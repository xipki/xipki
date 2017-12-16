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

package org.xipki.ca.certprofile.commonpki;

import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.isismtt.x509.NamingAuthority;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.1
 */

public class ProfessionInfoOption {

    private final NamingAuthority namingAuthority;

    private final List<String> professionItems;

    private final List<ASN1ObjectIdentifier> professionOids;

    private final RegistrationNumberOption registrationNumberOption;

    private byte[] addProfessionalInfo;

    public ProfessionInfoOption(
            final NamingAuthority namingAuthority,
            final List<String> professionItems,
            final List<ASN1ObjectIdentifier> professionOids,
            final RegistrationNumberOption registrationNumberOption,
            final byte[] addProfessionalInfo) {
        this.namingAuthority = namingAuthority;
        this.professionItems = ParamUtil.requireNonEmpty("professionItems", professionItems);
        this.professionOids = professionOids;
        this.registrationNumberOption = registrationNumberOption;
        this.addProfessionalInfo = addProfessionalInfo;
    }

    public byte[] addProfessionalInfo() {
        return addProfessionalInfo;
    }

    public void setAddProfessionalInfo(byte[] addProfessionalInfo) {
        this.addProfessionalInfo = addProfessionalInfo;
    }

    public NamingAuthority namingAuthority() {
        return namingAuthority;
    }

    public List<String> professionItems() {
        return professionItems;
    }

    public List<ASN1ObjectIdentifier> professionOids() {
        return professionOids;
    }

    public RegistrationNumberOption registrationNumberOption() {
        return registrationNumberOption;
    }

}
