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

package org.xipki.ca.certprofile.commonpki;

import java.util.List;

import org.bouncycastle.asn1.isismtt.x509.NamingAuthority;
import org.bouncycastle.asn1.x509.GeneralName;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.1
 */

public class AdmissionsOption {

    private final GeneralName admissionAuthority;

    private final NamingAuthority namingAuthority;

    private final List<ProfessionInfoOption> professionInfos;

    public AdmissionsOption(final GeneralName admissionAuthority,
            final NamingAuthority namingAuthority,
            final List<ProfessionInfoOption> professionInfos) {
        this.admissionAuthority = admissionAuthority;
        this.namingAuthority = namingAuthority;
        this.professionInfos = ParamUtil.requireNonEmpty("professionInfos", professionInfos);
    }

    public GeneralName admissionAuthority() {
        return admissionAuthority;
    }

    public NamingAuthority namingAuthority() {
        return namingAuthority;
    }

    public List<ProfessionInfoOption> professionInfos() {
        return professionInfos;
    }

}
