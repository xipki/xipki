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

package org.xipki.ca.dbtool.diffdb.io;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.HashAlgoType;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class EjbcaCaInfo {

    private final int caId;

    private final X500Name subject;

    private final String hexSha1;

    private final String caDirname;

    public EjbcaCaInfo(final int caId, final byte[] certBytes, final String caDirname) {
        ParamUtil.requireNonNull("certBytes", certBytes);

        this.caId = caId;
        this.hexSha1 = HashAlgoType.SHA1.hexHash(certBytes).toLowerCase();
        this.subject = Certificate.getInstance(certBytes).getSubject();
        this.caDirname = ParamUtil.requireNonNull("caDirname", caDirname);
    }

    public int caId() {
        return caId;
    }

    public X500Name subject() {
        return subject;
    }

    public String hexSha1() {
        return hexSha1;
    }

    public String caDirname() {
        return caDirname;
    }

}
