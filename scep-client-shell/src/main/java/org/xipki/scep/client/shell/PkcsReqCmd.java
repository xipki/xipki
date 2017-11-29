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

package org.xipki.scep.client.shell;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.xipki.common.util.ParamUtil;
import org.xipki.scep.client.EnrolmentResponse;
import org.xipki.scep.client.ScepClient;
import org.xipki.scep.client.exception.ScepClientException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-scep", name = "pkcs-req",
        description = "enroll certificate via messageType PkcsReq")
@Service
public class PkcsReqCmd extends EnrollCertCommandSupport {

    @Override
    protected EnrolmentResponse requestCertificate(final ScepClient client,
            final CertificationRequest csr, final PrivateKey identityKey,
            final X509Certificate identityCert) throws ScepClientException {
        ParamUtil.requireNonNull("client", client);
        return client.scepPkcsReq(csr, identityKey, identityCert);
    }

}
