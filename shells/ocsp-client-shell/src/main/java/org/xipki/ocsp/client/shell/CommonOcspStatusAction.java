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

package org.xipki.ocsp.client.shell;

import java.util.List;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.shell.XiAction;
import org.xipki.shell.completer.HashAlgCompleter;
import org.xipki.shell.completer.SigAlgCompleter;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class CommonOcspStatusAction extends XiAction {

  @Option(name = "--issuer", aliases = "-i", required = true,
      description = "DER encoded issuer certificate file")
  @Completion(FileCompleter.class)
  protected String issuerCertFile;

  @Option(name = "--nonce", description = "use nonce")
  protected Boolean usenonce = Boolean.FALSE;

  @Option(name = "--nonce-len", description = "nonce length in octects")
  protected Integer nonceLen;

  @Option(name = "--hash", description = "hash algorithm name")
  @Completion(HashAlgCompleter.class)
  protected String hashAlgo = "SHA256";

  @Option(name = "--sig-alg", multiValued = true,
      description = "comma-separated preferred signature algorithms")
  @Completion(SigAlgCompleter.class)
  protected List<String> prefSigAlgs;

  @Option(name = "--http-get", description = "use HTTP GET for small request")
  protected Boolean useHttpGetForSmallRequest = Boolean.FALSE;

  @Option(name = "--sign", description = "sign request")
  protected Boolean signRequest = Boolean.FALSE;

  protected RequestOptions getRequestOptions() throws Exception {
    ASN1ObjectIdentifier hashAlgOid = AlgorithmUtil.getHashAlg(hashAlgo);
    RequestOptions options = new RequestOptions();
    options.setUseNonce(usenonce.booleanValue());
    if (nonceLen != null) {
      options.setNonceLen(nonceLen);
    }
    options.setHashAlgorithmId(hashAlgOid);
    options.setSignRequest(signRequest.booleanValue());
    options.setUseHttpGetForRequest(useHttpGetForSmallRequest.booleanValue());

    if (isNotEmpty(prefSigAlgs)) {
      options.setPreferredSignatureAlgorithms(prefSigAlgs.toArray(new String[0]));
    }
    return options;
  }

}
