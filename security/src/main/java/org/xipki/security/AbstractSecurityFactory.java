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

package org.xipki.security;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class AbstractSecurityFactory implements SecurityFactory {

  @Override
  public ConcurrentContentSigner createSigner(String type, SignerConf conf, X509Certificate cert)
      throws ObjectCreationException {
    X509Certificate[] certs = (cert == null) ? null : new X509Certificate[]{cert};
    return createSigner(type, conf, certs);
  }

  @Override
  public ContentVerifierProvider getContentVerifierProvider(X509Certificate cert)
      throws InvalidKeyException {
    ParamUtil.requireNonNull("cert", cert);
    return getContentVerifierProvider(cert.getPublicKey());
  }

  @Override
  public ContentVerifierProvider getContentVerifierProvider(X509CertificateHolder cert)
      throws InvalidKeyException {
    ParamUtil.requireNonNull("cert", cert);
    PublicKey publicKey = generatePublicKey(cert.getSubjectPublicKeyInfo());
    return getContentVerifierProvider(publicKey);
  }

}
