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

package org.xipki.ocsp.server;

import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.util.CollectionUtil;

import java.security.cert.CertificateEncodingException;
import java.util.HashSet;
import java.util.Set;

import static org.xipki.util.Args.notBlank;

/**
 * Certificate issuer filter.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class IssuerFilter {

  private final Set<String> includeSha1Fps;

  private final Set<String> excludeSha1Fps;

  public IssuerFilter(Set<X509Cert> includes, Set<X509Cert> excludes) throws CertificateEncodingException {
    if (CollectionUtil.isEmpty(includes)) {
      includeSha1Fps = null;
    } else {
      includeSha1Fps = new HashSet<>(includes.size());
      for (X509Cert include : includes) {
        includeSha1Fps.add(HashAlgo.SHA1.base64Hash(include.getEncoded()));
      }
    }

    if (CollectionUtil.isEmpty(excludes)) {
      excludeSha1Fps = null;
    } else {
      excludeSha1Fps = new HashSet<>(excludes.size());
      for (X509Cert exclude : excludes) {
        excludeSha1Fps.add(HashAlgo.SHA1.base64Hash(exclude.getEncoded()));
      }
    }
  }

  public boolean includeAll() {
    return includeSha1Fps == null && excludeSha1Fps == null;
  }

  public boolean includeIssuerWithSha1Fp(String sha1Fp) {
    notBlank(sha1Fp, "sha1Fp");
    return (includeSha1Fps == null || includeSha1Fps.contains(sha1Fp)) &&
        (excludeSha1Fps == null || !excludeSha1Fps.contains(sha1Fp));
  }

}
