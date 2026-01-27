// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.CollectionUtil;

import java.util.HashSet;
import java.util.Set;

/**
 * Certificate issuer filter.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class IssuerFilter {

  private final Set<String> includeSha1Fps;

  private final Set<String> excludeSha1Fps;

  public IssuerFilter(Set<X509Cert> includes, Set<X509Cert> excludes) {
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
    Args.notBlank(sha1Fp, "sha1Fp");
    return (includeSha1Fps == null || includeSha1Fps.contains(sha1Fp)) &&
        (excludeSha1Fps == null || !excludeSha1Fps.contains(sha1Fp));
  }

}
