// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.xipki.util.Args;

/**
 * Control of the CertificatePolicyQualifier (in the extension CertificatePolicies).
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CertificatePolicyQualifier {

  private final String cpsUri;

  private final String userNotice;

  private CertificatePolicyQualifier(String cpsUri, String userNotice) {
    this.cpsUri = cpsUri;
    this.userNotice = userNotice;
  }

  public String getCpsUri() {
    return cpsUri;
  }

  public String getUserNotice() {
    return userNotice;
  }

  public static CertificatePolicyQualifier getInstanceForUserNotice(String userNotice) {
    Args.notNull(userNotice, "userNotice");
    Args.range(userNotice.length(), "userNotice.length", 1, 200);
    return new CertificatePolicyQualifier(null, userNotice);
  }

  public static CertificatePolicyQualifier getInstanceForCpsUri(String cpsUri) {
    return new CertificatePolicyQualifier(Args.notNull(cpsUri, "cpsUri"), null);
  }

}
