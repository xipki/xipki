// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.qa.ValidationResult;

/**
 * QA for Certprofile.
 *
 * @author Lijun Liao
 *
 */

public interface CertprofileQa {

  ValidationResult checkCert(
      byte[] certBytes, IssuerInfo issuerInfo, X500Name requestedSubject,
      SubjectPublicKeyInfo requestedPublicKey, Extensions requestedExtensions);

}
