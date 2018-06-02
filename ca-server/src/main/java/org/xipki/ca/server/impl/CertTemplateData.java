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

package org.xipki.ca.server.impl;

import java.util.Date;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertTemplateData {

  private final X500Name subject;

  private final SubjectPublicKeyInfo publicKeyInfo;

  private final Date notBefore;

  private final Date notAfter;

  private final String certprofileName;

  private final String genkeyType;

  private final Extensions extensions;

  private final ASN1Integer certReqId;

  public CertTemplateData(X500Name subject, SubjectPublicKeyInfo publicKeyInfo, Date notBefore,
      Date notAfter, Extensions extensions, String certprofileName) {
    this(subject, null, publicKeyInfo, notBefore, notAfter, extensions, certprofileName, null);
  }

  public CertTemplateData(X500Name subject, String keygenType, SubjectPublicKeyInfo publicKeyInfo,
      Date notBefore, Date notAfter, Extensions extensions, String certprofileName,
      ASN1Integer certReqId) {
    this.genkeyType = StringUtil.isBlank(keygenType) ? null : keygenType;
    if (this.genkeyType == null) {
      ParamUtil.requireNonNull("publicKeyInfo", publicKeyInfo);
    }

    this.publicKeyInfo = publicKeyInfo;
    this.subject = ParamUtil.requireNonNull("subject", subject);
    this.certprofileName = ParamUtil.requireNonBlank("certprofileName", certprofileName)
        .toLowerCase();
    this.extensions = extensions;
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    this.certReqId = certReqId;
  }

  public X500Name getSubject() {
    return subject;
  }

  public SubjectPublicKeyInfo getPublicKeyInfo() {
    return publicKeyInfo;
  }

  public String getGenkeyType() {
    return genkeyType;
  }

  public Date getNotBefore() {
    return notBefore;
  }

  public Date getNotAfter() {
    return notAfter;
  }

  public String getCertprofileName() {
    return certprofileName;
  }

  public Extensions getExtensions() {
    return extensions;
  }

  public ASN1Integer getCertReqId() {
    return certReqId;
  }

}
