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

package org.xipki.ca.server;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.util.Args;

import java.math.BigInteger;
import java.util.Date;

/**
 * Certificate template data.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertTemplateData {

  private final X500Name subject;

  private final SubjectPublicKeyInfo publicKeyInfo;

  private final Date notBefore;

  private final Date notAfter;

  private final String certprofileName;

  private final boolean serverkeygen;

  private final Extensions extensions;

  private final BigInteger certReqId;

  private boolean forCrossCert;

  public CertTemplateData(
      X500Name subject, SubjectPublicKeyInfo publicKeyInfo, Date notBefore,
      Date notAfter, Extensions extensions, String certprofileName) {
    this(subject, publicKeyInfo, notBefore, notAfter, extensions, certprofileName, null, false);
  }

  public CertTemplateData(
      X500Name subject, SubjectPublicKeyInfo publicKeyInfo, Date notBefore, Date notAfter, Extensions extensions,
      String certprofileName, BigInteger certReqId, boolean serverkeygen) {
    this.publicKeyInfo = publicKeyInfo;
    this.subject = Args.notNull(subject, "subject");
    this.certprofileName = Args.toNonBlankLower(certprofileName, "certprofileName");
    this.extensions = extensions;
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    this.certReqId = certReqId;
    this.serverkeygen = serverkeygen;
  }

  public boolean isForCrossCert() {
    return forCrossCert;
  }

  public void setForCrossCert(boolean forCrossCert) {
    this.forCrossCert = forCrossCert;
  }

  public X500Name getSubject() {
    return subject;
  }

  public SubjectPublicKeyInfo getPublicKeyInfo() {
    return publicKeyInfo;
  }

  public boolean isServerkeygen() {
    return serverkeygen;
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

  public BigInteger getCertReqId() {
    return certReqId;
  }

}
