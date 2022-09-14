/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.ca.sdk;

import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class EnrollCertRequestEntry {

  private BigInteger certReqId;

  private String certprofile;

  /**
   * Specifies the PKCS#10 Request. Note that the CA ddoes NOT verify the signature of
   * this request. You may also put any dummy value in the signature field.
   * The verification of CSR must be processed by the CA client calling
   * the enrolment service.
   * <p>
   * If p10req is set, the {@link #subject}, {@link #subjectPublicKey} and
   * {@link #extensions} will be ignored.
   */
  private byte[] p10req;

  /**
   * Specifies the Subject. Must be set if p10req is not present, set it to empty string
   * if empty subject is expected. Must be set if p10req is not present.
   */
  private X500NameType subject;

  /**
   * Specifies the DER-encoded SubjectPublicKeyInfo.
   * If both this and the p10req is not set, CA will generate the keypair.
   */
  private byte[] subjectPublicKey;

  /**
   * Specifies the additional extensions. Will be considered only if p10req is not present.
   */
  private byte[] extensions;

  /**
   * Epoch time in seconds of not-before.
   */
  private Long notBefore;

  /**
   * Epoch time in seconds of not-after.
   */
  private Long notAfter;

  private OldCertInfoByIssuerAndSerial oldCertIsn;

  private OldCertInfoBySubject oldCertSubject;

  public BigInteger getCertReqId() {
    return certReqId;
  }

  public void setCertReqId(BigInteger certReqId) {
    this.certReqId = certReqId;
  }

  public String getCertprofile() {
    return certprofile;
  }

  public void setCertprofile(String certprofile) {
    this.certprofile = certprofile;
  }

  public byte[] getSubjectPublicKey() {
    return subjectPublicKey;
  }

  public void setSubjectPublicKey(byte[] subjectPublicKey) {
    this.subjectPublicKey = subjectPublicKey;
  }

  public void subjectPublicKey(SubjectPublicKeyInfo subjectPublicKey)
      throws IOException {
    this.subjectPublicKey = subjectPublicKey == null ? null : subjectPublicKey.getEncoded();
  }

  public X500NameType getSubject() {
    return subject;
  }

  public void setSubject(X500NameType subject) {
    this.subject = subject;
  }

  public byte[] getExtensions() {
    return extensions;
  }

  public void setExtensions(byte[] extensions) {
    this.extensions = extensions;
  }

  public void extensions(Extensions extensions)
      throws IOException {
    this.extensions = extensions == null ? null : extensions.getEncoded();
  }

  public byte[] getP10req() {
    return p10req;
  }

  public void setP10req(byte[] p10req) {
    this.p10req = p10req;
  }

  public Long getNotBefore() {
    return notBefore;
  }

  public void setNotBefore(Long notBefore) {
    this.notBefore = notBefore;
  }

  public void notBefore(Date notBefore) {
    this.notBefore = notBefore == null ? null : notBefore.getTime() / 1000;
  }

  public Long getNotAfter() {
    return notAfter;
  }

  public void setNotAfter(Long notAfter) {
    this.notAfter = notAfter;
  }

  public void notAfter(Date notAfter) {
    this.notAfter = notAfter == null ? null : notAfter.getTime() / 1000;
  }

  public OldCertInfoByIssuerAndSerial getOldCertIsn() {
    return oldCertIsn;
  }

  public void setOldCertIsn(OldCertInfoByIssuerAndSerial oldCertIsn) {
    this.oldCertIsn = oldCertIsn;
  }

  public OldCertInfoBySubject getOldCertSubject() {
    return oldCertSubject;
  }

  public void setOldCertSubject(OldCertInfoBySubject oldCertSubject) {
    this.oldCertSubject = oldCertSubject;
  }

}
