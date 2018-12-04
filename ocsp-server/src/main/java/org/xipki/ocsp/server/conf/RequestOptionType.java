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

package org.xipki.ocsp.server.conf;

import java.util.LinkedList;
import java.util.List;

import org.xipki.ocsp.server.conf.OcspserverType.ValidationModel;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */
public class RequestOptionType extends ValidatableConf {

  /**
   * Whether to support HTTP GET for small request.
   * The default is false.
   */
  private boolean supportsHttpGet = false;

  /**
   * Maximal count of entries contained in one RequestList.
   */
  private int maxRequestListCount;

  /**
   * Maximal size in byte of a request.
   */
  private int maxRequestSize;

  /**
   * version of the request, current support values are v1.
   */
  private List<String> versions;

  private NonceType nonce;

  private boolean signatureRequired;

  private boolean validateSignature;

  private List<String> hashAlgorithms;

  private RequestOptionType.CertpathValidation certpathValidation;

  private String name;

  public boolean isSupportsHttpGet() {
    return supportsHttpGet;
  }

  public void setSupportsHttpGet(boolean supportsHttpGet) {
    this.supportsHttpGet = supportsHttpGet;
  }

  public int getMaxRequestListCount() {
    return maxRequestListCount;
  }

  public void setMaxRequestListCount(int maxRequestListCount) {
    this.maxRequestListCount = maxRequestListCount;
  }

  public int getMaxRequestSize() {
    return maxRequestSize;
  }

  public void setMaxRequestSize(int maxRequestSize) {
    this.maxRequestSize = maxRequestSize;
  }

  public List<String> getVersions() {
    return versions;
  }

  public void setVersions(List<String> versions) {
    this.versions = versions;
  }

  public NonceType getNonce() {
    return nonce;
  }

  public void setNonce(NonceType nonce) {
    this.nonce = nonce;
  }

  public boolean isSignatureRequired() {
    return signatureRequired;
  }

  public void setSignatureRequired(boolean signatureRequired) {
    this.signatureRequired = signatureRequired;
  }

  public boolean isValidateSignature() {
    return validateSignature;
  }

  public void setValidateSignature(boolean validateSignature) {
    this.validateSignature = validateSignature;
  }

  public List<String> getHashAlgorithms() {
    if (hashAlgorithms == null) {
      hashAlgorithms = new LinkedList<>();
    }
    return hashAlgorithms;
  }

  public void setHashAlgorithms(List<String> hashAlgorithms) {
    this.hashAlgorithms = hashAlgorithms;
  }

  public RequestOptionType.CertpathValidation getCertpathValidation() {
    return certpathValidation;
  }

  public void setCertpathValidation(RequestOptionType.CertpathValidation certpathValidation) {
    this.certpathValidation = certpathValidation;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(versions, "versions");
    notNull(nonce, "nonce");
    validate(nonce);
    validate(certpathValidation);
  }

  public static class CertpathValidation extends ValidatableConf {

    private ValidationModel validationModel;

    private CertCollectionType trustAnchors;

    private CertCollectionType certs;

    public ValidationModel getValidationModel() {
      return validationModel;
    }

    public void setValidationModel(ValidationModel validationModel) {
      this.validationModel = validationModel;
    }

    public CertCollectionType getTrustAnchors() {
      return trustAnchors;
    }

    public void setTrustAnchors(CertCollectionType trustAnchors) {
      this.trustAnchors = trustAnchors;
    }

    public CertCollectionType getCerts() {
      return certs;
    }

    public void setCerts(CertCollectionType certs) {
      this.certs = certs;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(validationModel, "validationModel");
      notNull(trustAnchors, "trustAnchors");
      validate(trustAnchors);
      validate(certs);
    }

  }

}
