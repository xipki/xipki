// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.client;

import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.util.Args;

import java.util.Arrays;
import java.util.List;

/**
 * OCSP request options.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class RequestOptions {

  private boolean signRequest;

  private boolean useNonce = true;

  private int nonceLen = 8;

  private boolean allowNoNonceInResponse;

  private boolean useHttpGetForRequest;

  private HashAlgo hashAlgorithm = HashAlgo.SHA256;

  private List<SignAlgo> preferredSignatureAlgorithms;

  public RequestOptions() {
  }

  public boolean isUseNonce() {
    return useNonce;
  }

  public void setUseNonce(boolean useNonce) {
    this.useNonce = useNonce;
  }

  public int getNonceLen() {
    return nonceLen;
  }

  public void setNonceLen(int nonceLen) {
    this.nonceLen = Args.positive(nonceLen, "nonceLen");
  }

  public HashAlgo getHashAlgorithm() {
    return hashAlgorithm;
  }

  public void setHashAlgorithm(HashAlgo hashAlgorithm) {
    this.hashAlgorithm = hashAlgorithm;
  }

  public List<SignAlgo> getPreferredSignatureAlgorithms() {
    return preferredSignatureAlgorithms;
  }

  public void setPreferredSignatureAlgorithms(SignAlgo[] preferredSignatureAlgorithms) {
    this.preferredSignatureAlgorithms = Arrays.asList(preferredSignatureAlgorithms);
  }

  public boolean isUseHttpGetForRequest() {
    return useHttpGetForRequest;
  }

  public void setUseHttpGetForRequest(boolean useHttpGetForRequest) {
    this.useHttpGetForRequest = useHttpGetForRequest;
  }

  public boolean isSignRequest() {
    return signRequest;
  }

  public void setSignRequest(boolean signRequest) {
    this.signRequest = signRequest;
  }

  public boolean isAllowNoNonceInResponse() {
    return allowNoNonceInResponse;
  }

  public void setAllowNoNonceInResponse(boolean allowNoNonceInResponse) {
    this.allowNoNonceInResponse = allowNoNonceInResponse;
  }

}
