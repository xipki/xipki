// Copyright (c) 2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

/**
 * PKCS#11 constants category enumerations.
 *
 * @author Lijun Liao (xipki)
 */
public enum Category {
  /**
   * attribute
   */
  CKA("CKA"),
  /**
   * certificate type
   */
  CKC("CKC"),
  /**
   * key derivation function
   */
  CKD("CKD"),
  /**
   * bit flag of mechanism info
   */
  CKF_MECHANISM("CKF"),
  /**
   * bit flag of OTP
   */
  CKF_OTP("CKF"),
  /**
   * bit flag of session info
   */
  CKF_SESSION("CKF"),
  /**
   * bit flag of slot info
   */
  CKF_SLOT("CKF"),
  /**
   * bit flag of token info
   */
  CKF_TOKEN("CKF"),
  /**
   * generator
   */
  CKG_GENERATOR("CKG"),
  /**
   * mask generation function
   */
  CKG_MGF("CKG"),
  /**
   * hardware feature
   */
  CKH("CKH"),
  /**
   * PQC CK_HEDGE_TYPE
   */
  CKH_HEDGE("CKH_HEDGE"),
  /**
   * key type
   */
  CKK("CKK"),
  /**
   * mechanism type
   */
  CKM("CKM"),
  /**
   * object class
   */
  CKO("CKO"),
  /**
   * profile ID
   */
  CKP_PROFILE_ID("CKP"),
  /**
   * parameter set for ML-DSA
   */
  CKP_ML_DSA("CKP"),
  /**
   * parameter set for SLH-DSA
   */
  CKP_SLH_DSA("CKP"),
  /**
   * parameter set for ML-KEM
   */
  CKP_ML_KEM("CKP"),
  /**
   * pseudo-random function
   */
  CKP_PRF("CKP"),
  /**
   * return value
   */
  CKR("CKR"),
  /**
   * session state
   */
  CKS("CKS"),
  /**
   * user
   */
  CKU("CKU"),
  /**
   * salt/encoding parameter source
   */
  CKZ("CKZ");

  private final String prefix;

  Category(String prefix) {
    this.prefix = prefix;
  }

  public String getPrefix() {
    return prefix;
  }

}
