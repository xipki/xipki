package org.xipki.ca.sdk;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public abstract class CertsRequest extends SdkRequest {

  private String transactionId;

  /**
   * For case to enroll more than 1 certificates in one request, default to false.
   * <ul>
   *   <li>true: either all certificates have been enrolled or failed.</li>
   *   <li>false: each certificate may have been enrolled or failed</li>
   * </ul>
   */
  private Boolean groupEnroll;

  /**
   * Whether an explicit confirm is required. Default to false.
   */
  private Boolean explicitConfirm;

  private Integer confirmWaitTimeMs;

  /**
   * Specifies how to embed the CA certificate in the response:
   */
  private CertsMode caCertMode;

  public String getTransactionId() {
    return transactionId;
  }

  public void setTransactionId(String transactionId) {
    this.transactionId = transactionId;
  }

  public Boolean getExplicitConfirm() {
    return explicitConfirm;
  }

  public void setExplicitConfirm(Boolean explicitConfirm) {
    this.explicitConfirm = explicitConfirm;
  }

  public Boolean getGroupEnroll() {
    return groupEnroll;
  }

  public void setGroupEnroll(Boolean groupEnroll) {
    this.groupEnroll = groupEnroll;
  }

  public CertsMode getCaCertMode() {
    return caCertMode;
  }

  public void setCaCertMode(CertsMode caCertMode) {
    this.caCertMode = caCertMode;
  }

  public Integer getConfirmWaitTimeMs() {
    return confirmWaitTimeMs;
  }

  public void setConfirmWaitTimeMs(Integer confirmWaitTimeMs) {
    this.confirmWaitTimeMs = confirmWaitTimeMs;
  }

}
