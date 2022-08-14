package org.xipki.ca.gateway.conf;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class CaNameSignersConf {

  private SignerConf default_;

  private CaNameSignerConf[] signers;

  public SignerConf getDefault() {
    return default_;
  }

  public void setDefault(SignerConf default_) {
    this.default_ = default_;
  }

  public CaNameSignerConf[] getSigners() {
    return signers;
  }

  public void setSigners(CaNameSignerConf[] signers) {
    this.signers = signers;
  }
}
