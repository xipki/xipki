package org.xipki.ca.gateway.conf;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class CaNameSignerConf {

  private String name;

  private SignerConf signer;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public SignerConf getSigner() {
    return signer;
  }

  public void setSigner(SignerConf signer) {
    this.signer = signer;
  }
}
