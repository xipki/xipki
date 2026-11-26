// License Apache License 2.0

package org.xipki.mgmt.web.dto;

import org.xipki.mgmt.web.core.*;

/**
 * Generic DTO for entities with name/type/conf pattern: CertprofileEntry, PublisherEntry,
 * KeypairGenEntry, SignerEntry, RequestorEntry
 *
 * @author palos
 */
public class NameTypeConfDto extends StrictRequest {

  public String name;
  public String type;
  public String conf;
  public boolean replaceConf;
  public boolean confHidden;
  public boolean faulty;
  // For signer only
  public String base64Cert;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public String getConf() {
    return conf;
  }

  public void setConf(String conf) {
    this.conf = conf;
  }

  public boolean isReplaceConf() {
    return replaceConf;
  }

  public void setReplaceConf(boolean replaceConf) {
    this.replaceConf = replaceConf;
  }

  public boolean isConfHidden() {
    return confHidden;
  }

  public void setConfHidden(boolean confHidden) {
    this.confHidden = confHidden;
  }

  public boolean isFaulty() {
    return faulty;
  }

  public void setFaulty(boolean faulty) {
    this.faulty = faulty;
  }

  public String getBase64Cert() {
    return base64Cert;
  }

  public void setBase64Cert(String base64Cert) {
    this.base64Cert = base64Cert;
  }
}
