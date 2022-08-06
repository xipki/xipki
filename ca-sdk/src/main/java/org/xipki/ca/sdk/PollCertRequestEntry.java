package org.xipki.ca.sdk;

public class PollCertRequestEntry {

  /*
   * In SCEP: this field is null.
   */
  private Integer id;

  private X500NameType subject;

  public Integer getId() {
    return id;
  }

  public void setId(Integer id) {
    this.id = id;
  }

  public X500NameType getSubject() {
    return subject;
  }

  public void setSubject(X500NameType subject) {
    this.subject = subject;
  }

}
