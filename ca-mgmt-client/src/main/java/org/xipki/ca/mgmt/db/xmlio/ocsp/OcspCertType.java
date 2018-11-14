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

package org.xipki.ca.mgmt.db.xmlio.ocsp;

import javax.xml.stream.XMLStreamException;

import org.xipki.ca.mgmt.db.xmlio.DbiXmlWriter;
import org.xipki.ca.mgmt.db.xmlio.IdentifidDbObjectType;
import org.xipki.ca.mgmt.db.xmlio.InvalidDataObjectException;
import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspCertType extends IdentifidDbObjectType {

  public static final String TAG_PARENT = "certs";

  public static final String TAG_ROOT = "cert";

  /**
   * base64 encoded hash.
   */
  public static final String TAG_HASH = "hash";

  /**
   * issuer id.
   */
  public static final String TAG_IID = "iid";

  /**
   * not after.
   */
  public static final String TAG_NAFTER = "nafter";

  /**
   * not before.
   */
  public static final String TAG_NBEFORE = "nbefore";

  /**
   * whether revoked.
   */
  public static final String TAG_REV = "rev";

  /**
   * revocation invalidity time.
   */
  public static final String TAG_RIT = "rit";

  /**
   * revocation reason.
   */
  public static final String TAG_RR = "rr";

  /**
   * revocation time.
   */
  public static final String TAG_RT = "rt";

  /**
   * certificate serial number.
   */
  public static final String TAG_SN = "sn";

  /**
   * subject.
   */
  public static final String TAG_SUBJECT = "subject";

  /**
   * last update.
   */
  public static final String TAG_UPDATE = "update";

  private String hash;

  private Integer iid;

  private Long nafter;

  private Long nbefore;

  private Boolean rev;

  private Long rit;

  private Integer rr;

  private Long rt;

  private String sn;

  private String subject;

  private Long update;

  public String getHash() {
    return hash;
  }

  public void setHash(String hash) {
    this.hash = hash;
  }

  public Integer getIid() {
    return iid;
  }

  public void setIid(Integer iid) {
    this.iid = iid;
  }

  public Long getNafter() {
    return nafter;
  }

  public void setNafter(Long nafter) {
    this.nafter = nafter;
  }

  public Long getNbefore() {
    return nbefore;
  }

  public void setNbefore(Long nbefore) {
    this.nbefore = nbefore;
  }

  public Boolean getRev() {
    return rev;
  }

  public void setRev(Boolean rev) {
    this.rev = rev;
  }

  public Long getRit() {
    return rit;
  }

  public void setRit(Long rit) {
    this.rit = rit;
  }

  public Integer getRr() {
    return rr;
  }

  public void setRr(Integer rr) {
    this.rr = rr;
  }

  public Long getRt() {
    return rt;
  }

  public void setRt(Long rt) {
    this.rt = rt;
  }

  public String getSn() {
    return sn;
  }

  public void setSn(String sn) {
    this.sn = sn;
  }

  public String getSubject() {
    return subject;
  }

  public void setSubject(String subject) {
    this.subject = subject;
  }

  public Long getUpdate() {
    return update;
  }

  public void setUpdate(Long update) {
    this.update = update;
  }

  @Override
  public void validate() throws InvalidDataObjectException {
    super.validate();

    assertNotNull(TAG_IID, iid);

    assertNotBlank(TAG_SN, sn);
    assertNotNull(TAG_REV, rev);
    if (rev) {
      assertNotNull(TAG_RR, rr);
      assertNotNull(TAG_RT, rt);
    }
    assertNotNull(TAG_UPDATE, update);
  }

  @Override
  public void writeTo(DbiXmlWriter writer) throws InvalidDataObjectException, XMLStreamException {
    Args.notNull(writer, "writer");

    validate();

    writer.writeStartElement(TAG_ROOT);
    writeIfNotNull(writer, TAG_ID, getId());
    writeIfNotNull(writer, TAG_IID, iid);
    writeIfNotNull(writer, TAG_SN, sn);
    writeIfNotNull(writer, TAG_UPDATE, update);
    writeIfNotNull(writer, TAG_REV, rev);
    writeIfNotNull(writer, TAG_RR, rr);
    writeIfNotNull(writer, TAG_RT, rt);
    writeIfNotNull(writer, TAG_RIT, rit);

    writeIfNotNull(writer, TAG_NBEFORE, nbefore);
    writeIfNotNull(writer, TAG_NAFTER, nafter);
    writeIfNotNull(writer, TAG_SUBJECT, subject);
    writeIfNotNull(writer, TAG_HASH, hash);

    writer.writeEndElement();
    writer.writeNewline();
  }

}
