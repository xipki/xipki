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

package org.xipki.cmpclient.conf;

import java.util.LinkedList;
import java.util.List;

import org.xipki.util.FileOrBinary;
import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */
public class ResponderType extends ValidatableConf {

  private String name;

  private FileOrBinary cert;

  private ResponderType.PbmMac pbmMac;

  private ResponderType.Signature signature;

  public String getName() {
    return name;
  }

  public void setName(String value) {
    this.name = value;
  }

  public FileOrBinary getCert() {
    return cert;
  }

  public void setCert(FileOrBinary value) {
    this.cert = value;
  }

  public ResponderType.PbmMac getPbmMac() {
    return pbmMac;
  }

  public void setPbmMac(ResponderType.PbmMac value) {
    this.pbmMac = value;
  }

  public ResponderType.Signature getSignature() {
    return signature;
  }

  public void setSignature(ResponderType.Signature value) {
    this.signature = value;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(name, "name");
    validate(cert);
    exactOne(pbmMac, "pbmMac", signature, "signature");
    validate(pbmMac);
    validate(signature);
  }

  public static class PbmMac extends ValidatableConf {

    private List<String> owfAlgos;

    private List<String> macAlgos;

    public List<String> getOwfAlgos() {
      if (owfAlgos == null) {
        owfAlgos = new LinkedList<>();
      }
      return owfAlgos;
    }

    public void setOwfAlgos(List<String> owfAlgos) {
      this.owfAlgos = owfAlgos;
    }

    public List<String> getMacAlgos() {
      if (macAlgos == null) {
        macAlgos = new LinkedList<>();
      }
      return macAlgos;
    }

    public void setMacAlgos(List<String> macAlgos) {
      this.macAlgos = macAlgos;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(owfAlgos, "owfAlgos");
      notEmpty(macAlgos, "macAlgos");
    }

  }

  public static class Signature extends ValidatableConf {

    private List<String> signatureAlgos;

    public List<String> getSignatureAlgos() {
      if (signatureAlgos == null) {
        signatureAlgos = new LinkedList<>();
      }
      return signatureAlgos;
    }

    public void setSignatureAlgos(List<String> signatureAlgos) {
      this.signatureAlgos = signatureAlgos;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(signatureAlgos, "signatureAlgos");
    }

  }

}
