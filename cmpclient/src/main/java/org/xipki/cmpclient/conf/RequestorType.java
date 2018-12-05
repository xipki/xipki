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

import org.xipki.util.FileOrBinary;
import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */
public class RequestorType extends ValidatableConf {

  private String name;

  private boolean signRequest;

  private RequestorType.PbmMac pbmMac;

  private RequestorType.Signature signature;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public boolean isSignRequest() {
    return signRequest;
  }

  public void setSignRequest(boolean signRequest) {
    this.signRequest = signRequest;
  }

  public RequestorType.PbmMac getPbmMac() {
    return pbmMac;
  }

  public void setPbmMac(RequestorType.PbmMac pbmMac) {
    this.pbmMac = pbmMac;
  }

  public RequestorType.Signature getSignature() {
    return signature;
  }

  public void setSignature(RequestorType.Signature signature) {
    this.signature = signature;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(name, "name");
    exactOne(pbmMac, "pbmMac", signature, "signature");
    validate(pbmMac);
    validate(signature);
  }

  public static class PbmMac extends ValidatableConf {

    private byte[] kid;

    private String sender;

    private String password;

    private String owf;

    private int iterationCount;

    private String mac;

    public byte[] getKid() {
      return kid;
    }

    public void setKid(byte[] kid) {
      this.kid = kid;
    }

    public String getSender() {
      return sender;
    }

    public void setSender(String sender) {
      this.sender = sender;
    }

    public String getPassword() {
      return password;
    }

    public void setPassword(String password) {
      this.password = password;
    }

    public String getOwf() {
      return owf;
    }

    public void setOwf(String owf) {
      this.owf = owf;
    }

    public int getIterationCount() {
      return iterationCount;
    }

    public void setIterationCount(int iterationCount) {
      this.iterationCount = iterationCount;
    }

    public String getMac() {
      return mac;
    }

    public void setMac(String mac) {
      this.mac = mac;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(kid, "kid");
      notEmpty(sender, "sender");
      notEmpty(password, "password");
      notEmpty("owf", owf);
      notEmpty(mac, "mac");
    }

  }

  public static class Signature extends ValidatableConf {

    private FileOrBinary cert;

    private String signerType;

    private String signerConf;

    public FileOrBinary getCert() {
      return cert;
    }

    public void setCert(FileOrBinary cert) {
      this.cert = cert;
    }

    public String getSignerType() {
      return signerType;
    }

    public void setSignerType(String signerType) {
      this.signerType = signerType;
    }

    public String getSignerConf() {
      return signerConf;
    }

    public void setSignerConf(String signerConf) {
      this.signerConf = signerConf;
    }

    @Override
    public void validate() throws InvalidConfException {
      validate(cert);
    }

  }

}
