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

package org.xipki.ca.client;

import java.security.SecureRandom;

import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class PbmMacClientCmpRequestor implements ClientCmpRequestor {

  private final SecureRandom random = new SecureRandom();

  private final GeneralName name;

  private final boolean signRequest;

  private final char[] password;

  // CHECKSTYLE:SKIP
  private final byte[] senderKID;

  private final AlgorithmIdentifier owf;

  private final int iterationCount;

  private final AlgorithmIdentifier mac;

  public PbmMacClientCmpRequestor(boolean signRequest, X500Name x500name, char[] password,
      // CHECKSTYLE:SKIP
      byte[] senderKID, AlgorithmIdentifier owf, int iterationCount, AlgorithmIdentifier mac) {
    this.signRequest = signRequest;
    this.name = new GeneralName(x500name);
    this.password = password;
    this.senderKID = senderKID;
    this.owf = owf;
    this.iterationCount = iterationCount;
    this.mac = mac;
  }

  @Override
  public GeneralName getName() {
    return name;
  }

  public char[] getPassword() {
    return password;
  }

  // CHECKSTYLE:SKIP
  public byte[] getSenderKID() {
    return senderKID;
  }

  public PBMParameter getParameter() {
    return new PBMParameter(randomSalt(), owf, iterationCount, mac);
  }

  public AlgorithmIdentifier getOwf() {
    return owf;
  }

  public int getIterationCount() {
    return iterationCount;
  }

  public AlgorithmIdentifier getMac() {
    return mac;
  }

  @Override
  public boolean signRequest() {
    return signRequest;
  }

  private byte[] randomSalt() {
    byte[] bytes = new byte[64];
    random.nextBytes(bytes);
    return bytes;
  }
}
