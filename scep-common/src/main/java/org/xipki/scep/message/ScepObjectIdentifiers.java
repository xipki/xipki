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

package org.xipki.scep.message;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * TODO.
 * @author Lijun Liao
 */

public class ScepObjectIdentifiers {

  public static final ASN1ObjectIdentifier ID_VERISIGN =
      new ASN1ObjectIdentifier("2.16.840.1.113733");

  public static final ASN1ObjectIdentifier ID_PKI = ID_VERISIGN.branch("1");

  public static final ASN1ObjectIdentifier ID_ATTRIBUTES = ID_PKI.branch("9");

  public static final ASN1ObjectIdentifier ID_TRANSACTION_ID = ID_ATTRIBUTES.branch("7");

  public static final ASN1ObjectIdentifier ID_MESSAGE_TYPE = ID_ATTRIBUTES.branch("2");

  public static final ASN1ObjectIdentifier ID_PKI_STATUS = ID_ATTRIBUTES.branch("3");

  public static final ASN1ObjectIdentifier ID_FAILINFO = ID_ATTRIBUTES.branch("4");

  public static final ASN1ObjectIdentifier ID_SENDER_NONCE = ID_ATTRIBUTES.branch("5");

  public static final ASN1ObjectIdentifier ID_RECIPIENT_NONCE = ID_ATTRIBUTES.branch("6");

  private ScepObjectIdentifiers() {
  }
}
