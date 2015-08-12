/*
 * Copyright (c) 2015 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.scep4j.message;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * @author Lijun Liao
 */

public class ScepObjectIdentifiers
{
    public static final ASN1ObjectIdentifier id_VeriSign = new ASN1ObjectIdentifier("2.16.840.1.113733");
    public static final ASN1ObjectIdentifier id_pki = id_VeriSign.branch("1");
    public static final ASN1ObjectIdentifier id_attributes = id_pki.branch("9");
    public static final ASN1ObjectIdentifier id_transactionID = id_attributes.branch("7");
    public static final ASN1ObjectIdentifier id_messageType = id_attributes.branch("2");
    public static final ASN1ObjectIdentifier id_pkiStatus = id_attributes.branch("3");
    public static final ASN1ObjectIdentifier id_failInfo = id_attributes.branch("4");
    public static final ASN1ObjectIdentifier id_senderNonce = id_attributes.branch("5");
    public static final ASN1ObjectIdentifier id_recipientNonce = id_attributes.branch("6");
}
