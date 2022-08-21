/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.litecaclient;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Collection of Object Identifiers.
 *
 * @author Lijun Liao
 */

public class ObjectIdentifiers {

  private static final ASN1ObjectIdentifier id_secg_scheme = new ASN1ObjectIdentifier("1.3.132.1");

  public static final ASN1ObjectIdentifier id_aes128_cbc_in_ecies = id_secg_scheme.branch("20.0");

  public static final ASN1ObjectIdentifier id_ecies_specifiedParameters = id_secg_scheme.branch("8");

  public static final ASN1ObjectIdentifier id_hmac_full_ecies = id_secg_scheme.branch("22");

  public static final ASN1ObjectIdentifier id_iso18033_kdf2 = new ASN1ObjectIdentifier("1.0.18033.2.5.2");

  public static final ASN1ObjectIdentifier id_sha1 = new ASN1ObjectIdentifier("1.3.14.3.2.26");

  public static final ASN1ObjectIdentifier id_it_certProfile = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.21");

}
