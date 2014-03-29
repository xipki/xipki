/*
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This work is part of XiPKI, owned by Lijun Liao (lijun.liao@gmail.com)
 *
 */

package org.xipki.ca.server;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class ObjectIdentifiers {
	private static final ASN1ObjectIdentifier id_at = new ASN1ObjectIdentifier("2.5.4");
	
	public static final ASN1ObjectIdentifier id_at_commonName = id_at.branch("3");
	public static final ASN1ObjectIdentifier id_at_surName = id_at.branch("4");
	public static final ASN1ObjectIdentifier id_at_serialNumber = id_at.branch("5");
	public static final ASN1ObjectIdentifier id_at_countryName = id_at.branch("6");
	public static final ASN1ObjectIdentifier id_at_localityName = id_at.branch("7");
	public static final ASN1ObjectIdentifier id_at_stateOrProvinceName = id_at.branch("8");
	public static final ASN1ObjectIdentifier id_at_street = id_at.branch("9");
	public static final ASN1ObjectIdentifier id_at_organizationName = id_at.branch("10");
	public static final ASN1ObjectIdentifier id_at_organizationUnitName = id_at.branch("11");
	public static final ASN1ObjectIdentifier id_at_title = id_at.branch("12");
	public static final ASN1ObjectIdentifier id_at_givenName = id_at.branch("42");
	public static final ASN1ObjectIdentifier id_at_postalCode = id_at.branch("17");

	public static final ASN1ObjectIdentifier id_tsl_kp_tslSigning    = new ASN1ObjectIdentifier("0.4.0.2231.3.0");
	
	private static final ASN1ObjectIdentifier id_pkix = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");
	private static final ASN1ObjectIdentifier id_kp                  = id_pkix.branch("3");
	public static final ASN1ObjectIdentifier id_kp_serverAuth        = id_kp.branch("1");
	public static final ASN1ObjectIdentifier id_kp_clientAuth        = id_kp.branch("2");
	public static final ASN1ObjectIdentifier id_kp_ocsp              = id_pkix.branch("1.48.1");			
	public static final ASN1ObjectIdentifier id_extension_pkix_ocsp_nocheck = id_pkix.branch("48.1.5");	
}
