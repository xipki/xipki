/*
 * Copyright 2014 xipki.org
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

package org.xipki.remotep11.common;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

public class RemoteP11Constants {
	// just dummy, for intern purpose
	private static final ASN1ObjectIdentifier id_remotep11      = new ASN1ObjectIdentifier("1.2.3.4.5.6");
	
	public static final ASN1ObjectIdentifier id_version         = id_remotep11.branch("1");
	public static final ASN1ObjectIdentifier id_pso_rsa_x509    = id_remotep11.branch("2");
	public static final ASN1ObjectIdentifier id_pso_rsa_pkcs    = id_remotep11.branch("3");
	public static final ASN1ObjectIdentifier id_pso_ecdsa       = id_remotep11.branch("4");
	public static final ASN1ObjectIdentifier id_get_publickey   = id_remotep11.branch("5");
	public static final ASN1ObjectIdentifier id_get_certificate = id_remotep11.branch("6");
	public static final ASN1ObjectIdentifier id_list_slots      = id_remotep11.branch("7");
	public static final ASN1ObjectIdentifier id_list_keylabels  = id_remotep11.branch("8");
	
	public static final GeneralName CMP_SERVER = 
			new GeneralName(GeneralName.uniformResourceIdentifier, "http://xipki.org/remotep11/server");
	public static final GeneralName CMP_CLIENT = 
			new GeneralName(GeneralName.uniformResourceIdentifier, "http://xipki.org/remotep11/client");

}
