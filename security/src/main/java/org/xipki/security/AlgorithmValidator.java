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

package org.xipki.security;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Interface to check whether given algorithm is permitted.
 *
 * @author Lijun Liao
 * @since 2.1.0
 */

public interface AlgorithmValidator {

  boolean isAlgorithmPermitted(AlgorithmIdentifier algId);

  boolean isAlgorithmPermitted(String algName);

}
