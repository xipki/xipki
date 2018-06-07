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

package org.xipki.shell.completer;

import java.util.Arrays;

import org.apache.karaf.shell.api.action.lifecycle.Service;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Service
// CHECKSTYLE:SKIP
public class ECCurveNameCompleter extends AbstractEnumCompleter {

  public ECCurveNameCompleter() {
    setTokens(Arrays.asList("b-163", "b-233", "b-283", "b-409", "b-571",
        "brainpoolp160r1", "brainpoolp160t1", "brainpoolp192r1", "brainpoolp192t1",
        "brainpoolp224r1", "brainpoolp224t1", "brainpoolp256r1", "brainpoolp256t1",
        "brainpoolp320r1", "brainpoolp320t1", "brainpoolp384r1", "brainpoolp384t1",
        "brainpoolp512r1", "brainpoolp512t1",
        "c2pnb163v1", "c2pnb163v2", "c2pnb163v3", "c2pnb176w1", "c2pnb208w1", "c2pnb272w1",
        "c2pnb304w1", "c2pnb368w1", "c2tnb191v1", "c2tnb191v2", "c2tnb191v3", "c2tnb239v1",
        "c2tnb239v2", "c2tnb239v3", "c2tnb359v1", "c2tnb431r1", "frp256v1",
        "k-163", "k-233", "k-283", "k-409", "k-571", "p-192", "p-224", "p-256", "p-384", "p-521",
        "prime192v1", "prime192v2", "prime192v3", "prime239v1", "prime239v2", "prime239v3",
        "prime256v1",
        "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1", "secp160r1", "secp160r2",
        "secp192k1", "secp192r1", "secp224k1", "secp224r1", "secp256k1", "secp256r1", "secp384r1",
        "secp521r1", "sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1", "sect163r1",
        "sect163r2", "sect193r1", "sect193r2", "sect233k1", "sect233r1", "sect239k1", "sect283k1",
        "sect283r1", "sect409k1", "sect409r1", "sect571k1", "sect571r1", "sm2p256v1", "wapip192v1"
        ));
  }

}
