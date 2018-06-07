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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.karaf.shell.api.action.lifecycle.Service;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Service
public class ExtKeyusageCompleter extends AbstractEnumCompleter {

  private static final Map<String, String> nameToIdMap = new HashMap<>();

  private static final Set<String> tokens;

  static {
    Map<String, String> map = new HashMap<>();
    map.put("serverAuth",      "1.3.6.1.5.5.7.3.1");
    map.put("clientAuth",      "1.3.6.1.5.5.7.3.2");
    map.put("codeSigning",     "1.3.6.1.5.5.7.3.3");
    map.put("emailProtection", "1.3.6.1.5.5.7.3.4");
    map.put("ipsecEndSystem",  "1.3.6.1.5.5.7.3.5");
    map.put("ipsecTunnel",     "1.3.6.1.5.5.7.3.6");
    map.put("timeStamping",    "1.3.6.1.5.5.7.3.8");
    map.put("OCSPSigning",     "1.3.6.1.5.5.7.3.9");

    tokens = new HashSet<>(map.keySet());

    for (String name : map.keySet()) {
      nameToIdMap.put(name.toLowerCase(), map.get(name));
    }
  }

  public static String getIdForUsageName(String name) {
    return nameToIdMap.get(name.toLowerCase());
  }

  public ExtKeyusageCompleter() {
    setTokens(tokens);
  }

}
