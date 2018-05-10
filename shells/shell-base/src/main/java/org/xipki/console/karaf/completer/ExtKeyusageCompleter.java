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

package org.xipki.console.karaf.completer;

import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.AbstractEnumCompleter;
import org.xipki.security.ObjectIdentifiers;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Service
public class ExtKeyusageCompleter extends AbstractEnumCompleter {

  public ExtKeyusageCompleter() {
    String tokens = StringUtil.concat(
        ObjectIdentifiers.id_kp_clientAuth.getId(), ",",
        ObjectIdentifiers.id_kp_codeSigning.getId(), ",",
        ObjectIdentifiers.id_kp_emailProtection.getId(), ",",
        ObjectIdentifiers.id_kp_ipsecEndSystem.getId(), ",",
        ObjectIdentifiers.id_kp_ipsecTunnel.getId(), ",",
        ObjectIdentifiers.id_kp_OCSPSigning.getId(), ",",
        ObjectIdentifiers.id_kp_serverAuth.getId(), ",",
        ObjectIdentifiers.id_kp_timeStamping.getId());
    
    setTokens(tokens);
  }

}
