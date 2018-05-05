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

package org.xipki.security.speed.pkcs11.cmd;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.common.LoadExecutor;
import org.xipki.console.karaf.completer.ECCurveNameCompleter;
import org.xipki.security.speed.cmd.completer.ECDSASigAlgCompleter;
import org.xipki.security.speed.pkcs11.P11ECSignSpeed;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "speed-ec-sign-p11",
    description = "performance test of PKCS#11 EC signature creation")
@Service
// CHECKSTYLE:SKIP
public class SpeedP11ECSignCmd extends SpeedP11Action {

  @Option(name = "--curve", required = true,
      description = "EC curve name\n(required)")
  @Completion(ECCurveNameCompleter.class)
  private String curveName;

  @Option(name = "--sig-algo", required = true,
      description = "signature algorithm\n(required)")
  @Completion(ECDSASigAlgCompleter.class)
  private String sigAlgo;

  @Override
  protected LoadExecutor getTester() throws Exception {
    return new P11ECSignSpeed(securityFactory, getSlot(), sigAlgo, curveName);
  }

}
