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

package org.xipki.qa.shell.security.pkcs12;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.qa.security.P12DSAKeyGenSpeed;
import org.xipki.qa.shell.security.SingleSpeedAction;
import org.xipki.util.BenchmarkExecutor;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "speed-dsa-gen-p12",
    description = "performance test of PKCS#12 DSA key generation")
@Service
// CHECKSTYLE:SKIP
public class SpeedP12DSAKeyGenAction extends SingleSpeedAction {

  @Option(name = "--plen", description = "bit length of the prime")
  private Integer plen = 2048;

  @Option(name = "--qlen", description = "bit length of the sub-prime")
  private Integer qlen;

  @Override
  protected BenchmarkExecutor getTester() throws Exception {
    if (qlen == null) {
      qlen = (plen >= 2048) ? 256 : 160;
    }
    return new P12DSAKeyGenSpeed(plen, qlen, securityFactory);
  }

}
