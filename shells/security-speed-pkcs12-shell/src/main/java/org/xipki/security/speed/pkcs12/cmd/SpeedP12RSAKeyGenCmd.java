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

package org.xipki.security.speed.pkcs12.cmd;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.common.LoadExecutor;
import org.xipki.security.speed.cmd.SingleSpeedAction;
import org.xipki.security.speed.pkcs12.P12RSAKeyGenLoadTest;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "speed-rsa-gen-p12",
    description = "performance test of PKCS#12 RSA key generation")
@Service
// CHECKSTYLE:SKIP
public class SpeedP12RSAKeyGenCmd extends SingleSpeedAction {

  @Option(name = "--key-size",
      description = "keysize in bit")
  private Integer keysize = 2048;

  @Option(name = "-e",
      description = "public exponent")
  private String publicExponent = "0x10001";

  @Override
  protected LoadExecutor getTester() throws Exception {
    return new P12RSAKeyGenLoadTest(keysize, toBigInt(publicExponent), securityFactory);
  }

}
