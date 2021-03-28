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

package org.xipki.ctlog.dummyserver;

import org.xipki.util.Base64;

/**
 * The CT Log servlet EC.
 *
 * @author Lijun Liao
 */
//CHECKSTYLE:SKIP
public class CtLogServletEC extends CtLogServlet {

  private static final String privateKey =
        "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCA5yyZCYzCoBiIEspXdhwWyhQOmfB6O"
      + "nhFO/g2UCMxkew==";

  private static final String publicKey =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt13k6XhtxLVQlTmmP9NVgsLF2EA2U0Blp2ug1cm7"
      + "H0ltv7NnrCRq+K87YyiggdGdrKwvDN5/DE1muN/jUditww==";

  public CtLogServletEC() {
    super(Base64.decode(privateKey), Base64.decode(publicKey));
  }

}
