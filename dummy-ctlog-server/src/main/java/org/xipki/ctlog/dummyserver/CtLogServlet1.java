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

import java.util.Arrays;
import java.util.Base64;

/**
 * The CT Log servlet 1.
 *
 * @author Lijun Liao
 */
@SuppressWarnings("serial")
public class CtLogServlet1 extends CtLogServlet {

  private String id;

  public CtLogServlet1() {
    byte[] tmpId = new byte[32];
    Arrays.fill(tmpId, (byte) 0x11);
    id = Base64.getEncoder().encodeToString(tmpId);
  }

  @Override
  protected String getLogId() {
    return id;
  }

}
