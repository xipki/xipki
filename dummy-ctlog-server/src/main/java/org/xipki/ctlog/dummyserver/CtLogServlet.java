/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * TODO.
 * @author Lijun Liao
 */
@SuppressWarnings("serial")
public abstract class CtLogServlet extends HttpServlet {

  public static class CtLogServlet1 extends CtLogServlet {

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

  public static class CtLogServlet2 extends CtLogServlet {

    private String id;

    public CtLogServlet2() {
      byte[] tmpId = new byte[32];
      Arrays.fill(tmpId, (byte) 0x22);
      id = Base64.getEncoder().encodeToString(tmpId);
    }

    @Override
    protected String getLogId() {
      return id;
    }

  }

  private final SecureRandom random = new SecureRandom();

  protected abstract String getLogId();

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    StringBuilder sb = new StringBuilder();
    sb.append("{\n");
    sb.append("\t\"sct_version\":0,\n");
    sb.append("\t\"id\":\"").append(getLogId()).append("\",\n");
    sb.append("\t\"timestamp\":").append(System.currentTimeMillis()).append(",\n");
    sb.append("\t\"signature\":\"").append(buildEncodedDigitallySigned()).append("\"\n");
    sb.append("}\n");

    resp.setContentType("application/json");
    byte[] respContent = sb.toString().getBytes();
    resp.setContentLengthLong(respContent.length);
    resp.getOutputStream().write(respContent);
    resp.setStatus(HttpServletResponse.SC_OK);
  }

  private String buildEncodedDigitallySigned() throws IOException {
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    os.write(4); // Hash Algorithm
    os.write(3); // Signature Algorithm
    os.write(new byte[] {0x00, 0x46});
    os.write(new byte[] {0x30, 0x44});
    os.write(new byte[] {0x02, 0x20});
    // ECDSA r of 32 bytes
    byte[] r = new byte[32];
    random.nextBytes(r);
    r[0] = (byte) (0x7F & r[0]);
    os.write(r);

    // ECDSA s of 32 bytes
    os.write(new byte[] {0x02, 0x20});
    byte[] s = new byte[32];
    random.nextBytes(s);
    s[0] = (byte) (0x7F & s[0]);
    os.write(s);

    byte[] encoded = os.toByteArray();
    return new String(Base64.getEncoder().encode(encoded));
  }

}
