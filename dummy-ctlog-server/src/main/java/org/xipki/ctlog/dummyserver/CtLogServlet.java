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
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * HTTP servlet of CT Log server.
 *
 * @author Lijun Liao
 */
@SuppressWarnings("serial")
public abstract class CtLogServlet extends HttpServlet {

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
  } // method doPost

  private String buildEncodedDigitallySigned() throws IOException {
    // ECDSA r of 32 bytes
    byte[] r = new byte[32];
    random.nextBytes(r);
    r = new BigInteger(1, r).toByteArray();

    // ECDSA s of 32 bytes
    byte[] s = new byte[32];
    random.nextBytes(s);
    s = new BigInteger(1, s).toByteArray();

    ByteArrayOutputStream os = new ByteArrayOutputStream();
    os.write(4); // Hash Algorithm
    os.write(3); // Signature Algorithm

    os.write(0x00);
    os.write(6 + r.length + s.length);
    os.write(0x30);
    os.write(4 + r.length + s.length);

    os.write(0x02);
    os.write(r.length);
    os.write(r);

    os.write(0x02);
    os.write(s.length);
    os.write(s);

    byte[] encoded = os.toByteArray();
    return new String(Base64.getEncoder().encode(encoded));
  } // method buildEncodedDigitallySigned

}
