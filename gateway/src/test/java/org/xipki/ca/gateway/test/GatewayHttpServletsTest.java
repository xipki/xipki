// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.ca.gateway.est.EstHttpServlet;
import org.xipki.ca.gateway.rest.RestHttpServlet;
import org.xipki.util.http.HttpConstants;
import org.xipki.util.http.XiHttpResponse;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

/**
 * The HTTP servlets of the EST and REST gateways: the method check and the forwarding of the
 * path to the responder.
 *
 * @author Lijun Liao (xipki)
 */
public class GatewayHttpServletsTest {

  private static GatewayTestEnv env;

  private static EstHttpServlet est;

  private static RestHttpServlet rest;

  @BeforeClass
  public static void init() throws Exception {
    env = new GatewayTestEnv();
    est = new EstHttpServlet(false, env.estResponder());
    rest = new RestHttpServlet(false, env.restResponder());
  }

  @AfterClass
  public static void shutdown() {
    if (env != null) {
      env.close();
    }
  }

  @Test
  public void est() throws Exception {
    Resp resp = new Resp();
    est.service(request("GET", "/cacerts"), resp);
    Assert.assertEquals(200, resp.status);
    Assert.assertTrue("CA certificates", resp.out.size() > 0);

    resp = new Resp();
    est.service(request("PUT", "/cacerts"), resp);
    Assert.assertEquals(405, resp.status);

    resp = new Resp();
    est.service(request("GET", "/unknown-command"), resp);
    Assert.assertEquals(404, resp.status);
  }

  @Test
  public void rest() throws Exception {
    Resp resp = new Resp();
    rest.service(request("GET", "/" + GatewayTestEnv.CA + "/cacert"), resp);
    Assert.assertEquals(200, resp.status);
    Assert.assertArrayEquals(env.ca().caCert().getEncoded(), resp.out.toByteArray());

    resp = new Resp();
    rest.service(request("DELETE", "/" + GatewayTestEnv.CA + "/cacert"), resp);
    Assert.assertEquals(405, resp.status);
  }

  private static TestHttpRequest request(String method, String path) {
    TestHttpRequest req = new TestHttpRequest(method);
    req.setAttribute(HttpConstants.ATTR_XIPKI_PATH, path);
    return req;
  }

  private static final class Resp implements XiHttpResponse {

    private int status = 200;

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    @Override
    public void setStatus(int sc) {
      this.status = sc;
    }

    @Override
    public void sendError(int sc) {
      this.status = sc;
    }

    @Override
    public void setContentType(String type) {
    }

    @Override
    public void addHeader(String name, String value) {
    }

    @Override
    public void setHeader(String name, String value) {
    }

    @Override
    public void setContentLength(int len) {
    }

    @Override
    public OutputStream getOutputStream() {
      return out;
    }

  }

}
