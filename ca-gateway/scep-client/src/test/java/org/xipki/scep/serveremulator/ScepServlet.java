// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.serveremulator;

import com.sun.net.httpserver.HttpExchange;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.scep.message.CaCaps;
import org.xipki.scep.message.NextCaMessage;
import org.xipki.scep.transaction.Operation;
import org.xipki.scep.util.ScepConstants;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.ConfPairs;
import org.xipki.util.IoUtil;
import org.xipki.util.exception.DecodeException;

import java.io.EOFException;
import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

/**
 * URL http://host:port/scep/&lt;name&gt;/&lt;profile-alias&gt;/pkiclient.exe
 *
 * @author Lijun Liao (xipki)
 */

public class ScepServlet {

  public static final int SC_OK = 200;

  public static final int SC_BAD_REQUEST = 400;

  public static final int SC_FORBIDDEN = 403;

  public static final int SC_METHOD_NOT_ALLOWED = 405;

  public static final int SC_INTERNAL_SERVER_ERROR = 500;

  private static final Logger LOG = LoggerFactory.getLogger(ScepServlet.class);

  private static final String CT_RESPONSE = ScepConstants.CT_PKI_MESSAGE;

  private final SimulatorScepResponder responder;

  public ScepServlet(SimulatorScepResponder responder) {
    this.responder = Args.notNull(responder, "responder");
  }

  protected void service(HttpExchange exchange) throws IOException {
    boolean post;

    String method = exchange.getRequestMethod();
    if ("GET".equals(method)) {
      post = false;
    } else if ("POST".equals(method)) {
      post = true;
    } else {
      sendError(exchange, SC_METHOD_NOT_ALLOWED);
      return;
    }

    String auditMessage = null;

    try {
      CaCaps caCaps = responder.getCaCaps();
      if (post && !caCaps.supportsPost()) {
        auditMessage = "HTTP POST is not supported";
        sendError(exchange, SC_BAD_REQUEST);
        return;
      }

      URI reqUri = exchange.getRequestURI();
      String query = reqUri.getQuery();
      Map<String, String> params = new HashMap<>();
      if (query != null && !query.isEmpty()) {
        int startIndex = 0;
        while (true) {
          int index = query.indexOf('&', startIndex);
          String token = query.substring(startIndex, index == -1 ? query.length() : index);
          int index2 = token.indexOf('=');
          if (index2 != -1) {
            params.put(token.substring(0, index2), token.substring(index2 + 1));
          }

          if (index == -1) {
            break;
          }

          startIndex = index + 1;
        }
      }

      String operation = params.get("operation");
      if ("PKIOperation".equalsIgnoreCase(operation)) {
        CMSSignedData reqMessage;
        // parse the request
        try {
          byte[] content = post
              ? IoUtil.readAllBytesAndClose(exchange.getRequestBody())
              : Base64.decode(params.get("message"));

          reqMessage = new CMSSignedData(content);
        } catch (Exception ex) {
          auditMessage = "invalid request";
          sendError(exchange, SC_BAD_REQUEST);
          return;
        }

        ContentInfo ci;
        try {
          ci = responder.servicePkiOperation(reqMessage);
        } catch (DecodeException ex) {
          auditMessage = "could not decrypt and/or verify the request";
          sendError(exchange, SC_BAD_REQUEST);
          return;
        } catch (CaException ex) {
          ex.printStackTrace();
          auditMessage = "system internal error";
          sendError(exchange, SC_INTERNAL_SERVER_ERROR);
          return;
        }
        byte[] respBytes = ci.getEncoded();
        sendToResponse(exchange, CT_RESPONSE, respBytes);
      } else if (Operation.GetCACaps.getCode().equalsIgnoreCase(operation)) {
        // CA-Ident is ignored
        byte[] caCapsBytes = responder.getCaCaps().getBytes();
        sendToResponse(exchange, ScepConstants.CT_TEXT_PLAIN, caCapsBytes);
      } else if (Operation.GetCACert.getCode().equalsIgnoreCase(operation)) {
        // CA-Ident is ignored
        byte[] respBytes;
        String ct;
        if (responder.getRaEmulator() == null) {
          ct = ScepConstants.CT_X509_CA_CERT;
          respBytes = responder.getCaEmulator().getCaCertBytes();
        } else {
          CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();
          try {
            cmsSignedDataGen.addCertificate(responder.getCaEmulator().getCaCert().toBcCert());
            ct = ScepConstants.CT_X509_CA_RA_CERT;
            cmsSignedDataGen.addCertificate(responder.getRaEmulator().getRaCert().toBcCert());
            CMSSignedData degenerateSignedData = cmsSignedDataGen.generate(new CMSAbsentContent());
            respBytes = degenerateSignedData.getEncoded();
          } catch (CMSException ex) {
            ex.printStackTrace();
            auditMessage = "system internal error";
            sendError(exchange, SC_INTERNAL_SERVER_ERROR);
            return;
          }
        }

        sendToResponse(exchange, ct, respBytes);
      } else if (Operation.GetNextCACert.getCode().equalsIgnoreCase(operation)) {
        if (responder.getNextCaAndRa() == null) {
          auditMessage = "SCEP operation '" + operation + "' is not permitted";
          sendError(exchange, SC_FORBIDDEN);
          return;
        }

        try {
          NextCaMessage nextCaMsg = new NextCaMessage();
          nextCaMsg.setCaCert(responder.getNextCaAndRa().getCaCert());
          if (responder.getNextCaAndRa().getRaCert() != null) {
            X509Cert raCert = responder.getNextCaAndRa().getRaCert();
            nextCaMsg.setRaCerts(Collections.singletonList(raCert));
          }

          ContentInfo signedData = responder.encode(nextCaMsg);
          byte[] respBytes = signedData.getEncoded();
          sendToResponse(exchange, ScepConstants.CT_X509_NEXT_CA_CERT, respBytes);
        } catch (Exception ex) {
          ex.printStackTrace();
          auditMessage = "system internal error";
          sendError(exchange, SC_INTERNAL_SERVER_ERROR);
        }
      } else {
        auditMessage = "unknown SCEP operation '" + operation + "'";
        sendError(exchange, SC_BAD_REQUEST);
      } // end if ("PKIOperation".equalsIgnoreCase(operation))
    } catch (EOFException ex) {
      LOG.warn("connection reset by peer", ex);
      sendError(exchange, SC_INTERNAL_SERVER_ERROR);
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen!", th);
      auditMessage = "internal error";
      sendError(exchange, SC_INTERNAL_SERVER_ERROR);
    } finally {
      if (auditMessage != null) {
        LOG.error("error {}", auditMessage);
      }
    } // end try
  } // method service

  private void sendToResponse(HttpExchange resp, String contentType, byte[] body)
      throws IOException {
    int rLen = body == null ? 0 : body.length;
    resp.getResponseHeaders().set("content-type", contentType);
    resp.sendResponseHeaders(SC_OK, rLen);
    if (body != null) {
      resp.getResponseBody().write(body);
    }
  }

  private void sendError(HttpExchange exchange, int errorCode) throws IOException {
    exchange.sendResponseHeaders(errorCode, 0);
  }

}
