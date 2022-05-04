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

package org.xipki.scep.serveremulator;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.scep.message.CaCaps;
import org.xipki.scep.message.MessageDecodingException;
import org.xipki.scep.message.NextCaMessage;
import org.xipki.scep.serveremulator.AuditEvent.AuditLevel;
import org.xipki.scep.transaction.CaCapability;
import org.xipki.scep.transaction.Operation;
import org.xipki.scep.util.ScepConstants;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.IoUtil;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;

/**
 * URL http://host:port/scep/&lt;name&gt;/&lt;profile-alias&gt;/pkiclient.exe
 *
 * @author Lijun Liao
 */

public class ScepServlet extends HttpServlet {

  private static final long serialVersionUID = 1L;

  private static final Logger LOG = LoggerFactory.getLogger(ScepServlet.class);

  private static final String CT_RESPONSE = ScepConstants.CT_PKI_MESSAGE;

  private final ScepResponder responder;

  public ScepServlet(ScepResponder responder) {
    this.responder = Args.notNull(responder, "responder");
  }

  @Override
  protected void service(HttpServletRequest req, HttpServletResponse resp)
          throws IOException {
    boolean post;

    String method = req.getMethod();
    if ("GET".equals(method)) {
      post = false;
    } else if ("POST".equals(method)) {
      post = true;
    } else {
      resp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
      return;
    }

    AuditEvent event = new AuditEvent();
    event.setName(AuditEvent.NAME_PERF);
    event.putEventData(AuditEvent.NAME_servletPath, req.getServletPath());

    AuditLevel auditLevel = AuditLevel.INFO;
    String auditMessage = null;

    try {
      CaCaps caCaps = responder.getCaCaps();
      if (post && !caCaps.supportsPost()) {
        auditMessage = "HTTP POST is not supported";
        auditLevel = AuditLevel.ERROR;
        resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
        return;
      }

      String operation = req.getParameter("operation");
      event.putEventData(AuditEvent.NAME_operation, operation);

      if ("PKIOperation".equalsIgnoreCase(operation)) {
        CMSSignedData reqMessage;
        // parse the request
        try {
          byte[] content = post ? IoUtil.read(req.getInputStream())
              : Base64.decode(req.getParameter("message"));

          reqMessage = new CMSSignedData(content);
        } catch (Exception ex) {
          auditMessage = "invalid request";
          auditLevel = AuditLevel.ERROR;
          resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
          return;
        }

        ContentInfo ci;
        try {
          ci = responder.servicePkiOperation(reqMessage, event);
        } catch (MessageDecodingException ex) {
          auditMessage = "could not decrypt and/or verify the request";
          auditLevel = AuditLevel.ERROR;
          resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
          return;
        } catch (CaException ex) {
          ex.printStackTrace();
          auditMessage = "system internal error";
          auditLevel = AuditLevel.ERROR;
          resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
          return;
        }
        byte[] respBytes = ci.getEncoded();
        sendToResponse(resp, CT_RESPONSE, respBytes);
      } else if (Operation.GetCACaps.getCode().equalsIgnoreCase(operation)) {
        // CA-Ident is ignored
        byte[] caCapsBytes = responder.getCaCaps().getBytes();
        sendToResponse(resp, ScepConstants.CT_TEXT_PLAIN, caCapsBytes);
      } else if (Operation.GetCACert.getCode().equalsIgnoreCase(operation)) {
        // CA-Ident is ignored
        byte[] respBytes;
        String ct;
        if (responder.getRaEmulator() == null) {
          ct = ScepConstants.CT_X509_CA_CERT;
          respBytes = responder.getCaEmulator().getCaCertBytes();
        } else {
          ct = ScepConstants.CT_X509_CA_RA_CERT;
          CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();
          try {
            cmsSignedDataGen.addCertificate(
                responder.getCaEmulator().getCaCert().toBcCert());
            ct = ScepConstants.CT_X509_CA_RA_CERT;
            cmsSignedDataGen.addCertificate(
                responder.getRaEmulator().getRaCert().toBcCert());
            CMSSignedData degenerateSignedData = cmsSignedDataGen.generate(
                new CMSAbsentContent());
            respBytes = degenerateSignedData.getEncoded();
          } catch (CMSException ex) {
            ex.printStackTrace();
            auditMessage = "system internal error";
            auditLevel = AuditLevel.ERROR;
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
          }
        }

        sendToResponse(resp, ct, respBytes);
      } else if (Operation.GetNextCACert.getCode().equalsIgnoreCase(operation)) {
        if (responder.getNextCaAndRa() == null) {
          auditMessage = "SCEP operation '" + operation + "' is not permitted";
          auditLevel = AuditLevel.ERROR;
          resp.sendError(HttpServletResponse.SC_FORBIDDEN);
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
          sendToResponse(resp, ScepConstants.CT_X509_NEXT_CA_CERT, respBytes);
        } catch (Exception ex) {
          ex.printStackTrace();
          auditMessage = "system internal error";
          auditLevel = AuditLevel.ERROR;
          resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
      } else {
        auditMessage = "unknown SCEP operation '" + operation + "'";
        auditLevel = AuditLevel.ERROR;
        resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
      } // end if ("PKIOperation".equalsIgnoreCase(operation))
    } catch (EOFException ex) {
      LOG.warn("connection reset by peer", ex);
      resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen!", th);
      auditLevel = AuditLevel.ERROR;
      auditMessage = "internal error";
      resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    } finally {
      if (event.getLevel() != AuditLevel.ERROR) {
        event.setLevel(auditLevel);
      }

      if (auditMessage != null) {
        event.putEventData("error", auditMessage);
      }

      event.log(LOG);
    } // end try
  } // method service

  private void sendToResponse(HttpServletResponse resp, String contentType, byte[] body)
      throws IOException {
    resp.setContentType(contentType);
    resp.setContentLength(body.length);
    resp.getOutputStream().write(body);
  }

  protected PKIMessage generatePkiMessage(InputStream is)
      throws IOException {
    ASN1InputStream asn1Stream = new ASN1InputStream(Args.notNull(is, "is"));

    try {
      return PKIMessage.getInstance(asn1Stream.readObject());
    } finally {
      try {
        asn1Stream.close();
      } catch (Exception ex) {
        LOG.error("could not close stream: {}", ex.getMessage());
      }
    }
  } // method generatePkiMessage

}
