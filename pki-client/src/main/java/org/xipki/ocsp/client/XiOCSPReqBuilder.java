// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.client;

import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.pkix.asn1.ocsp.CertID;
import org.xipki.pkix.asn1.ocsp.OCSPRequest;
import org.xipki.pkix.asn1.ocsp.Request;
import org.xipki.pkix.asn1.ocsp.Signature;
import org.xipki.pkix.asn1.ocsp.TBSRequest;
import org.xipki.pkix.asn1.util.ContentSigner;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.pkix.asn1.x509.Extensions;
import org.xipki.pkix.asn1.x509.GeneralName;
import org.xipki.pkix.exception.OCSPException;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * XiPKI OCSPReq Builder.
 *
 * @author Lijun Liao (xipki)
 */
public class XiOCSPReqBuilder {
  private final List<RequestObject> list = new ArrayList<>();
  private GeneralName requestorName = null;
  private Extensions requestExtensions = null;

  private static class RequestObject {
    private final CertID certId;
    private final Extensions extensions;

    public RequestObject(CertID certId, Extensions  extensions) {
      this.certId = certId;
      this.extensions = extensions;
    }

    public Request toRequest() {
      return new Request(certId, extensions);
    }
  }

  /**
   * Add a request for the given CertificateID.
   *
   * @param certId certificate ID of interest
   * @return a reference to this object.
   */
  public XiOCSPReqBuilder addRequest(CertID certId) {
    list.add(new RequestObject(certId, null));

    return this;
  }

  /**
   * Add a request with extensions.
   *
   * @param certId certificate ID of interest
   * @param singleRequestExtensions the extensions to attach to the request
   * @return a reference to this object.
   */
  public XiOCSPReqBuilder addRequest(CertID certId, Extensions singleRequestExtensions) {
    list.add(new RequestObject(certId, singleRequestExtensions));

    return this;
  }

  /**
   * Set the requestor name to the passed in X500Name.
   *
   * @param requestorName an X500Name representing the requestor name.
   * @return a reference to this object.
   */
  public XiOCSPReqBuilder setRequestorName(X500Name requestorName) {
    this.requestorName = GeneralName.ofDirectoryName(requestorName);
    return this;
  }

  public XiOCSPReqBuilder setRequestorName(GeneralName requestorName) {
    this.requestorName = requestorName;
    return this;
  }

  public XiOCSPReqBuilder setRequestExtensions(Extensions requestExtensions) {
    this.requestExtensions = requestExtensions;
    return this;
  }

  private OCSPRequest generateRequest(ContentSigner contentSigner, Certificate[] chain)
      throws OCSPException {
    Iterator<RequestObject> it = list.iterator();

    List<Request> requests = new LinkedList<>();

    while (it.hasNext()) {
      try {
        requests.add(it.next().toRequest());
      } catch (Exception ex) {
        throw new OCSPException("exception creating Request", ex);
      }
    }

    TBSRequest tbsReq = new TBSRequest(requestorName,
                          new Request.Seq0(requests), requestExtensions);

    Signature signature = null;

    if (contentSigner != null) {
      if (requestorName == null) {
        throw new OCSPException("requestorName must be specified if request is signed.");
      }

      byte[] sigValue;
      try {
        sigValue = contentSigner.atomicSign(tbsReq.getEncoded());
      } catch (Exception ex) {
        throw new OCSPException("exception processing TBSRequest: " + ex, ex);
      }

      Asn1BitString bitSig = new Asn1BitString(sigValue);
      AlgorithmIdentifier sigAlgId = contentSigner.getAlgorithmIdentifier();

      if (chain != null && chain.length > 0) {
        Certificate.Seq0 asn1Chain = new Certificate.Seq0(chain);
        signature = new Signature(sigAlgId, bitSig, asn1Chain);
      } else {
        signature = new Signature(sigAlgId, bitSig);
      }
    }

    return new OCSPRequest(tbsReq, signature);
  } // method generateRequest

  /**
   * Generate an unsigned request.
   *
   * @return the OCSPRequest
   * @throws OCSPException
   *           If OCSP request cannot be built.
   */
  public OCSPRequest build() throws OCSPException {
    return generateRequest(null, null);
  }

  public OCSPRequest build(ContentSigner signer, Certificate[] chain) throws OCSPException {
    if (signer == null) {
      throw new IllegalArgumentException("no signer specified");
    }

    return generateRequest(signer, chain);
  }
}
