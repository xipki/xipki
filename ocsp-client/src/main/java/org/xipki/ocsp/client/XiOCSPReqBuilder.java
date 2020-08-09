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

package org.xipki.ocsp.client;

import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.Signature;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.operator.ContentSigner;

/**
 * OCSP Request builder.
 *
 * @author Lijun Liao
 *
 */
// CHECKSTYLE:SKIP
public class XiOCSPReqBuilder {
  private List<RequestObject> list = new ArrayList<>();
  private GeneralName requestorName = null;
  private Extensions requestExtensions = null;

  private class RequestObject {
    CertID certId;
    Extensions  extensions;

    public RequestObject(CertID certId, Extensions  extensions) {
      this.certId = certId;
      this.extensions = extensions;
    }

    public Request toRequest()
        throws Exception {
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
    this.requestorName = new GeneralName(GeneralName.directoryName, requestorName);

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

    ASN1EncodableVector requests = new ASN1EncodableVector();

    while (it.hasNext()) {
      try {
        requests.add(((RequestObject)it.next()).toRequest());
      } catch (Exception ex) {
        throw new OCSPException("exception creating Request", ex);
      }
    }

    TBSRequest tbsReq = new TBSRequest(requestorName, new DERSequence(requests), requestExtensions);

    Signature signature = null;

    if (contentSigner != null) {
      if (requestorName == null) {
        throw new OCSPException("requestorName must be specified if request is signed.");
      }

      try {
        // CHECKSTYLE:SKIP
        OutputStream sOut = contentSigner.getOutputStream();
        sOut.write(tbsReq.getEncoded(ASN1Encoding.DER));
        sOut.close();
      } catch (Exception ex) {
        throw new OCSPException("exception processing TBSRequest: " + ex, ex);
      }

      DERBitString bitSig = new DERBitString(contentSigner.getSignature());
      AlgorithmIdentifier sigAlgId = contentSigner.getAlgorithmIdentifier();

      if (chain != null && chain.length > 0) {
        ASN1EncodableVector vec = new ASN1EncodableVector();

        for (int i = 0; i != chain.length; i++) {
          vec.add(chain[i]);
        }

        signature = new Signature(sigAlgId, bitSig, new DERSequence(vec));
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
  public OCSPRequest build()
      throws OCSPException {
    return generateRequest(null, null);
  }

  public OCSPRequest build(ContentSigner signer, Certificate[] chain)
      throws OCSPException {
    if (signer == null) {
      throw new IllegalArgumentException("no signer specified");
    }

    return generateRequest(signer, chain);
  }
}
