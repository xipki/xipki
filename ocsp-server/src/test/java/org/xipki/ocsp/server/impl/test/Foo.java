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

package org.xipki.ocsp.server.impl.test;

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.Signature;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.xipki.ocsp.server.impl.type.OcspRequest;
import org.xipki.security.ObjectIdentifiers;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class Foo {

    private static class Control {
        int version;
        boolean withRequestName;
        boolean withNonce;
        boolean withPrefSigAlgs;
        boolean withSignature;
        boolean extensionCritical;
    }

    public static void main(String[] args) {
        try {
            Control control = new Control();
            control.version = 0;
            control.withNonce = true;
            control.extensionCritical = true;

            byte[] request = createRequest(control);
            int version = OcspRequest.readRequestVersion(request);
            System.out.println("version: " + version);
            System.out.println("signature: " + OcspRequest.containsSignature(request));

            OcspRequest.getInstance(request);

            control.version = 1;
            control.withSignature = true;
            control.withNonce = true;
            control.withPrefSigAlgs = true;
            request = createRequest(control);
            version = OcspRequest.readRequestVersion(request);
            System.out.println("version: " + version);
            System.out.println("signature: " + OcspRequest.containsSignature(request));

            OcspRequest.getInstance(request);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private static byte[] createRequest(Control control) throws Exception {
        GeneralName requestorName = control.withRequestName
                ? new GeneralName(new X500Name("CN=requestor1")) : null;

        AlgorithmIdentifier algId1 = new AlgorithmIdentifier(
                OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
        CertID certId1 = new CertID(algId1,
                new DEROctetString(newBytes(20, (byte) 0x11)),
                new DEROctetString(newBytes(20, (byte) 0x12)),
                new ASN1Integer(BigInteger.valueOf(0x1234)));
        Request request1 = new Request(certId1, null);

        AlgorithmIdentifier algId2 = new AlgorithmIdentifier(
                OIWObjectIdentifiers.idSHA1);
        CertID certId2 = new CertID(algId2,
                new DEROctetString(newBytes(20, (byte) 0x21)),
                new DEROctetString(newBytes(20, (byte) 0x22)),
                new ASN1Integer(BigInteger.valueOf(0x1235)));
        Request request2 = new Request(certId2,
                new Extensions(new Extension(ObjectIdentifiers.id_ad_timeStamping,
                        false, newBytes(30, (byte) 0x33))));
        ASN1Sequence requestList = new DERSequence(new ASN1Encodable[]{request1, request2});

        Extensions requestExtensions = null;
        if (control.withNonce || control.withPrefSigAlgs) {
            int size = 0;
            if (control.withNonce) {
                size++;
            }

            if (control.withPrefSigAlgs) {
                size++;
            }

            Extension[] arrays = new Extension[size];
            int offset = 0;
            if (control.withNonce) {
                arrays[offset++] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                        control.extensionCritical, newBytes(20, (byte) 0x44));
            }

            if (control.withPrefSigAlgs) {
                AlgorithmIdentifier sigAlg1 = new AlgorithmIdentifier(
                        PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);
                AlgorithmIdentifier sigAlg2 = new AlgorithmIdentifier(
                        PKCSObjectIdentifiers.sha1WithRSAEncryption, DERNull.INSTANCE);
                ASN1Sequence seq = new DERSequence(new ASN1Encodable[]{sigAlg1, sigAlg2});
                arrays[offset++] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_pref_sig_algs,
                        control.extensionCritical, seq.getEncoded());
            }

            requestExtensions = new Extensions(arrays);
        }

        ASN1EncodableVector v = new ASN1EncodableVector();

        if (control.version != 0) {
            v.add(new DERTaggedObject(true, 0,
                    new ASN1Integer(BigInteger.valueOf(control.version))));
        }

        if (requestorName != null) {
            v.add(new DERTaggedObject(true, 1, requestorName));
        }

        v.add(requestList);

        if (requestExtensions != null) {
            v.add(new DERTaggedObject(true, 2, requestExtensions));
        }

        TBSRequest tbsRequest = TBSRequest.getInstance(new DERSequence(v));

        Signature sig = null;
        if (control.withSignature) {
            sig = new Signature(
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption),
                    new DERBitString(newBytes(256, (byte) 0xFF)));
        }
        return new OCSPRequest(tbsRequest, sig).getEncoded();
    }

    private static byte[] newBytes(int len, byte fill) {
        byte[] bytes = new byte[len];
        Arrays.fill(bytes, fill);
        return bytes;
    }

}
