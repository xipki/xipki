/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.security.p11.sun;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParametersSpi;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;


/**
 * This class implements encoding and decoding of Elliptic Curve parameters
 * as specified in RFC 3279.
 *
 * However, only named curves are currently supported.
 *
 * ASN.1 from RFC 3279 follows. Note that X9.62 (2005) has added some additional
 * options.
 *
 * <pre>
 *    EcpkParameters ::= CHOICE {
 *      ecParameters  ECParameters,
 *      namedCurve    OBJECT IDENTIFIER,
 *      implicitlyCA  NULL }
 *
 *    ECParameters ::= SEQUENCE {
 *       version   ECPVer,          -- version is always 1
 *       fieldID   FieldID,         -- identifies the finite field over
 *                                  -- which the curve is defined
 *       curve     Curve,           -- coefficients a and b of the
 *                                  -- elliptic curve
 *       base      ECPoint,         -- specifies the base point P
 *                                  -- on the elliptic curve
 *       order     INTEGER,         -- the order n of the base point
 *       cofactor  INTEGER OPTIONAL -- The integer h = #E(Fq)/n
 *       }
 *
 *    ECPVer ::= INTEGER {ecpVer1(1)}
 *
 *    Curve ::= SEQUENCE {
 *       a         FieldElement,
 *       b         FieldElement,
 *       seed      BIT STRING OPTIONAL }
 *
 *    FieldElement ::= OCTET STRING
 *
 *    ECPoint ::= OCTET STRING
 * </pre>
 *
 */
public final class ECParameters extends AlgorithmParametersSpi {

	
	
    // used by ECPublicKeyImpl and ECPrivateKeyImpl
    static AlgorithmParameters getAlgorithmParameters(ECParameterSpec spec)
            throws InvalidKeyException {
        try {
            AlgorithmParameters params =
                AlgorithmParameters.getInstance("EC", "BC");
            params.init(spec);
            return params;
        } catch (GeneralSecurityException e) {
            throw new InvalidKeyException("EC parameters error", e);
        }
    }

    /*
     * The parameters these AlgorithmParameters object represents.
     * Currently, it is always an instance of NamedCurve.
     */
    private ECParameterSpec namedCurve;

    // A public constructor is required by AlgorithmParameters class.
    public ECParameters() {
        // empty
    }

    // AlgorithmParameterSpi methods

    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {

        if (paramSpec == null) {
            throw new InvalidParameterSpecException
                ("paramSpec must not be null");
        }

        if (paramSpec.getClass().getName().equals("sun.security.ec.NamedCurve"))
        {
            namedCurve = (ECParameterSpec)paramSpec;
            return;
        }

        if (paramSpec instanceof ECParameterSpec) {
            namedCurve = SunNamedCurveExtender.lookupCurve((ECParameterSpec)paramSpec);
        } else if (paramSpec instanceof ECGenParameterSpec) {
            String name = ((ECGenParameterSpec)paramSpec).getName();
            namedCurve = SunNamedCurveExtender.lookupCurve(name);
        } else {
            throw new InvalidParameterSpecException
                ("Only ECParameterSpec and ECGenParameterSpec supported");
        }

        if (namedCurve == null) {
            throw new InvalidParameterSpecException(
                "Not a supported curve: " + paramSpec);
        }
    }

    protected void engineInit(byte[] params) throws IOException { 
    	if(params.length < 30)
    	{
    		try{
    			ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) ASN1ObjectIdentifier.fromByteArray(params);
                ECParameterSpec spec = SunNamedCurveExtender.lookupCurve(oid.getId());
                if (spec == null) {
                    throw new IOException("Unknown named curve: " + oid);
                }

                namedCurve = spec;
                return;
    		}catch(IllegalArgumentException e)
    		{
    		}
    	}

        // The code below is incomplete.
        // It is left as a starting point for a complete parsing implementation.
        X9ECParameters x9EcParams = X9ECParameters.getInstance(params);
        ECCurve curve = x9EcParams.getCurve();
        
        ECNamedCurveSpec ecNamedCurveSpec = new ECNamedCurveSpec(
        		"dummy", curve, x9EcParams.getG(), x9EcParams.getN(), x9EcParams.getH());

        ECParameterSpec spec = new ECParameterSpec(
        		ecNamedCurveSpec.getCurve(), 
        		ecNamedCurveSpec.getGenerator(), 
        		ecNamedCurveSpec.getOrder(), 
        		ecNamedCurveSpec.getCofactor());
        try {
			engineInit(spec);
		} catch (InvalidParameterSpecException e) {
			throw new IOException("InvalidParameterSpecException: " + e.getMessage(), e);
		}
    }

    protected void engineInit(byte[] params, String decodingMethod)
            throws IOException {
        engineInit(params);
    }

    protected <T extends AlgorithmParameterSpec> T
            engineGetParameterSpec(Class<T> spec)
            throws InvalidParameterSpecException {

        if (spec.isAssignableFrom(ECParameterSpec.class)) {
            return spec.cast(namedCurve);
        }

        if (spec.isAssignableFrom(ECGenParameterSpec.class)) {
            // Ensure the name is the Object ID
            String name = SunNamedCurveExtender.getNamedCurveObjectId(namedCurve);
            return spec.cast(new ECGenParameterSpec(name));
        }

        throw new InvalidParameterSpecException(
            "Only ECParameterSpec and ECGenParameterSpec supported");
    }

    protected byte[] engineGetEncoded() throws IOException {
        return SunNamedCurveExtender.getNamedCurveEncoded(namedCurve);
    }

    protected byte[] engineGetEncoded(String encodingMethod)
            throws IOException {
        return engineGetEncoded();
    }

    protected String engineToString() {
        if (namedCurve == null) {
            return "Not initialized";
        }

        return namedCurve.toString();
    }
}

