/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
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
 *    EcpkParameters ::= CHOICE
 *   {
 *      ecParameters  ECParameters,
 *      namedCurve    OBJECT IDENTIFIER,
 *      implicitlyCA  NULL }
 *
 *    ECParameters ::= SEQUENCE
 *    {
 *       version   ECPVer,          -- version is always 1
 *       fieldID   FieldID,         -- identifies the finite field over
 *                                  -- which the curve is defined
 *       curve     Curve,           -- coefficients a and b of the
 *                                  -- elliptic curve
 *       base      ECPoint,         -- specifies the base point P
 *                                  -- on the elliptic curve
 *       order     INTEGER,         -- the order n of the base point
 *       cofactor  INTEGER OPTIONAL -- The integer h = #E(Fq)/n }
 *
 *    ECPVer ::= INTEGER {ecpVer1(1)}
 *
 *    Curve ::= SEQUENCE
 *    {
 *       a         FieldElement,
 *       b         FieldElement,
 *       seed      BIT STRING OPTIONAL }
 *
 *    FieldElement ::= OCTET STRING
 *
 *    ECPoint ::= OCTET STRING
 * </pre>
 *
 * @author Lijun Liao
 */

public final class ECParameters extends AlgorithmParametersSpi
{

    // used by ECPublicKeyImpl and ECPrivateKeyImpl
    static AlgorithmParameters getAlgorithmParameters(
            final ECParameterSpec spec)
    throws InvalidKeyException
    {
        try
        {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC", "BC");
            params.init(spec);
            return params;
        } catch (GeneralSecurityException e)
        {
            throw new InvalidKeyException("EC parameters error", e);
        }
    }

    /*
     * The parameters these AlgorithmParameters object represents.
     * Currently, it is always an instance of NamedCurve.
     */
    private ECParameterSpec namedCurve;

    // A public constructor is required by AlgorithmParameters class.
    public ECParameters()
    {
        // empty
    }

    // AlgorithmParameterSpi methods

    protected void engineInit(
            final AlgorithmParameterSpec paramSpec)
    throws InvalidParameterSpecException
    {
        if (paramSpec == null)
        {
            throw new InvalidParameterSpecException("paramSpec must not be null");
        }

        if (paramSpec.getClass().getName().equals("sun.security.ec.NamedCurve"))
        {
            namedCurve = (ECParameterSpec)paramSpec;
            return;
        }

        if (paramSpec instanceof ECParameterSpec)
        {
            namedCurve = SunNamedCurveExtender.lookupCurve((ECParameterSpec)paramSpec);
        } else if (paramSpec instanceof ECGenParameterSpec)
        {
            String name = ((ECGenParameterSpec)paramSpec).getName();
            namedCurve = SunNamedCurveExtender.lookupCurve(name);
        } else
        {
            throw new InvalidParameterSpecException("only ECParameterSpec and ECGenParameterSpec supported");
        }

        if (namedCurve == null)
        {
            throw new InvalidParameterSpecException("not a supported curve: " + paramSpec);
        }
    }

    protected void engineInit(
            final byte[] params)
    throws IOException
    {
        if(params.length < 30)
        {
            try
            {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) ASN1ObjectIdentifier.fromByteArray(params);
                ECParameterSpec spec = SunNamedCurveExtender.lookupCurve(oid.getId());
                if (spec == null)
                {
                    throw new IOException("unknown named curve: " + oid);
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
        try
        {
            engineInit(spec);
        } catch (InvalidParameterSpecException e)
        {
            throw new IOException("InvalidParameterSpecException: " + e.getMessage(), e);
        }
    }

    protected void engineInit(
            final byte[] params,
            final String decodingMethod)
    throws IOException
    {
        engineInit(params);
    }

    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(
            final Class<T> spec)
    throws InvalidParameterSpecException
    {

        if (spec.isAssignableFrom(ECParameterSpec.class))
        {
            return spec.cast(namedCurve);
        }

        if (spec.isAssignableFrom(ECGenParameterSpec.class))
        {
            // Ensure the name is the Object ID
            String name = SunNamedCurveExtender.getNamedCurveObjectId(namedCurve);
            return spec.cast(new ECGenParameterSpec(name));
        }

        throw new InvalidParameterSpecException("only ECParameterSpec and ECGenParameterSpec supported");
    }

    protected byte[] engineGetEncoded()
    throws IOException
    {
        return SunNamedCurveExtender.getNamedCurveEncoded(namedCurve);
    }

    protected byte[] engineGetEncoded(
            final String encodingMethod)
    throws IOException
    {
        return engineGetEncoded();
    }

    protected String engineToString()
    {
        if (namedCurve == null)
        {
            return "not initialized";
        }

        return namedCurve.toString();
    }
}

