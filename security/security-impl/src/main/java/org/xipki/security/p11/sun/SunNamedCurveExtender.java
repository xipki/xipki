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

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.LogUtil;

/**
 * @author Lijun Liao
 */

public class SunNamedCurveExtender
{
    private static Logger LOG = LoggerFactory.getLogger(SunNamedCurveExtender.class);

    private final static int P  = 1; // prime curve
    private final static int B  = 2; // binary curve

    private static final Pattern SPLIT_PATTERN = Pattern.compile(",|\\[|\\]");

    private static Boolean EXECUTED = Boolean.FALSE;
    private static final boolean jdk18on;

    private static Class<?> class_NamedCurve;
    private static Class<?> class_CurveDB;
    private static Method method_CurveDB_lookup_paramSpec;
    private static Method method_CurveDB_lookup_name;
    private static Method method_NamedCurve_getEncoded;
    private static Method method_NamedCurve_getObjectId;
    private static boolean successfull = true;

    static
    {
        boolean _jdk18On;
        try
        {
            class_CurveDB = Class.forName("sun.security.ec.CurveDB");
            _jdk18On = true;
        } catch (ClassNotFoundException e)
        {
            _jdk18On = false;
        }

        jdk18on = _jdk18On;

        final String classname_NamedCurve = "sun.security.ec.NamedCurve";
        try
        {
            class_NamedCurve = Class.forName(classname_NamedCurve);
        } catch (ClassNotFoundException e)
        {
            LOG.warn("could not load class {}", classname_NamedCurve);
            LOG.debug("could not load class " + classname_NamedCurve, e);
            successfull = false;
        }

        if (jdk18on)
        {
            if (successfull)
            {
                method_CurveDB_lookup_name = getMethod(class_CurveDB, "lookup",
                        new Class<?>[]{String.class});
            }
            if (method_CurveDB_lookup_name == null)
            {
                successfull = false;
            }

            if (successfull)
            {
                method_CurveDB_lookup_paramSpec = getMethod(class_CurveDB, "lookup",
                        new Class<?>[]{ECParameterSpec.class});
            }
            if (method_CurveDB_lookup_paramSpec == null)
            {
                successfull = false;
            }

            if (successfull)
            {
                method_NamedCurve_getObjectId = getMethod(class_NamedCurve, "getObjectId", null);
            }
            if (method_NamedCurve_getObjectId == null)
            {
                successfull = false;
            }

            if (successfull)
            {
                method_NamedCurve_getEncoded = getMethod(class_NamedCurve, "getEncoded", null);
            }
            if (method_NamedCurve_getEncoded == null)
            {
                successfull = false;
            }
        }
    }

    public static void main(
            final String[] args)
    {
        addNamedCurves();
    }

    public static void addNamedCurves()
    {
        synchronized (EXECUTED)
        {
            if (successfull == false)
            {
                LOG.warn("could not initialize");
                return;
            }

            if (EXECUTED)
            {
                return;
            }
            EXECUTED = Boolean.TRUE;

            try
            {
                if (jdk18on)
                {
                    addNamedCurves_jdk18on();
                }
                else
                {
                    addNamedCurves_jdk17();
                }

            } catch (Throwable t)
            {
                final String message = "uncatched Error";
                if (LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(),
                            t.getMessage());
                }
                LOG.debug(message, t);
            }
        }
    }

    private static void addNamedCurves_jdk17()
    {
        final Class<?>[] Param_NamedCurve_add = new Class[]
        {
            String.class, String.class, int.class, String.class,
            String.class, String.class, String.class, String.class, String.class, int.class
        };
        final Class<?>[] Param_getCurve = new Class[]{String.class};

        Method method_add = getMethod(class_NamedCurve, "add", Param_NamedCurve_add);
        if (method_add == null)
        {
            return;
        }

        Method method_getCurve = getMethod(class_NamedCurve, "getECParameterSpec",
                Param_getCurve);
        if (method_getCurve == null)
        {
            return;
        }

        Field field_SPLIT_PATTERN = getField(class_NamedCurve, "SPLIT_PATTERN");
        if (field_SPLIT_PATTERN == null)
        {
            return;
        }

        try
        {
            field_SPLIT_PATTERN.set(null, SPLIT_PATTERN);
        } catch (IllegalArgumentException | IllegalAccessException e)
        {
            final String message = "could not set Field SPLIT_PATTERN";
            if (LOG.isWarnEnabled())
            {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
            return;
        }

        Set<String> processedCurveOids = new HashSet<>();
        Map<String, String> addedCurves = new HashMap<>();

        Enumeration<?> curveNames = ECNamedCurveTable.getNames();
        while (curveNames.hasMoreElements())
        {
            String curveName = (String) curveNames.nextElement();
            ASN1ObjectIdentifier curveId = getCurveId(curveName);

            if (curveId == null)
            {
                LOG.info("cound not find curve OID for curve {}, ignore it", curveName);
                continue;
            }

            String curveDesc = "named curve " + curveName + " (" + curveId + ")";

            if (processedCurveOids.contains(curveId.getId()))
            {
                LOG.debug("{} is already processed, ignore it", curveDesc);
                continue;
            }

            processedCurveOids.add(curveId.getId());

            if (curve_isRegistered(method_getCurve, curveId))
            {
                LOG.debug("{} is already registered, ignore it", curveDesc);
                continue;
            }

            X9ECParameters params = ECNamedCurveTable.getByOID(curveId);
            ECCurve curve = params.getCurve();

            if (curve instanceof ECCurve.Fp || curve instanceof ECCurve.F2m)
            {
                CurveData c = new CurveData(params);
                boolean added = NamedCurve_add(method_add, curveName, curveId.getId(), c.type,
                        c.sfield, c.a, c.b, c.x, c.y, c.n, c.h);

                if (added)
                {
                    LOG.debug("added {}", curveDesc);
                    addedCurves.put(curveName, curveId.getId());
                }
                else
                {
                    LOG.warn("could not add {}", curveDesc);
                }
            }
            else
            {
                LOG.info("unknown curve type {}", curve.getClass().getName());
            }
        }

        try
        {
            field_SPLIT_PATTERN.set(null, null);
        } catch (IllegalArgumentException | IllegalAccessException e)
        {
            final String message = "could not set Field SPLIT_PATTERN";
            if (LOG.isWarnEnabled())
            {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
            return;
        }

        logAddedCurves(addedCurves);
    }

    private static void addNamedCurves_jdk18on()
    {
        final Class<?>[] Param_CurveDB_add = new Class[]
        {
            String.class, String.class, int.class, String.class,
            String.class, String.class, String.class, String.class, String.class, int.class,
            Pattern.class
        };
        final Class<?>[] Param_getCurve = new Class[]{String.class};

        Method method_add = getMethod(class_CurveDB, "add", Param_CurveDB_add);
        if (method_add == null)
        {
            return;
        }

        Method method_getCurve = getMethod(class_CurveDB, "lookup", Param_getCurve);
        if (method_getCurve == null)
        {
            return;
        }

        Field field_oidMap = getField(class_CurveDB, "oidMap");
        if (field_oidMap == null)
        {
            return;
        }

        Field field_specCollection = getField(class_CurveDB, "specCollection");
        if (field_specCollection == null)
        {
            return;
        }

        Set<String> processedCurveOids = new HashSet<>();
        Map<String, String> addedCurves = new HashMap<>();

        Enumeration<?> curveNames = ECNamedCurveTable.getNames();
        while (curveNames.hasMoreElements())
        {
            String curveName = (String) curveNames.nextElement();
            ASN1ObjectIdentifier curveId = getCurveId(curveName);
            if (curveId == null)
            {
                LOG.debug("cound not find curve OID for curve {}, ignore it", curveName);
                continue;
            }

            String curveDesc = "named curve " + curveName + " (" + curveId + ")";

            if (processedCurveOids.contains(curveId.getId()))
            {
                LOG.debug("{} is already processed, ignore it", curveDesc);
                continue;
            }

            processedCurveOids.add(curveId.getId());

            if (curve_isRegistered(method_getCurve, curveId))
            {
                LOG.info("{} is already registered, ignore it", curveDesc);
                continue;
            }

            X9ECParameters params = ECNamedCurveTable.getByOID(curveId);
            ECCurve curve = params.getCurve();
            if (curve instanceof ECCurve.Fp || curve instanceof ECCurve.F2m)
            {
                CurveData c = new CurveData(params);
                boolean added = CurveDB_add(method_add, curveName, curveId.getId(), c.type,
                        c.sfield, c.a, c.b, c.x, c.y, c.n, c.h);

                if (added)
                {
                    LOG.debug("added {}", curveDesc);
                    addedCurves.put(curveName, curveId.getId());
                }
                else
                {
                    LOG.warn("could not add {}", curveDesc);
                }
            }
            else
            {
                LOG.info("unknown curve type {}", curve.getClass().getName());
            }
        }

        try
        {
            Map<?,?> oidMap = (Map<?, ?>) field_oidMap.get(null);
            Collection<?> namedCurves = Collections.unmodifiableCollection(oidMap.values());

            field_specCollection.set(null, namedCurves);
        } catch (IllegalArgumentException | IllegalAccessException | ClassCastException e)
        {
            final String message =
                    "could not update change the value of field CurveDB.specCollection.";
            if (LOG.isWarnEnabled())
            {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
        }

        logAddedCurves(addedCurves);
    }

    private static ASN1ObjectIdentifier getCurveId(
            final String curveName)
    {
        ASN1ObjectIdentifier curveId = X962NamedCurves.getOID(curveName);

        if (curveId == null)
        {
            curveId = SECNamedCurves.getOID(curveName);
        }

        if (curveId == null)
        {
            curveId = TeleTrusTNamedCurves.getOID(curveName);
        }

        if (curveId == null)
        {
            curveId = NISTNamedCurves.getOID(curveName);
        }

        return curveId;
    }

    private static boolean curve_isRegistered(
            final Method method_lookup,
            final ASN1ObjectIdentifier curveId)
    {
        try
        {
            Object curve = method_lookup.invoke(null, new Object[]{curveId.getId()});
            return curve != null;
        } catch (IllegalArgumentException | IllegalAccessException | InvocationTargetException e)
        {
            LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
        }

        return true; // if error occurs, just return true
    }

    private static boolean CurveDB_add(
            final Method method_add,
            final String name,
            final String soid,
            final int type,
            final String sfield,
            final String a,
            final String b,
            final String x,
            final String y,
            final String n,
            final int h)
    {
        try
        {
            method_add.invoke(null, new Object[]{name, soid, type, sfield, a, b, x, y, n, h,
                    SPLIT_PATTERN});
        } catch (IllegalArgumentException | IllegalAccessException | InvocationTargetException e)
        {
            LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
            return false;
        }

        return true;
    }

    private static boolean NamedCurve_add(
            final Method method_add,
            final String name,
            final String soid,
            final int type,
            final String sfield,
            final String a,
            final String b,
            final String x,
            final String y,
            final String n,
            final int h)
    {
        try
        {
            method_add.invoke(null, new Object[]{name, soid, type, sfield, a, b, x, y, n, h});
        } catch (IllegalArgumentException | IllegalAccessException | InvocationTargetException e)
        {
            LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
            return false;
        }

        return true;
    }

    private static final Method getMethod(
            final Class<?> clz,
            final String methodName,
            final Class<?>[] params)
    {
        Method serviceMethod = null;
        final String desc = "method " + clz.getName() + "." + methodName;

        try
        {
            if (params == null)
            {
                serviceMethod = clz.getDeclaredMethod(methodName);
            }
            else
            {
                serviceMethod = clz.getDeclaredMethod(methodName, params);
            }
            serviceMethod.setAccessible(true);
            return serviceMethod;
        } catch (SecurityException | NoSuchMethodException e)
        {
            final String message = "could not get " + desc;
            if (LOG.isWarnEnabled())
            {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
        }

        return null;
    }

    private static final Field getField(
            final Class<?> clazz,
            final String fieldName)
    {
        String desc = "Field " + fieldName;
        try
        {
            Field field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
            return field;
        } catch (NoSuchFieldException e)
        {
            final String message = "could not get " + desc;
            if (LOG.isWarnEnabled())
            {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
        }

        return null;
    }

    private static class CurveData
    {
        final int type;
        final String sfield;
        final String a;
        final String b;
        final String x;
        final String y;
        final String n;
        final int h;

        CurveData(
                final X9ECParameters params)
        {
            ECCurve curve = params.getCurve();

            this.a = curve.getA().toBigInteger().toString(16);
            this.b = curve.getB().toBigInteger().toString(16);
            this.x = params.getG().getAffineXCoord().toBigInteger().toString(16);
            this.y = params.getG().getAffineYCoord().toBigInteger().toString(16);
            this.n = params.getN().toString(16);
            this.h = params.getH().intValue();

            if (curve instanceof ECCurve.Fp)
            {
                this.type = P;

                ECCurve.Fp c = (ECCurve.Fp) curve;
                this.sfield = c.getQ().toString(16);
            }
            else // if (curve instanceof ECCurve.F2m)
            {
                this.type = B;

                ECCurve.F2m c = (ECCurve.F2m) curve;
                int m = c.getM();

                int ks[] = new int[3];
                ks[0] = c.getK1();
                ks[1] = c.getK2();
                ks[2] = c.getK3();

                BigInteger rp = BigInteger.ONE;
                rp = rp.setBit(m);

                for (int j = 0; j < ks.length; j++)
                {
                    if (ks[j] > 0)
                    {
                        rp = rp.setBit(ks[j]);
                    }
                }
                this.sfield = rp.toString(16);
            }
        }
    }

    private static void logAddedCurves(
            final Map<String, String> addedCurves)
    {
        StringBuilder sb = new StringBuilder(
                "the following named curves are added to the SUN's list of named curves:\n");

        Set<String> tmp = addedCurves.keySet();
        List<String> names = new ArrayList<>(tmp);
        Collections.sort(names);

        for (String name : names)
        {
            String oid = addedCurves.get(name);
            sb.append("\t");
            sb.append(name);
            sb.append(" (");
            sb.append(oid);
            sb.append(")\n");
        }

        LOG.info("{}", sb);
    }

    static byte[] getNamedCurveEncoded(
            final ECParameterSpec namedCurve)
    {
        try
        {
            return (byte[]) method_NamedCurve_getEncoded.invoke(namedCurve, (Object) null);
        } catch (IllegalArgumentException | IllegalAccessException | InvocationTargetException e)
        {
            LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
            return null;
        }
    }

    static String getNamedCurveObjectId(
            final ECParameterSpec namedCurve)
    {
        try
        {
            return (String) method_NamedCurve_getObjectId.invoke(namedCurve, (Object)null);
        } catch (IllegalArgumentException | IllegalAccessException | InvocationTargetException e)
        {
            LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
            return null;
        }
    }

    static ECParameterSpec lookupCurve(
            final String name)
    {
        try
        {
            return (ECParameterSpec) method_CurveDB_lookup_name.invoke(null, name);
        } catch (IllegalArgumentException | IllegalAccessException | InvocationTargetException e)
        {
            LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
            return null;
        }
    }

    static ECParameterSpec lookupCurve(
            final ECParameterSpec paramSpec)
    {
        try
        {
            return (ECParameterSpec) method_CurveDB_lookup_paramSpec.invoke(null, paramSpec);
        } catch (IllegalArgumentException | IllegalAccessException | InvocationTargetException e)
        {
            LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
            return null;
        }
    }
}
