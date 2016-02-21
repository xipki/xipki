/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.commons.security.impl.p11.sun;

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
import org.xipki.commons.common.util.LogUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SunNamedCurveExtender {

    private static class CurveData {

        final int type;

        final String sfield;

        final String a;

        final String b;

        final String x;

        final String y;

        final String n;

        final int h;

        CurveData(
                final X9ECParameters params) {
            ECCurve curve = params.getCurve();

            this.a = curve.getA().toBigInteger().toString(16);
            this.b = curve.getB().toBigInteger().toString(16);
            this.x = params.getG().getAffineXCoord().toBigInteger().toString(16);
            this.y = params.getG().getAffineYCoord().toBigInteger().toString(16);
            this.n = params.getN().toString(16);
            this.h = params.getH().intValue();

            if (curve instanceof ECCurve.Fp) {
                this.type = P;

                ECCurve.Fp c = (ECCurve.Fp) curve;
                this.sfield = c.getQ().toString(16);
            } else { // if (curve instanceof ECCurve.F2m)
                this.type = B;

                ECCurve.F2m c = (ECCurve.F2m) curve;
                int m = c.getM();

                int[] ks = new int[]{c.getK1(), c.getK2(), c.getK3()};

                BigInteger rp = BigInteger.ONE;
                rp = rp.setBit(m);

                for (int j = 0; j < ks.length; j++) {
                    if (ks[j] > 0) {
                        rp = rp.setBit(ks[j]);
                    }
                }
                this.sfield = rp.toString(16);
            }
        } // constructor

    } // class CurveData

    private static final Logger LOG = LoggerFactory.getLogger(SunNamedCurveExtender.class);

    private static final int P = 1; // prime curve

    private static final int B = 2; // binary curve

    private static final Pattern SPLIT_PATTERN = Pattern.compile(",|\\[|\\]");

    private static Boolean executed = Boolean.FALSE;

    private static Class<?> classNamedCurve;

    private static Class<?> classCurveDB;

    private static Method methodCurveDBLookupParamSpec;

    private static Method methodCurveDBLookupName;

    private static Method methodNamedCurveGetEncoded;

    private static Method methodNamedCurveGetObjectId;

    private static boolean successful = true;

    static {
        try {
            classCurveDB = Class.forName("sun.security.ec.CurveDB");
        } catch (ClassNotFoundException e) {
            successful = false;
        }

        final String classnameNamedCurve = "sun.security.ec.NamedCurve";
        try {
            classNamedCurve = Class.forName(classnameNamedCurve);
        } catch (ClassNotFoundException e) {
            LOG.warn("could not load class {}", classnameNamedCurve);
            LOG.debug("could not load class " + classnameNamedCurve, e);
            successful = false;
        }

        if (successful) {
            methodCurveDBLookupName = getMethod(classCurveDB, "lookup",
                    new Class<?>[]{String.class});
        }
        if (methodCurveDBLookupName == null) {
            successful = false;
        }

        if (successful) {
            methodCurveDBLookupParamSpec = getMethod(classCurveDB, "lookup",
                    new Class<?>[]{ECParameterSpec.class});
        }
        if (methodCurveDBLookupParamSpec == null) {
            successful = false;
        }

        if (successful) {
            methodNamedCurveGetObjectId = getMethod(classNamedCurve, "getObjectId", null);
        }
        if (methodNamedCurveGetObjectId == null) {
            successful = false;
        }

        if (successful) {
            methodNamedCurveGetEncoded = getMethod(classNamedCurve, "getEncoded", null);
        }
        if (methodNamedCurveGetEncoded == null) {
            successful = false;
        }
    } // method static

    private SunNamedCurveExtender() {
    }

    /*
    public static void main(
            final String[] args) {
        addNamedCurves();
    }*/

    public static void addNamedCurves() {
        synchronized (executed) {
            if (!successful) {
                LOG.warn("could not initialize");
                return;
            }

            if (executed) {
                return;
            }
            executed = Boolean.TRUE;

            try {
                addNamedCurvesJdk18on();
            } catch (Throwable t) {
                final String message = "uncatched Error";
                if (LOG.isErrorEnabled()) {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(),
                            t.getMessage());
                }
                LOG.debug(message, t);
            }
        } // end synchronized (EXECUTED)
    } // method addNamedCurves

    private static void addNamedCurvesJdk18on() {
        final Class<?>[] paramCurveDBAdd = new Class[] {
            String.class, String.class, int.class, String.class,
            String.class, String.class, String.class, String.class, String.class, int.class,
            Pattern.class
        };
        final Class<?>[] paramGetCurve = new Class[]{String.class};

        Method methodAdd = getMethod(classCurveDB, "add", paramCurveDBAdd);
        if (methodAdd == null) {
            return;
        }

        Method methodGetCurve = getMethod(classCurveDB, "lookup", paramGetCurve);
        if (methodGetCurve == null) {
            return;
        }

        Field fieldOidMap = getField(classCurveDB, "oidMap");
        if (fieldOidMap == null) {
            return;
        }

        Field fieldSpecCollection = getField(classCurveDB, "specCollection");
        if (fieldSpecCollection == null) {
            return;
        }

        Set<String> processedCurveOids = new HashSet<>();
        Map<String, String> addedCurves = new HashMap<>();

        Enumeration<?> curveNames = ECNamedCurveTable.getNames();
        while (curveNames.hasMoreElements()) {
            String curveName = (String) curveNames.nextElement();
            ASN1ObjectIdentifier curveId = getCurveId(curveName);
            if (curveId == null) {
                LOG.debug("cound not find curve OID for curve {}, ignore it", curveName);
                continue;
            }

            String curveDesc = "named curve " + curveName + " (" + curveId + ")";

            if (processedCurveOids.contains(curveId.getId())) {
                LOG.debug("{} is already processed, ignore it", curveDesc);
                continue;
            }

            processedCurveOids.add(curveId.getId());

            if (curveIsRegistered(methodGetCurve, curveId)) {
                LOG.info("{} is already registered, ignore it", curveDesc);
                continue;
            }

            X9ECParameters params = ECNamedCurveTable.getByOID(curveId);
            ECCurve curve = params.getCurve();
            if (curve instanceof ECCurve.Fp || curve instanceof ECCurve.F2m) {
                CurveData c = new CurveData(params);
                boolean added = curveDBAdd(methodAdd, curveName, curveId.getId(), c.type,
                        c.sfield, c.a, c.b, c.x, c.y, c.n, c.h);

                if (added) {
                    LOG.debug("added {}", curveDesc);
                    addedCurves.put(curveName, curveId.getId());
                } else {
                    LOG.warn("could not add {}", curveDesc);
                }
            } else {
                LOG.info("unknown curve type {}", curve.getClass().getName());
            }
        } // end while

        try {
            Map<?, ?> oidMap = (Map<?, ?>) fieldOidMap.get(null);
            Collection<?> namedCurves = Collections.unmodifiableCollection(oidMap.values());

            fieldSpecCollection.set(null, namedCurves);
        } catch (IllegalArgumentException | IllegalAccessException | ClassCastException e) {
            final String message =
                    "could not update change the value of field CurveDB.specCollection.";
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
        }

        logAddedCurves(addedCurves);
    } // method addNamedCurvesJdk18on

    private static ASN1ObjectIdentifier getCurveId(
            final String curveName) {
        ASN1ObjectIdentifier curveId = X962NamedCurves.getOID(curveName);

        if (curveId == null) {
            curveId = SECNamedCurves.getOID(curveName);
        }

        if (curveId == null) {
            curveId = TeleTrusTNamedCurves.getOID(curveName);
        }

        if (curveId == null) {
            curveId = NISTNamedCurves.getOID(curveName);
        }

        return curveId;
    }

    private static boolean curveIsRegistered(
            final Method methodLookup,
            final ASN1ObjectIdentifier curveId) {
        try {
            Object curve = methodLookup.invoke(null, new Object[]{curveId.getId()});
            return curve != null;
        } catch (IllegalArgumentException | IllegalAccessException | InvocationTargetException e) {
            LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
        }

        return true; // if error occurs, just return true
    }

    private static boolean curveDBAdd(
            final Method methodAdd,
            final String name,
            final String soid,
            final int type,
            final String sfield,
            final String a,
            final String b,
            final String x,
            final String y,
            final String n,
            final int h) {
        try {
            methodAdd.invoke(null, new Object[]{name, soid, type, sfield, a, b, x, y, n, h,
                    SPLIT_PATTERN});
        } catch (IllegalArgumentException | IllegalAccessException | InvocationTargetException e) {
            LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
            return false;
        }

        return true;
    }

    private static Method getMethod(
            final Class<?> clz,
            final String methodName,
            final Class<?>[] params) {
        Method serviceMethod = null;
        final String desc = "method " + clz.getName() + "." + methodName;

        try {
            if (params == null) {
                serviceMethod = clz.getDeclaredMethod(methodName);
            } else {
                serviceMethod = clz.getDeclaredMethod(methodName, params);
            }
            serviceMethod.setAccessible(true);
            return serviceMethod;
        } catch (SecurityException | NoSuchMethodException e) {
            final String message = "could not get " + desc;
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
        }

        return null;
    }

    private static Field getField(
            final Class<?> clazz,
            final String fieldName) {
        String desc = "Field " + fieldName;
        try {
            Field field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
            return field;
        } catch (NoSuchFieldException e) {
            final String message = "could not get " + desc;
            if (LOG.isWarnEnabled()) {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
        }

        return null;
    }

    private static void logAddedCurves(
            final Map<String, String> addedCurves) {
        StringBuilder sb = new StringBuilder(
                "the following named curves are added to the SUN's list of named curves:\n");

        Set<String> tmp = addedCurves.keySet();
        List<String> names = new ArrayList<>(tmp);
        Collections.sort(names);

        for (String name : names) {
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
            final ECParameterSpec namedCurve) {
        try {
            return (byte[]) methodNamedCurveGetEncoded.invoke(namedCurve, (Object) null);
        } catch (IllegalArgumentException | IllegalAccessException | InvocationTargetException e) {
            LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
            return null;
        }
    }

    static String getNamedCurveObjectId(
            final ECParameterSpec namedCurve) {
        try {
            return (String) methodNamedCurveGetObjectId.invoke(namedCurve, (Object) null);
        } catch (IllegalArgumentException | IllegalAccessException | InvocationTargetException e) {
            LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
            return null;
        }
    }

    static ECParameterSpec lookupCurve(
            final String name) {
        try {
            return (ECParameterSpec) methodCurveDBLookupName.invoke(null, name);
        } catch (IllegalArgumentException | IllegalAccessException | InvocationTargetException e) {
            LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
            return null;
        }
    }

    static ECParameterSpec lookupCurve(
            final ECParameterSpec paramSpec) {
        try {
            return (ECParameterSpec) methodCurveDBLookupParamSpec.invoke(null, paramSpec);
        } catch (IllegalArgumentException | IllegalAccessException | InvocationTargetException e) {
            LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
            return null;
        }
    }

}
