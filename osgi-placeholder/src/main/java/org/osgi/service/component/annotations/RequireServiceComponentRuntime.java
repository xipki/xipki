// #THIRDPARTY
// Copyright (c) Contributors to the Eclipse Foundation
// License: Apache-2.0

package org.osgi.service.component.annotations;

import org.osgi.annotation.bundle.Requirement;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Documented
@Retention(RetentionPolicy.CLASS)
@Target({
    ElementType.TYPE, ElementType.PACKAGE
})
@Requirement(namespace = "osgi.extender", //
    name = "osgi.component", //
    version = "1.5")
public @interface RequireServiceComponentRuntime {
  // This is a marker annotation.
}
