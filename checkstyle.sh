#!/bin/sh

mvn checkstyle:checkstyle-aggregate -Dcheckstyle.config.location=xipki_sun_checks.xml -Dcheckstyle.output.format=plain
