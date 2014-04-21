#!/bin/sh

COMMAND=$1

PROP_FILE=ocsp-publisher.properties
CHANGELOG_FILE=ocsp-init.xml
JDBC_CP=$( echo ../lib/ext/*.jar | sed 's/ /:/g')

# retrieve the database configuration
cat ../ocsp-config/$PROP_FILE | sed 's/\./_/' > .$PROP_FILE
. ./.$PROP_FILE
rm .$PROP_FILE -f
echo command=$COMMAND
echo db.driverClassName=$db_driverClassName
echo db.username=$db_username

#echo db.password=$db_password

DFLT_SCHEMA=

if [ "$db_driverClassName" = "com.ibm.db2.jcc.DB2Driver" ]; then
        echo "Database type: DB2"
        SEP=":currentSchema="
        db_schema=${db_url#*$SEP}
        db_url=${db_url%$SEP*}
        DFLT_SCHEMA="--defaultSchemaName=$db_schema"

        echo db.schema=$db_schema
        echo db.url=$db_url
else
        echo "Database type: -"
        echo db.url=$db_url
fi

liquibase/liquibase --url=$db_url --username=$db_username --password=$db_password --changeLogFile=$CHANGELOG_FILE --classpath=$JDBC_CP $DFLT_SCHEMA $COMMAND

