#!/bin/sh

## resolve links - $0 may be a symlink
PRG="$0"
while [ -h "$PRG" ] ; do
  ls=`ls -ld "$PRG"`
  link=`expr "$ls" : '.*-> \(.*\)$'`
  if expr "$link" : '/.*' > /dev/null; then
    PRG="$link"
  else
   PRG=`dirname "$PRG"`"/$link"
  fi
done

THIS_HOME=`dirname "$PRG"`

# make it fully qualified
export XIPKI_HOME=`cd "$THIS_HOME/.." && pwd`
export LIQUIBASE_HOME="$XIPKI_HOME/sql/liquibase"

DBCONF_FILE=$XIPKI_HOME/ca-config/ca-db.properties
CHANGELOG_FILE=$XIPKI_HOME/sql/ca-init.xml

$THIS_HOME/init-db.sh dropAll $DBCONF_FILE $CHANGELOG_FILE
echo ""
echo ""

$THIS_HOME/init-db.sh update $DBCONF_FILE $CHANGELOG_FILE
echo ""
echo ""

DBCONF_FILE=$XIPKI_HOME/ocsp-config/ocsp-publisher.properties
CHANGELOG_FILE=$XIPKI_HOME/sql/ocsp-init.xml

$THIS_HOME/init-db.sh dropAll $DBCONF_FILE $CHANGELOG_FILE
echo ""
echo ""

$THIS_HOME/init-db.sh update $DBCONF_FILE $CHANGELOG_FILE

