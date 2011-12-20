#! /bin/sh

dropdb $1
$OCFAROOT/bin/createdb.sh $1
