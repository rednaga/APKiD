#!/bin/sh
# This will simply take the argument passed to it,
# parse the dirctory and bind it as a read-only mount point on the container
# and pass in the filename as the argument to apkid
#
# This can easily be set to an alias and added to your .profile or whatever

docker run --rm -v "`dirname $1`":/input:ro -i rednaga/apkid:v1  "`basename $1`";
