#!/usr/bin/perl

# this file adjusts the syslog-ng configuration entry for ocfa
# use rpm as an argument when running from rpm

use strict;
use warnings;
use File::Copy;

my $ORGFILE="/etc/syslog-ng/syslog-ng.conf.in";
my $NEWFILE="/etc/syslog-ng/syslog-ng.conf.in.new";
my $PATCHFILE="syslog-ng-patch";
my $PRINT="true";

# different path when building from rpm
foreach (@ARGV){
  $PATCHFILE="misc/syslog/syslog-ng-patch" if /rpm/;
}

# if the newfile exists throw it away
unlink $NEWFILE if (-f $NEWFILE);

open OLDFILE,"<$ORGFILE" or die "Cannot open file $ORGFILE";
open NEWFILE,">$NEWFILE" or die "Cannot open file $NEWFILE";

# first copy the file without the old ocfa entry
while (<OLDFILE>) {
  chomp;
  $PRINT=undef if (/^# OCFA-START/);
  
  print NEWFILE "$_\n" if $PRINT;
  $PRINT="true"  if (/^# OCFA-STOP/);
}

close OLDFILE;

# append the patch file
open PATCHFILE,"<$PATCHFILE";

print NEWFILE "# OCFA-START\n";
print NEWFILE $_ while (<PATCHFILE>);
print NEWFILE "# OCFA-STOP\n";

close PATCHFILE;
close NEWFILE;

`cp $NEWFILE $ORGFILE`;

# clean up the tempfile
unlink $NEWFILE if (-f $NEWFILE);
