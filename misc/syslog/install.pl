#!/usr/bin/perl
if (-f "/var/log/ocfa.log") {
  print "Syslog aparently already updated\n";
  exit;
}
if ($ARGV[0] eq "true") {
   print "PostInstall syslog_reconfig=true\n";
   $ans="y";
} elsif  ($ARGV[0] eq "true") {
   print "PostInstall syslog_reconfig=false\n";
   $ans="n";
} else {
  print "\n\n\n\n\nInstall script wants to update the syslog configuration\n";
  print "It will do this by overwriting (syslogd) or patching (syslog-ng) the\n";
  print "configuration file of your syslog daemon.\n";
  print "Given the impact on the syslog configuration of your system you may\n";
  print "wish to update syslog by hand. The open computer forensics architecture\n";
  print "will send all its logging to the 'user' facility. If you want to configure\n";
  print "the syslog daemon manualy you should do so by patching the config to send\n";
  print "all 'user' logging to a single file, for example /var/log/ocfa.log\n\n";
  while (($ans ne "y") && ($ans ne "n")) {
     print "do you want to this install script to overwrite your syslog config ? y/n :";
     $ans=<>;
     $ans =~ s/\r//;
     chomp($ans);
     $ans=lc($ans);
  }
}
if ($ans eq "n") {
   print "Skipping syslog reconfiguration\n";
   exit;
}
open(OLOG,">/var/log/ocfa.log")|| die "Problem creating /var/log/ocfa.log";
close(OLOG);
if (-f "/etc/syslog.conf") {
  print "Overwriting /etc/syslog.conf , backup can be found in /etc/syslog.conf.backup_ocfainstall\n";
  `cp /etc/syslog.conf /etc/syslog.conf.backup_ocfainstall`;
  `cp syslog.conf /etc/`;
}
if (-f "/etc/syslog-ng.conf") {
  print "Patching /etc/syslog-ng.conf , backup can be found in /etc/syslog-ng.conf.backup_ocfainstall\n";
  `cp /etc/syslog-ng.conf /etc/syslog-ng.conf.backup_ocfainstall`;
  `cat syslog-ng-patch >> /etc/syslog-ng.conf`;
}
if (-f "/etc/syslog-ng/syslog-ng.conf") {
    print "Patching /etc/syslog-ng/syslog-ng.conf , backup can be found in /etc/syslog-ng/syslog-ng.conf.backup_ocfainstall\n";
    `cp /etc/syslog-ng/syslog-ng.conf /etc/syslog-ng/syslog-ng.conf.backup_ocfainstall`;
    `cat syslog-ng-patch >> /etc/syslog-ng/syslog-ng.conf`;
}
if (-f "/etc/init.d/sysklogd") {
  print "Restarting sysklogd\n";
  `/etc/init.d/sysklogd restart`;
}
if (-f "/etc/init.d/syslog") {
  print "Restarting syslog\n";
  `/etc/init.d/syslog restart`;
}
if (-f "/etc/init.d/syslogd") {
  print "Restarting syslogd\n";
  `/etc/init.d/syslogd restart`;
}
if (-f  "/etc/init.d/syslog-ng") {
  print "Restarting syslog-ng\n";
  `/etc/init.d/syslog-ng restart`;
}
if (-f "/etc/init.d/syslogng") {
  print "Restarting syslogng\n";
  `/etc/init.d/syslogng restart`;
}

#
 
