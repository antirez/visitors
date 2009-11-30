#!/usr/bin/perl
#
# Use this tool to convert IIS logs into NCSA format that
# Visitors will be able to handle.
#
# make an IIS log look strikingly like an apache log
# we make a vague attempt to interpret the Fields: header
# in an IIS logfile and use that to make IIS fields match up
# with apache fields.
#
# Copyright jwa@jammed.com 12 Dec 2000
#
# This software is released under the GPL license
# as specified in the home page: http://www.jammed.com/~jwa/hacks/

while ($arg = shift @ARGV) {
	$tzoffset = shift @ARGV if ($arg eq "--faketz");
	$vhost = shift @ARGV if ($arg eq "--vhost");
	$debug = 1 if ($arg eq "--debug");	# show field interpretation
}	

if ($tzoffset eq "") {
	print STDERR "Will use -0000 as a fake tzoffset\n";
	$tzoffset = "-0000";
}

# build month hash
@m = ('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec');
while ($m = shift @m) {
	$month{++$n} = $m;
}

# an IIS log adheres to what's defined by 'Fields;'
# attempt to parse this, tagging 


LINE:
while ($line = <STDIN>) {
	$line =~ s/\r|\n//g;	# cooky DOS format
	if ($line =~ /^#Fields: /) {
		@line = split(" ", $line);
		shift @line; # shifts of #Fields
		# build a hash so we can look up a fieldname and 
		# have it return a position in the string
		undef %fieldh;
		$n = 0;	# zero-based array for split
		while ($l = shift @line) {
			$fieldh{$l} = $n++;
			print STDERR "$l is position $fieldh{$l}\n" if ($debug);
		}

	}
	next LINE if ($line =~ /^#/);

#Fields: date time c-ip cs-username s-sitename s-computername s-ip cs-method cs-
#uri-stem cs-uri-query sc-status sc-win32-status sc-bytes cs-bytes time-taken 
#s-port cs-version cs(User-Agent) cs(Cookie) cs(Referer)

	# this is really slow.  

	$date = yankfield("date");
	$time = yankfield("time");
	$ip = yankfield("c-ip");
	$username = yankfield("cs-username");
	$method = yankfield("cs-method");
	$stem = yankfield("cs-uri-stem");
	$query = yankfield("cs-uri-query");
	$status = yankfield("sc-status");
	#$bytes = yankfield("cs-bytes");
	# Which is it? sc-bytes or cs-bytes?  
	# cs-bytes only appears in some of the IIS logs I've seen.
	# I'll assume that sc-bytes is "server->client bytes", which 
	# is what we want anyway.
	$bytes = yankfield("sc-bytes");		# I'm gonna go with this.
	$useragent = yankfield("cs(User-Agent)");
	$referer = yankfield("cs(Referer)");

	$useragent =~ s/\+/\ /g;

	# our modified CLF sez:
	# IP - - [DD/MMM/YYYY:HH:MM:SS TZOFFSET] "method stem[?query]" status bytes "referer" "user agent" "vhost"

	# convert date 
	# 2000-07-19 00:00:01
	($y, $m, $d) = split("-", $date);
	$m =~ s/^0//g;
	$mname = $month{$m};

	# build url
	$url = $stem;
	if ($query ne "-") {
		$url .= "?$query";
	}

	# all done, print it out
	print "$ip - - [${d}/${mname}/${y}:${time} ${tzoffset}] \"$method $url\" $status $bytes \"$referer\" \"$useragent\" \"${vhost}\"\n";
}


# return the proper field, or "-" if it's not defined.
# (unfortunately ($date) = (split(" ", $line))[$fieldh{date}]; 
# will return element 0 if $fieldh{date} is undefined . . .)

sub yankfield {
	my ($field) = shift @_;

	print STDERR "Looking at $field; position [$fieldh{$field}]\n" if ($debug);

	if ($fieldh{$field} ne "") {
		return (split(" ", $line))[$fieldh{$field}];
	} else {
		print STDERR "$field undefined\n" if ($debug);
		return "-";
	}
}	

