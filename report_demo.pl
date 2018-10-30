#!/usr/bin/perl 
#
# This is the Hugh Buntu github branch for public posting
# Hastily written and shipped out.
# This is proprietary code. Its' purpose and use are not documented here. Sorry.
#
# WARNING! Production Code! Run by cron nightly!
#
# The BIG report. Designed to be run by cron at 11:59PM (23:59) log time.
# Get the date, then sleep for a couple of minutes and process.
#
# The objective here is to get as much done in one pass as possible,
# So the file iteration loop parses and organizes the data,
# and then various loops organize and display the data in different ways.
#
# (C) 2018 Hugh Buntu, ALL RIGHTS RESERVED  hugh@sogomail.com
# This code is for viewing purposes only and in this redacted version,
# nothing is promised to work.
#
require "ctime.pl";
require 'timelocal.pl';

# Configuration variables

$logfilename = "access_log";   # Apache format log file


# Get enough date information so we can filter log records for the day
# we are reporting on.


$thismonth = (Jan,Feb,Mar,Apr,May,Jun,Jul,Aug,Sep,Oct,Nov,Dec)[(localtime)[4]];
$thisday = (localtime)[3];
$thisyear = 1900 + (localtime)[5];

$targetdate = "$thismonth/$thisyear";
$targetdate = "Aug/2018";

print("Report for: $targetdate \n");

#
# First, load up the master w6 keyword list
#
# Read list of predefined keywords, and define them in array %defkeys
# Henceforth, writes to this array must be checked beforehand
# by testing to see if the desired key is defined. In this way we
# know which keywords are predefined, and can then count, log, etc.
#

# update keywords
system("( cd /usr/local/www/comnet/searchcache ; ls -1 ) >./keywords.txt");
#
open(PKEYS,"<keywords.txt") ||
	die("Can't open keywords.txt input file\n");

while(<PKEYS>)
	{
	if(length($_) < 2) { next; }
	$keycount++;
	chop $_;
	$thiskey = $_;
	#print("$thiskey \n");
	$defkey{$thiskey} = 0;
	}
print("Found $keycount keys in keywords.txt...\n");

#
# Additionally, open a W6 IP Address Output File for later use...
#
open(W6IP,">w6IPs.dat") || die("Can't open w6IPs.dat output file\n");

#
# Read in the access log...
#
#open(LOG,"<".$logfilename) ||
#	die("ERROR!!! Can't open $logfilename!!\n");
while(<>)
	{
	# Skip records that aren't of interest
	if(!/$targetdate/) { next; }
	# Parse the log record
	($ip,$dash1,$dash2,$datetime,$tzoff,$req,$reqURI,
		$http_ver,$result,$bytes,$referer,$client) = split(' ',$_);

	# ---------- Filter out known testing IPs ----------
	#if($ip eq "127.0.0.1") { $our_recs++; next; }

	# Keep track of server result codes
	$result_codes{$result}++;
	if($result eq "413") { print("$_"); }

	# --- COUNT AD BEACONS -----------------------------------------------
	# TEMPORARY TEST WEB BEACON FOR ADSENSE
	if( /test333\/1pixel.gif/ ) { $adsense++; }
	# Web Beacons for Livedoor
	if( /\/wb\/livedoor_1_cn.gif/ ) { $livedoor_1_cn++ }
	# TEMPORARY TEST WEB BEACON FOR ADSENSE
	if( /testYYY\/1pixel.gif/ ) { $Yahoo_adw++; }

	# --- DENIAL OF SERVICE (DDOS DOS) DATA -----------------------------
	# Count DOS problems: ticken, instutio
	if ( /ticken/ ) { $dos_ticken++; }
	if ( /instituto/ ) { $dos_instituto++; }

	# Count calls to G*Words script [redacted]
	if( /gwords_script.html/ ) { $g_words_script++; }
	if( /google_adsense_script.html/ ) { $google_demurs++; }


	# Look only at GETs of interest
	# eg. not the logo, dummy
	if( ($reqURI ne "/") && (substr($reqURI,0,2) ne "/?") )
		{ next; } 

	# Keep track of hits in each hour of the day, an array
	# of %hour{00..24}
	($logdate,$hour,$min,$sec,$sploodge) = split(':',$datetime);
	$loghour{$hour}++;

	# ---------- Find the keyword -------------
	$mypos = index($reqURI,"mysearch");	# find "mysearch"
   if($mypos > 1)
        {
	$keyword = substr($reqURI,$mypos);	# extract starting there
	$amppos = index($keyword,"&");		# find loc of & if any
	if($amppos > 1)				# if &, cut 'er off
		{ $keyword = substr($keyword,0,$amppos); }
	$keyword =~ s/\"//;			# eliminate " if any
	($junk,$key) = split('=',$keyword);	# eliminate "mysearch="

	# Unpack/decode several times,  because text may
	# have been multiply encoded. Depth determined by experimentation!
	$key =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C",hex($1))/ge;
	$key =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C",hex($1))/ge;
	$key =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C",hex($1))/ge;
	$key =~ s/\+/ /g;			# eliminate +'s
	} else { $key = "-"; }			# no key

	# ---------- Find the Mode ----------
	$mypos = index($reqURI,"mode");	# find "mysearch"
	if($mypos > 1)
	    {
	    $mymode = substr($reqURI,$mypos);		# extract starting there
	    $amppos = index($mymode,"&");		# find loc of & if any
	    if($amppos > 1)				# if &, cut 'er off
		{ $mymode = substr($mymode,0,$amppos); }
	    $mymode =~ s/\"//;			# eliminate " if any
	    ($junk,$mode) = split('=',$mymode);	# eliminate "mode="
	    }
        else { $mode = ""; }
	#
	# ---------- Record W6 Hits ----------
	#
	#if($mode eq "w6")
	if(1)
		{
		#if(undef($defkey{$key}))	# check master list
		#    {
		#    $defkey{$key} = 1;		# mark as encountered
		#    }
		if(defined($defkey{$key}))
			 { $defkey{$key}++; }    # mark as encountered
		# 8/11/2011 - below: huh?
		$keyhits_w6{$key}++; 		# record w6 hits
		$cnt_keyhits_w6++;		# count total
		print(W6IP "$ip\n");		# save IP for later
		}
		else { $keyhits{$key}++; 	# record other hits
			$cnt_keyhits_user++; }
	
	# ---------- Look at the referer URL ----------
	$referer =~ s/\"//g;	# clean quotes off it
	$refpages{$referer}++;	# get a count of each referer


	}	

#
# START OUTPUT - Done with the file, now work on the data...
#

print("Notes: w6 reporting is undergoing an overhaul as a new
        system for mapping w6 addresses to targets is put in place.
        web beacon reporting is accurate at this time.\n\n");
print("Report for date: $targetdate\n\n");
print("Total number of AdSense Control Panel Beacons found: $adsense \n");
print("Total number of Yahoo! Control Panel Beacons found: $Yahoo_adw \n");
print("Total number of AdSense demurs to display: $google_demurs (control column collapsed)\n");
print("Total number of G*Words Script Calls.....: $g_words_script \n");
print("Total number of Livedoor (cn) popups for Accoona: $livedoor_1_cn \n");
print("Total number of W6 hits: $cnt_keyhits_w6 \n");
print("Total number of user search hits: $cnt_keyhits_user \n");
print("DoS Problem logging...\n");
print("Total number of ticken hits: $dos_ticken \n");
print("Total number of instituto hits: $dos_instituto \n");
$grandtotalhits =  ($cnt_keyhits_user + $cnt_keyhits_w6) ;
print("Grand Total of hits: $grandtotalhits");
print("\n\n");


sub	by_key {
		$keyhits{$b} <=> $keyhits{$a};
		}

sub	by_w6_key {
		$keyhits_w6{$b} <=> $keyhits_w6{$a};
		}


	$minkeyhits_w6 = 100;
	print("-------------------- Keys by W6 Hits ----------------------\n");
	print("Keys with hit count less than $minkeyhits_w6 are not shown for brevity\n");
	print("The first hit is always followed by two Google crawler hits\n");
	$line_number = 1;
	foreach ( sort by_w6_key keys %keyhits_w6 )
		{
		if($keyhits_w6{$_} > $minkeyhits_w6) {
		    if($defkey{$_} < 2) {	# check master list
		        #if($_ eq "GoogleMore") {
		        if(1) {
			    $googlepercent = ($keyhits_w6{$_} / $grandtotalhits);
			    printf("%03d %05d %-32.32s %-1.3f \n",$line_number,$keyhits_w6{$_},
				$_,$googlepercent);
			    } else {
			    printf("%03d %05d %-68.68s\n",$line_number,$keyhits_w6{$_},$_);
			    }
			$line_number++;
			}
		    }
		}


	print("---------------------- Keys by Hits ------------------------\n");
	print("Note: Only keys hit >3 times shown\n");
	$line_number = 1;
	foreach ( sort by_key keys %keyhits )
		{
		if($keyhits{$_} > 100)
		  {
		  printf("%03d %05d %-72.72s\n",$line_number,$keyhits{$_},$_);
		  $line_number++;
		  }
		}
#
# 8/11/2011 new $defkey code here
#
# This sorts in descending order of hits
sub	by_defkey {
		$defkey{$b} <=> $defkey{$a};
		}
	print("---------------------- Searchcache by Hits ------------------------\n");

	$line_number = 1;
	foreach ( sort by_defkey keys %defkey )
		{
		if($defkey{$_} > 100) {
		  $srchcachename = $_;
		  if( -l "/usr/local/www/comnet/searchcache/$_") {
			$srchcachename = $_ . "*"; }
		  printf("%03d %05d %-68.68s\n",$line_number,$defkey{$_},
			$srchcachename );
		  $line_number++;
		  }
		}
	print("\n\n");

# This sorts in descending order of hits
sub	by_referer {
		$refpages{$b} <=> $refpages{$a};
		}

	print("------------------- Referers by Hits ---------------------\n");
	print("Note: Only referrers hit >4 times shown\n");
	$line_number = 1;
	foreach ( sort by_referer keys %refpages )
		{
		if($refpages{$_} > 4) {
			# correct "-" to read in english for tedd
			my($cnt);
			$cnt = $refpages{$_};
			if($_ eq "-") { $_ = "[Direct Entry]"; }
			printf("%03d %06d %-69.69s\n",$line_number,$cnt,$_);
			$line_number++;
			}
		}

print("\n\n\nWeb Server Result Codes (by code #; see www.apache.org version2.0)\n\n");

	$status_code{200} = "OK";
	$status_code{206} = "Partial Content";
	$status_code{302} = "Found";
	$status_code{304} = "Not Modified";
	$status_code{316} = "Illegal Form Submit Method";
	$status_code{400} = "Bad Request";
	$status_code{404} = "Not Found";
	$status_code{413} = "Not Found; always following a 404 ?!?! Parse error?";
	$status_code{501} = "Not Implemented";
	$status_code{505} = "HTTP Vers Not Supported";


	foreach ( sort keys %result_codes )
		{
		printf("%4.4d %6.6d %s\n",$_,$result_codes{$_},$status_code{$_});
		}




print("[end of hit based report]\n\n");

close(PKEYS);

### TO DO: BLOW AWAY ARRAYS TO RECLAIM MEMORY HERE

#====================================================================#
#								     #
#                This Section looks at the CPC Log		     #
#								     #
#====================================================================#
if(0) {


#
# Report on CPC income by keyword. A bit klugy. Date unknown; ~July 30
#

open(REDIR,"<comnet-redir-access.log") ||
	die ("ERROR: Can't open redirection log!!\n");

while(<REDIR>)
	{
        if(!/$targetdate/) { next; }

	# ------ Part 1 ------------
        @spaces = split(' ',$_);
        $ip = $spaces[0];
        $ltime = $spaces[3];
        $ltime =~ s/\[//;               # leaning toothpick syndrome
        $ltime =~ s/\:/ /;              # first : only
        ($referer,$junk) = split('\?',$spaces[10]);  # parse referrer
        $referer =~ s/\"//;             # nail leading double quote
        chop($referer);                 # nail trailing quote
        ($parg,$sarg,$junk) = split('&',$spaces[6]); # GET data
        ($junk,$cpc) = split('=',$parg);
        ($junk,$key,$key2) = split('=',$spaces[10]);
        $mode = "ni";
        if(substr($key,0,2) eq "w6") {
                ($mode,$junk)=split('\&',$key); $key=$key2;
		#$mode = "w6";  #statement above not working right?
		}
#print("Mode = $mode \n");
        chop($key);
	# Validate based on idea that 9.99 is max CPC (false assumption!)
	# We probably need to to_upper() and otherwise clean up keys here
        if(length($cpc) == 4)
                {
		# Aggregate variables into a record if needed...
                $mydata = "$ltime|$ip|$cpc|$key|$mode|$referer";
		#
		# for defined W6 keywords, track:
		#	%defkey_cpc_hits  = # of hits
		#	%defkey_cpc_total = total $ amount racked up
		#	%defkey_cpc_min   = minimum yield for a hit
		#	%defkey_cpc_max   = maximum yield for a hit
		#
		if( $mode eq "w6" )		# allow self-defining
		    {
		if(undef($defkey{$key})) {
		   $defkey{$key} = 1; }		# mark as encountered
		    }	


		    if($mode eq "w6") {
		    	$defkey_cpc_hits{$key}++;
		    	$defkey_cpc_total{$key} += $cpc;
			    if($defkey_cpc_min{$key} == 0)	# must init
				{ $defkey_cpc_min{$key} = $cpc; }
			    if($cpc < $defkey_cpc_min{$key})
				{ $defkey_cpc_min{$key} = $cpc; }
			    if($cpc > $defkey_cpc_max{$key})
				{ $defkey_cpc_max{$key} = $cpc; }
			    }

                if($cpc < 1) {			# NOT A VALID ASSUMPTION!
			$total += $cpc;	# grand total CPC
			if( $mode eq "w6" ) {
				$total_w6 += $cpc;
				}
			if( $mode eq "ni" ) {
				$total_ni += $cpc;
				}
			}
		$goodhits++;				# # of validated pays
                }
	else { $junkhits++;				# unvalidated hits
		print("$ltime|$ip|$cpc|$key|$mode|$referer \n");
		next; }

	$_ = $mydata;	# start all over again for part 2 :-D	

	# -------- Total Income by Keyword ----------
	# This will become obsolete as %defkey_* variable code is implemented

	@Flds = split('\|',$_);
	# get total income by keyword
	$keytotal{$Flds[3]} = ($keytotal{$Flds[3]} + $Flds[2]);
	#print(">>> $Flds[2]  @  $keytotal{$Flds[3]} \n");
	}

	# ----------------- Report Generation Section -----------------------

sub	by_keytotal {
		$keytotal{$b} <=> $keytotal{$a};
		}


	print("\n\n----- Keyword Income Report ------\n");
	foreach ( sort by_keytotal keys %keytotal )
		{
		s/' '//g;
		$keyname = $_;
		if($keyname eq "") { $keyname = "Unknown?"; }
		printf("%-24.24s %03.2f\n",$keyname,$keytotal{$_});
		$total_num_pay_keys++;
		}
	print("\nThere were a total of $total_num_pay_keys paying keywords.\n");

	#
	# Take two, using %defkey variables...
	#
	#	%keyhits_w6	  = # of W6 hits
	#	%defkey_cpc_hits  = # of CPC yields
	#	%defkey_cpc_total = total $ amount racked up
	#	%defkey_cpc_min   = minimum yield for a hit
	#	%defkey_cpc_max   = maximum yield for a hit

sub	by_defkeytotal {
		$defkey_cpc_total{$b} <=> $defkey_cpc_total{$a};
		}

	#
	# calculate efficiency
	#
	# - if we want to sort by efficiency, we need to calculate it
	#   first in a separate loop and then modify the sort procedure
	#

	print("\n\n----- W6 Defined Keyword Efficiency and Total Report -----\n");
	print("HTC = #hits on keywrd to yield a penny\n"
             ."CTC = #clickthrus on keywrd to yield a penny\n"
             ."Minpay = least amount paid for a clickthru for this keywrd\n"
             ."Maxpay = highest amount paid for a clickthru for this keywrd\n"
	     ."Total = total amount paid for this keyword\n"
	     ."#CPC = number of paying clickthrus generated by this keywrd\n"
	     ."All defined W6 keywords are listed including those without hits.\n"
	     ."List is separately maintained and may not be up to date or\n"
             ."accurate for the period being reported on.\n");
	print("Note: if #CPC's exceeds #of Hits, something is wrong with the data\n"
		. "for a given keyword, and yield value is erroneous!\n");
	print("Keyword           Hits   CPC's    Minpay   Maxpay  HTC    CTC     Total\n");
	print("-------           ----   -----    ------   ------  ---    ---     -----\n");
	foreach ( sort by_defkeytotal keys %defkey )
		{
		my($key,$keyshow,$eff_hit,$eff_click);
		$key = $_;
		$keyshow = $key;
		if($defkey{$key} > 0)
			{ $keyshow = $key . "*"; }
		if($defkey_cpc_total{$key} eq "")
			{ $defkey_cpc_total{$key} = 0; }
		if($defkey_cpc_total{$key} > 0) {
			$eff_hit = $keyhits_w6{$key} / ($defkey_cpc_total{$key} * 100);
			$eff_click = $defkey_cpc_hits{$key} / ($defkey_cpc_total{$key} * 100);
			}
		else { $eff_hit = 0; $eff_click = 0; }
		if($defkey_cpc_max{$key} eq "") { $defkey_cpc_max{$key} = 0; }
	if( $defkey_cpc_total{$key} > 0 )
		{
		printf("%-16.16s  %05d  %03d      %03.2f     %03.2f  %6.2f %6.2f    \$%03.2f \n",
			$keyshow, $keyhits_w6{$key}, $defkey_cpc_hits{$key},
			$defkey_cpc_min{$key},
			$defkey_cpc_max{$key},
			$eff_hit,$eff_click,
			$defkey_cpc_total{$key} ); 
		} # endif money, print
		}

	print("===========================================================\n");
	print("Good clickthru hits = $goodhits \n");
	print("Junk clickthru hits = $junkhits (non-processable redirects)\n");
	print("Total value of good clickthru hits = \$" . $total . "\n");
	printf("Total value of W6 hits: %03.2f \n", $total_w6 );
	printf("Total value of Organic (NI) hits: %03.2f \n", $total_ni );

	if( ($total != 0) && ($grandtotalhits != 0) ) {
		$hitvalue = $total / $grandtotalhits; }
	print("Averaged value of each hit: $hitvalue \n");
	if( ($grandtotalhits > 0) && ($goodhits > 0) ) {     # check div-by-0
		$hitratio = $grandtotalhits / $goodhits;
		}
	print("Ratio of all hits to paying hits: $hitratio \n");




} # end of if(0) disabling CPC reporting

#=============================== END OF CPC SECTION ========================


	print("\n==================== PERFORMANCE ==========================\n");
	print("Hits by the hour: If an hour is missing, there are no hits
and the server or the link was probably down during that hour.

Hour  #Hits \n");
	foreach ( sort keys %loghour )
		{
		printf("%02d    %05d\n",$_,$loghour{$_});
		}


#
# Close the W6 IP file and report
#
close(W6IP);

	print("[end of report]\n\n");


#
# End
#
