# simplemux_throughput_pps.pl version 1.2

# it is able to calculate the throughput and the packet-per-second rate, from a Simplemux output trace

# the result is in three columns:
# tick_end_time(us)   throughput(bps)   packets_per_second

# usage:

# $perl simplemux_throughput_pps.pl <trace file> <tick(us)> <event> <type> <peer IP> <port>

# examples:

# $ perl simplemux_throughput_pps.pl tracefile.txt 1000000 rec native all all
# $ perl simplemux_throughput_pps.pl log_simplemux 1000000 rec muxed all all
# $ perl simplemux_throughput_pps.pl log_simplemux 1000000 rec muxed 192.168.0.5 55555
# $ perl simplemux_throughput_pps.pl log_simplemux 1000000 sent demuxed



$infile 	= $ARGV[0];			# name of the log file
$tick 		= $ARGV[1];			# the tick in microseconds
$event 		= $ARGV[2];			# can be "rec"(received), "sent", "forward" or "error". Put 'all' for any
$type 		= $ARGV[3];			# can be "native" "muxed" or "demuxed". Put 'all' for any
$peer_ip 	= $ARGV[4];			# the IP address of the peer. Put 'all' for any
$port 		= $ARGV[5];			# the port. Put 'all' for any


#we compute how many bits were transmitted during each time interval specified
#by tick parameter in microseconds
$num_bytes = 0;
$num_packets = 0;
$tick_begin = 0;

open (DATA,"<$infile")
	|| die "Can't open $infile $!";

if ($tick == 0)
{
	print STDOUT "Tick not specified\nuse:\nperl simplemux_throughput.pl <trace file> <tick(us)> <event> <type> <peer IP> <port>\n";
	exit;
}

# print a line with the meaning of each column
printf STDOUT "tick_end_time(us)\tthroughput(bps)\tpackets_per_second\n";

while (my $string = <DATA>) {

	#x is the row of data
	my @x = split(' ', $string);
	if ( $tick_begin == 0 )
	{
		$tick_begin = $x[0];
		$tick_initial = $tick_begin;
	}

	#column 0 is time 
	if ( $x[0] <= $tick_begin + $tick )
	{
		#checking if the event corresponds to the one specified by the user
		if (($x[1] eq $event) || ( $event eq 'all'))
		{ 
			#checking if the type corresponds to the one specified by the user
			if (($x[2] eq $type) || ( $type eq 'all'))
			{ 
				#checking if the peer IP corresponds to the one specified by the user
				if (($x[6] eq $peer_ip) || ( $peer_ip eq 'all'))
				{ 
					#checking if the port corresponds to the one specified by the user
					if (($x[7] eq $port) || ( $port eq 'all'))
					{
						# acumulating the data
						$num_bytes = $num_bytes + ( 8 * $x[3] ); #factor of 8 for passing to bits
						#print STDOUT "$x[3]\n";
						$num_packets = $num_packets + 1;
					}
				}
			}
		}

	} else {
		# a tick has finished
		$throughput = 1000000 * ( $num_bytes / $tick );
		$pps = 1000000 * ( $num_packets / $tick );
		$interval = $tick_begin - $tick_initial + $tick;
		print STDOUT "$interval\t$throughput\t$pps\n";

		$num_bytes = 0;
		$num_packets = 0;

		# get the data of the current packet for the next tick
		#checking if the event corresponds to the one specified by the user
		if (($x[1] eq $event) || ( $event eq 'all'))
		{ 
			#checking if the type corresponds to the one specified by the user
			if (($x[2] eq $type) || ( $type eq 'all'))
			{ 
				#checking if the peer IP corresponds to the one specified by the user
				if (($x[6] eq $peer_ip) || ( $peer_ip eq 'all'))
				{ 
					#checking if the port corresponds to the one specified by the user
					if (($x[7] eq $port) || ( $port eq 'all'))
					{
						# acumulating the data
						$num_bytes = ( 8 * $x[3] ); #factor of 8 for passing to bits
						#print STDOUT "$x[3]\n";
						$num_packets = 1;
					}
				}
			}
		}


		$tick_begin = $tick_begin + $tick;

		# for each tick without packets, write the tick_begin time and 0
		while ( $x[0] > $tick + $tick_begin )
		{
			$interval = $tick_begin - $tick_initial + $tick;
			print STDOUT "$interval\t0\t0\n";
			$tick_begin = $tick_begin + $tick;		
		}
	}
}

# last tick (it is incomplete so I do not calculate nor print the results)
#$interval = $x[0] - $tick_initial;
#$throughput = 1000000 * ( $num_bytes / $interval );
#$pps = 1000000 * ( $num_packets / $interval );
#print STDOUT "$interval\t$throughput\t$pps\n";


close DATA;
exit(0);
