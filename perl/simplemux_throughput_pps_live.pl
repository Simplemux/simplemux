# simplemux_throughput_pps.pl version 1.4

# it is able to calculate the throughput and the packet-per-second rate, from a Simplemux output trace

# the result is in three columns:
# tick_end_time(us)   throughput(bps)   packets_per_second

# usage:

# $perl simplemux_throughput_pps.pl <tick(us)> <peer IP> <port>

# examples:

# $ perl simplemux_throughput_pps_live.pl 100000 2 192.168.0.5 all

# Print the native and muxed throughput and pps
# $ ./simplemux_1.6.21 -i tun0 -e eth0 -c 192.168.0.5 -M N -d 0 -r 2 -l stdout | perl simplemux_throughput_pps_live.pl 100000 2 192.168.0.5 all

$tick 		= $ARGV[0];			# the tick in microseconds
$bw_pps		= $ARGV[1];			# 0	calculate only BW
						# 1 calculate only pps
						# 2 calculate both
$peer_ip 	= $ARGV[2];			# the IP address of the peer. Put 'all' for any
$port 		= $ARGV[3];			# the port. Put 'all' for any


#we compute how many bits were transmitted during each time interval specified
#by tick parameter in microseconds
$num_bytes = 0;
$num_packets = 0;
$current_tick_begin = 0;	#the time of the beginning of the current tick
$initial_timestamp = 0;

my $calculate_BW = 0;
my $calculate_pps = 0;

if ($bw_pps == 0) {
	$calculate_BW = 1;
} elsif ($bw_pps == 1) {
	$calculate_pps = 1;
} elsif ($bw_pps == 2) {
	$calculate_BW = 1;
	$calculate_pps = 1;
} else {
	print STDOUT "Parameter BW_pps not specified or not correct. It must be 0 (BW), 1 (pps) or 2 (BW and pps)\n";
	exit;
}

if ($tick == 0)
{
	print STDOUT "Tick not specified\n";
	exit;
}

# print a line with the meaning of each column
# printf STDOUT "tick_end_time(us)\tthroughput(bps)\tpackets_per_second\t$peer_ip\t$port\n";

while (<STDIN>) {

	my $line = $_;
	chomp($line);

	# x is the row of data
	my @x = split(' ', $line);

	# this is only ran the first time
	# get the first timestamp and store it in 'initial_timestamp' and in 'current_tick_begin'
	if ( $current_tick_begin == 0 )
	{
		$current_tick_begin = $x[0];
		$initial_timestamp = $current_tick_begin;
		#printf STDOUT "initial timestamp: $initial_timestamp. current_tick_begin: $current_tick_begin\n";
	}

	# I only consider the lines where the events are

	#timestamp rec native
	#timestamp rec muxed
	#timestamp sent muxed
	#timestamp sent demuxed

	#column 0 is the timestamp
	if ( $x[0] > $current_tick_begin + $tick )
	{ 
		# a tick has finished
		$throughput_native = 1000000 * ( $num_bytes_native / $tick );
		$pps_native = 1000000 * ( $num_packets_native / $tick );

		$throughput_muxed = 1000000 * ( $num_bytes_muxed / $tick );
		$pps_muxed = 1000000 * ( $num_packets_muxed / $tick );

		$interval = $current_tick_begin - $initial_timestamp + $tick;

#		printf STDOUT "native\t$interval\t$throughput_native\t$pps_native\n";
#		printf STDOUT "muxed\t$interval\t$throughput_muxed\t$pps_muxed\n";



		if ($calculate_BW == 1) {
			# 0: native throughput
			printf STDOUT "0:$throughput_native\n";
			# 1: muxed throughput
			printf STDOUT "1:$throughput_muxed\n";
		}

		if ($calculate_pps == 1) {
			# 2: native pps
			printf STDOUT "2:$pps_native\n";
			# 3: muxed pps
			printf STDOUT "3:$pps_muxed\n";
		}
		$num_bytes_native = 0;
		$num_packets_native = 0;

		$num_bytes_muxed = 0;
		$num_packets_muxed = 0;

		$current_tick_begin = $current_tick_begin + $tick;
	}

#printf STDOUT $x[1];
	if ( ($x[1] eq 'rec' ) && ($x[2] eq 'native') ) {

		# acumulating the data
		$num_bytes_native = $num_bytes_native + ( 8 * $x[3] ); #factor of 8 for passing to bits
		$num_packets_native = $num_packets_native + 1;

	} 
	elsif ( ($x[1] eq 'rec' ) && ($x[2] eq 'muxed') ) {

		#checking if the peer IP corresponds to the one specified by the user
		if (($x[6] eq $peer_ip) || ( $peer_ip eq 'all') || ( $peer_ip eq ''))
		{ 
			#checking if the port corresponds to the one specified by the user
			if (($x[7] eq $port) || ( $port eq 'all') || ( $port eq ''))
			{
				# acumulating the data
				$num_bytes_muxed = $num_bytes_muxed + ( 8 * $x[3] ); #factor of 8 for passing to bits
				$num_packets_muxed = $num_packets_muxed + 1;

			}
		}
	} 
	elsif ( ($x[1] eq 'sent' ) && ($x[2] eq 'muxed') ) {

		#checking if the peer IP corresponds to the one specified by the user
		if (($x[6] eq $peer_ip) || ( $peer_ip eq 'all') || ( $peer_ip eq ''))
		{ 
			#checking if the port corresponds to the one specified by the user
			if (($x[7] eq $port) || ( $port eq 'all') || ( $port eq ''))
			{
				# acumulating the data
				$num_bytes_muxed = $num_bytes_muxed + ( 8 * $x[3] ); #factor of 8 for passing to bits
				$num_packets_muxed = $num_packets_muxed + 1;

			}
		}
	}
	elsif ( ($x[1] eq 'sent' ) && ($x[2] eq 'demuxed') ) {

		# acumulating the data
		$num_bytes_native = $num_bytes_native + ( 8 * $x[3] ); #factor of 8 for passing to bits
		$num_packets_native = $num_packets_native + 1;


	} 
	else {

	}

	# for each tick without packets, write the current_tick_begin time and 0
	while ( $x[0] > $current_tick_begin + $tick )
	{
		$interval = $current_tick_begin - $initial_timestamp + $tick;

		#printf STDOUT "native\t$interval\t0\t0\n";
		#printf STDOUT "muxed\t$interval\t0\t0\n";

		if ($calculate_BW == 1) {
			# 0: native throughput
			printf STDOUT "0:0\n";
			# 1: muxed throughput
			printf STDOUT "1:0\n";
		}

		if ($calculate_pps == 1) {
			# 2: native pps
			printf STDOUT "2:0\n";
			# 3: muxed pps
			printf STDOUT "3:0\n";
		}
		$current_tick_begin = $current_tick_begin + $tick;		
	}
}

# last tick (it is incomplete so I do not calculate nor print the results)
#$interval = $x[0] - $initial_timestamp;
#$throughput = 1000000 * ( $num_bytes / $interval );
#$pps = 1000000 * ( $num_packets / $interval );
#print STDOUT "$interval\t$throughput\t$pps\n";


close DATA;
exit(0);
