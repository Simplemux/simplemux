# simplemux_multiplexing_delay.pl version 1.1

# it is able to calculate the multiplexing delay of each packet, from a Simplemux output trace

# the result is in two columns:
# native_packet_id	multiplexing_delay(us)

# usage:

# $ perl simplemux_multiplexing_delay.pl <trace file> <output file>

$infile 	= $ARGV[0];			# name of the log file
$outfile	= $ARGV[1];			# name of the output file (by default it is STDOUT)


# call Linux "grep" to create two temporal files from the log file
# tmp_rec_native.txt	includes the native packets received by the ingress optimizer
# tmp_sent_muxed.txt	includes the multiplexed packets sent by the ingress optimizer
system ("grep 'rec'.'native' $infile > tmp_rec_native.txt");
system ("grep 'sent'.'muxed' $infile > tmp_sent_muxed.txt");

# open the two files
open (DATA_MUXED,"<tmp_sent_muxed.txt")
	|| die "Can't open tmp_sent_muxed.txt $!";

open (DATA_NATIVE,"<tmp_rec_native.txt")
	|| die "Can't open tmp_rec_native.txt $!";

# by default the output goes to STDOUT
if ($outfile eq undef) {
	$outfile = STDOUT;
} 
open (OUTPUT_FILE, ">>$outfile");

# print a line with the meaning of each column
printf $outfile "packet_id\tmultiplexing_delay(us)\n";

# variables for statistics
$num_muxed_packets = 0;			# the number of packets multiplexed into each bundle
$total_native_packets = 0;		# total amount of native packets
$cumulative_delay = 0;			# cumulative sum of the delay of each packet
$cumulative_delay_squares = 0;	# cumulative sum of the square of the delay of each packet

# while there are muxed packets in the log file
while (my $muxed_string = <DATA_MUXED>) {

	#x is the row of data
	my @x = split(' ', $muxed_string);

	# get the moment when the muxed packet has been sent
	$time_muxed_sent 	= $x[0];		#column 0 is time 
	$num_muxed_packets 	= $x[8];		#column 8 is the number of packets included in the bundle
	$last_packet_id 	= $x[4];		#column 4 is the identifier of the last native packet included in this multiplexed bundle

	# for each multiplexed packet
	#printf("$time_muxed_sent\t$num_muxed_packets\t$last_packet_id\n");

	# read the native packets file and write a line for each packet
	$i = 1;	# count the native packets

	while (($i <= $num_muxed_packets) && (my $native_string = <DATA_NATIVE>)) {
		#y is the row of data
		@y = split(' ',$native_string);
		if($y[4] <= $last_packet_id) {
			$mux_delay = $x[0]-$y[0];
			# for each native packet
			printf $outfile "$y[4]\t$mux_delay\n";
			$total_native_packets++;
			$cumulative_delay = $cumulative_delay + $mux_delay;
			$cumulative_delay_squares = $cumulative_delay_squares + ($mux_delay * $mux_delay);
		}
		$i++;		
	}
}


# delete the two temporal files
system("rm", "tmp_sent_muxed.txt");
system("rm", "tmp_rec_native.txt");

close DATA_MUXED;
close DATA_NATIVE;
close OUTPUT_FILE;

# calculate statistics and display them
$average_multiplexing_delay = $cumulative_delay / $total_native_packets;
$stdev_multiplexing_delay = sqrt (($cumulative_delay_squares - ($cumulative_delay * $cumulative_delay)/$total_native_packets)/($total_native_packets - 1));
printf STDOUT "total native packets:\t$total_native_packets\n";
printf STDOUT "Average multiplexing delay:\t$average_multiplexing_delay us\n";
printf STDOUT "stdev of the multiplexing delay:\t$stdev_multiplexing_delay us\n";

exit(0);
