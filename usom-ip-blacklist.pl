#!/usr/bin/perl -w
#######################
# v2.0
#######################

use File::Basename;
use lib dirname($0)."/lib";
use strict;
use warnings;
use LWP::UserAgent;
use Net::DNS::Resolver;
use File::Copy qw(copy);
use Encode;
use Term::ProgressBar;
  
my $debug = 0;  
my @whitelist_ips = ("0.0.0.0", "127.0.0.1", "8.8.8.8", "8.8.4.4");

my $usom_check_url = "https://www.usom.gov.tr/url-list.txt";
my $usom_raw_file = dirname($0)."/usom_raw.txt";
my $usom_ip_file = dirname($0)."/usom-ip-list.txt";
my $usom_out_file = dirname($0)."/usom-ip-list-output.txt";

unlink $usom_raw_file;

print "Usom Listesi indiriliyor...";

my $ua = LWP::UserAgent->new(max_redirect => 0);
$ua->ssl_opts( verify_hostname => 0 );
$ua->ssl_opts( SSL_verify_mode => 0 );
$ua->timeout(3);
		
my $response = $ua->get($usom_check_url, ':content_file' => $usom_raw_file);
if($response->is_error())
{
	print "\n\tUsom listesi indirilirken hata olustu: " . $response->status_line . "\n".$response->error_as_HTML."\n";
	exit;
}

print "bitti\n";
print "DNS isimleri cozuluyor...\n";

my $line_raw_file = &COUNT_RAW_FILE;
print "Usom Listesi Toplam Satir: " . $line_raw_file."\n";
print "Baslama Zamani: ".localtime . "\n";	

unlink $usom_ip_file;
unlink $usom_out_file;

open(RAWFILE, "<", $usom_raw_file) or die "Dosya Okuma Hatasi: $usom_raw_file";

my $baslama_zamani = localtime;	

my $count_line_raw_file = 0;
my $count_line_no_response = 0;
my $count_line_domainname = 0;
my $count_line_ipaddress = 0;
my $count_line_empty = 0;
my $count_line_error = 0;

my $line_outfile = "";
my $line_ip_list = "";

my $progress_bar;
if ($debug == 0){
	$progress_bar = Term::ProgressBar->new($line_raw_file);	
}
else{
	print "Debug mode acik:\n";
	print "\n\n#####################################################################\n";
}	
while(<RAWFILE>){
	$count_line_raw_file++;

	if($debug == 0){
		$progress_bar->update($count_line_raw_file);
	}
	
	my $line_raw_file=$_;
	$line_raw_file = FILTER_LINE($line_raw_file);
	
	# IP SATIRI:
	if($line_raw_file =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ ){
		$count_line_ipaddress++;
		print "ip_line:\t\t\t#$line_raw_file#\n" if($debug==1);
		$line_outfile .= "ip_line:\t\t\t#$line_raw_file#\n";
		$line_raw_file .= "\n";
	}
	# DOMAINNAME SATIRI:
	elsif ( ($line_raw_file !~ /^#/) && ($line_raw_file ne "")){    
		my $response2 = DNS($line_raw_file);
		if($response2 ne "no_response"){
			$count_line_domainname++;
			
			my $response3 = $response2;
			$response3 =~ s/\r|\n/, /g;
			
			my $line_raw_file1=$line_raw_file;
			
			my $whiteip_line = 0;
			foreach my $whiteip (@whitelist_ips) {
				if($response3 =~ /$whiteip/){
					#response hatalı olan satırları sıfırlıyoruz
					$count_line_error++;
					print "dns_line_whitelist_ip:\t\t$line_raw_file1 ip: $response3\n" if($debug==1);
					$line_outfile .= "dns_line_whitelist_ip:\t\t$line_raw_file1 ip: $response3\n";
					$line_raw_file = "";
					$whiteip_line = 1;
					last;
				}
			}
				
			if($whiteip_line == 0){
				print "dns_line_valid:\t\t\t$line_raw_file1 ip: $response3\n" if($debug==1);
				$line_outfile .= "dns_line_valid:\t\t\t$line_raw_file1 ip: $response3\n";
				$line_raw_file = $response2;
			}
		}
		else
		{
			$count_line_no_response++;
			print "dns_line_no_response:\t\t$line_raw_file\n" if($debug==1);
			$line_outfile .= "dns_line_no_response:\t\t$line_raw_file\n";
			#response olmayan satırları sıfırlıyoruz
			$line_raw_file = "";
		}	
	}
	# BOS ve ACIKLAMA SATIRI:
	else{
		$count_line_empty++;
		$line_raw_file = "";
	}
	$line_ip_list .= $line_raw_file;
}
close(RAWFILE);

&BLACKLIST_FILE;
&OUTFILE;

print "#####################################################################\n\n\n" if($debug==1);
print "Bitis Zamani: ".localtime . "\n\n";
print "Usom-IP Listesi Dosyasi:\t\t $usom_ip_file\n";
print "Usom IP Listesi Cikti Dosyasi:\t\t $usom_out_file\n";

	
###############################################################################
### FONKSIYONLAR
###############################################################################
sub FILTER_LINE {
	my $line = shift;
	$line = lc $line;
	
	# end of line, satır başı, satır başı boşluklar ve = in başındaki ve sonundaki boşluklar kaldırıldı.
	$line =~ s/\r|\n|^\s*|\s*$//g;  		
	
	# Türkçe karakter düzelt:
	$line =~ s/\xc3\xa7/c/g; # ç
	$line =~ s/\xc4\x9f/g/g; # ğ
	$line =~ s/\xc4\xb1/i/g; # ı
	$line =~ s/\xc3\xb6/o/g; # ö
	$line =~ s/\xc5\x9f/s/g; # ş
	$line =~ s/\xc3\xbc/u/g; # ü
		
	# http:// veya https:// kaldır:	
	if($line =~ m/https?:\/\/([^\/]+)(\/.*)?/){
		$line = $1;
	}
	# domainname'den uri kısmını kaldır:	
	elsif($line =~ m/([^\/]+)\/.*/){
		$line = $1;
	}
	return $line;
}

sub DNS {
	my $hostname = shift;
	my $res = Net::DNS::Resolver->new(
	  nameservers => [qw(8.8.8.8)],
	);

	my $query = $res->search($hostname);

	if ($query) {
	  my $record = "";
	  foreach my $rr ($query->answer){
		next unless $rr->type eq "A";
		$record = $record . $rr->address . "\n";
	  }
	  return $record;
	}
	else{
		return "no_response";
	}
}

sub BLACKLIST_FILE {
	open(IPFILE, ">$usom_ip_file") or die "Dosya Okuma Hatasi: $usom_ip_file";
	print IPFILE "#####################################################################\n";
	print IPFILE "# Usom IP Blacklist                                                 #\n";
	print IPFILE "# Generated on $baslama_zamani                             #\n";
	print IPFILE "#                                                                   #\n";
	print IPFILE "# Powered by hilmiesen                                              #\n";
	print IPFILE "# For Questions and Issues: info\@tnetworks.com.tr                   #\n";
	print IPFILE "#####################################################################\n";

	my @iplist1 = split("\n",$line_ip_list);

	#Sort edildi.
	@iplist1 = map {sprintf "%d.%d.%d.%d", split /\./} sort map {sprintf "%03d.%03d.%03d.%03d", split /\./} @iplist1;

	#uniq yapıldı
	my %counts;
	@iplist1 = grep !$counts{$_}++, @iplist1;

	foreach (@iplist1)
	{
		print IPFILE "$_\n"; # Print each entry in our array to the file
	}
	close(IPFILE);
}

sub OUTFILE {
	open(OUTFILE, ">$usom_out_file") or die "Dosya Okuma Hatasi: $usom_out_file";
	$count_line_raw_file = $count_line_raw_file - $count_line_empty;
	$count_line_domainname = $count_line_domainname - $count_line_error;

	print OUTFILE "############################################################\n";
	print OUTFILE "# Usom IP Blacklist Output File                            #\n";
	print OUTFILE "# Powered by hilmiesen                                     #\n";
	print OUTFILE "#                                                          #\n";

	$baslama_zamani .= (" " x (60 - 15 - length($baslama_zamani)));
	print OUTFILE "# Start Time: $baslama_zamani#\n";

	my $bitis_zamani = localtime . (" " x (60 - 13 - length(localtime)));
	print OUTFILE "# End Time: $bitis_zamani#\n";
	print OUTFILE "#                                                          #\n";

	$usom_check_url .= (" " x (60 - 13 - length($usom_check_url)));
	print OUTFILE "# Usom URL: ".$usom_check_url."#\n";
	print OUTFILE "#                                                          #\n";

	$count_line_raw_file      .= (" " x (60 - 30 - length($count_line_raw_file)));
	$count_line_ipaddress   .= (" " x (60 - 30 - length($count_line_ipaddress)));
	$count_line_domainname  .= (" " x (60 - 30 - length($count_line_domainname)));
	$count_line_error .= (" " x (60 - 30 - length($count_line_error)));
	$count_line_no_response   .= (" " x (60 - 30 - length($count_line_no_response)));

	print OUTFILE "# Total Line               : $count_line_raw_file#\n";
	print OUTFILE "# IP Line                  : $count_line_ipaddress#\n";
	print OUTFILE "# Valid Domain Line        : $count_line_domainname#\n";
	print OUTFILE "# Invalid Domain Line      : $count_line_error#\n";
	print OUTFILE "# No Response Domain Line  : $count_line_no_response#\n";
	print OUTFILE "#                                                          #\n";
	print OUTFILE "############################################################\n";

	print OUTFILE $line_outfile;

	close(OUTFILE);


}

sub COUNT_RAW_FILE {
	open(RAWFILE, "<", $usom_raw_file) or die "Dosya Okuma Hatasi: $usom_raw_file";
	my $count = 0;
	while(<RAWFILE>){
		$count++;
	}
	close(RAWFILE);
	return $count;
}