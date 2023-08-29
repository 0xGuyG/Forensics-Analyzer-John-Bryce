#!/bin/bash

start=$(date +%s)

#this function ensures the user runs the script as root

function Root(){
	G=$(groups)
	
	if [ $G == root ]
	then echo "[+] You are $G" 
	else echo "[!] Please run the script as root"
	exit
	fi
}
Root

#this function installs all necessary tools

function Install(){
	cd
	
	sudo apt update
	sudo apt-get install binutils -y
	sudo apt-get install binwalk -y
	sudo apt-get install bulk-extractor -y
	sudo apt-get install foremost -y
	
	if [ -d volatility_2.6_lin64_standalone ]
	then echo "Volatility Exists"
	else sudo wget http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip
	unzip volatility_2.6_lin64_standalone.zip
	echo "Volatility Installed"
	fi
	
	Bulk=$(which bulk_extractor) 
	if [ $Bulk == 0 ]
	then sudo apt-get install bulk-extractor -y
	else echo "bulk extractor was installed"
	fi
	
	Binwalk=$(which binwalk) 
	if [ $Binwalk == 0 ]
	then sudo apt-get install binwalk -y
	else echo "binwalk was installed"
	fi
	
	Foremost=$(which foremost) 
	if [ $Foremost == 0 ]
	then sudo apt-get install foremost -y
	else echo "foremost was installed"
	fi
	
	Strings=$(which strings) 
	if [ $Strings == 0 ]
	then sudo apt-get install binutils -y
	else echo "strings was installed"
	fi
}
Install

#this function takes a file as input from the user

function Input(){
	echo "[!] Please input absolute path of file:"
	read in
	if [ -e $in ]
	then echo "[+] File exists"
	else echo "[X] File does not exist" 
	exit
	fi
}
Input
	
#this function extracts the data from the file using binwalk, bulk extractor and foremost as well as acquiring human readables 

function Extract(){
	W=$(whoami)
	echo "[+] Extracting info now from given file into ~/Desktop/Output"
	
	cd
	mkdir Output
	
	sudo bulk_extractor $in -o ~/Output/bulk_extractor
	binwalk -e $in --run-as=root -C ~/Output/binwalk
	foremost -i $in -o ~/Output/foremost
	echo "[+] All data has been carved from $in"
	
	cd /$W/Output
	P=$(locate packets.pcap | grep -i output)
	S=$(ls -sh "$P" | awk '{print $1}')
	echo "[+] The network file location is $P and it's size is $S"
	strings $in > strings_output.txt
	
	echo "[+] The exe files extracted are:"
	ls "/$W/Output/foremost/exe"  
	
	cd /$W/Output
	cat strings_output.txt | grep -i password > pass.txt
	echo "The Passwords from $in were saved at pass.txt"
	
} 
Extract

#this function runs various volatility information extractions 

function Volatility(){
	PROFILE=$(cat .tmp | grep Suggested | awk '{print $4}' | sed 's/,//g')
	mkdir /$W/Output/Volatility
	cd ~/volatility_2.6_lin64_standalone/
	echo "Imageinfo:" 
	./volatility_2.6_lin64_standalone -f $in imageinfo 
	echo "running processes list:"
	./volatility_2.6_lin64_standalone -f $in --profile=$PROFILE pslist > /$W/Output/Volatility/Processes.txt
	echo "running connection list:"
	./volatility_2.6_lin64_standalone -f $in --profile=$PROFILE connections > /$W/Output/Volatility/Network.txt
	echo "running registry list:"
	./volatility_2.6_lin64_standalone -f $in --profile=$PROFILE hivelist > /$W/Output/Volatility/Registry.txt
	echo "Volatility reports were saved at /$W/Output/Volatility"
}

#this funtion shall check whether volatility can find a profile and if so continues on to the volatility function

function VolCheck(){
	cd ~/volatility_2.6_lin64_standalone/
	./volatility_2.6_lin64_standalone -f $in imageinfo > .tmp 2>/dev/null
	P=$(cat .tmp | grep Suggested | awk '{print $4}' | sed 's/,//g')
	echo $P
	if [ "$P" == "No" ]
	then
		echo "[!] No Profile found"
	else
		echo "[+] Running Volatility" && Volatility
	fi
}
VolCheck

#this function creates a report and zips the output files and report together

function Report(){
	sudo chmod -R 777 ~/Output/
	cd 
	echo "bulk extractor extracted (files):"
	ls "/$W/Output/bulk_extractor" |  wc -l 
	echo "binwalk extracted (files):"
	ls "/$W/Output/binwalk" | wc -l
	echo "foremost extracted (files):"
	ls "/$W/Output/foremost" |  wc -l 
	echo "volatility extracted (files):"
	ls "/$W/Output/Volatility" | wc -l
	ls "/$W/Output/bulk_extractor" |  wc -l > Report.txt
	ls "/$W/Output/bulk_extractor" >> Report.txt
	ls "/$W/Output/binwalk" | wc -l >> Report.txt
	ls "/$W/Output/binwalk" >> Report.txt
	ls "/$W/Output/foremost" |  wc -l >> Report.txt
	ls "/$W/Output/foremost" >> Report.txt
	ls "/$W/Output/Volatility" | wc -l >> Report.txt
	ls "/$W/Output/Volatility" >> Report.txt
	echo "A list of extracted files was saved in Report.txt"
	end=$(date +%s)
	runtime=$(($end - $start))
	echo "The script was executed in $runtime seconds"
	
	cd 
	zip Analysis.zip Output/ Report.txt
	echo "Zip containing files: Analysis.zip at /root"
}
Report
