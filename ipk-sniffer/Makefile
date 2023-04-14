###
# Author: Samuel Stolarik
# File: Makefile
# Date: 2023-04-15
# Project: IPK project 2 - Packet Sniffer
###

all: 
	dotnet publish -c Release -r linux-x64 -p:PublishSingleFile=true --self-contained false --output .

clean:
	dotnet clean
	rm ipk-sniffer ipk-sniffer.pdb

.PHONY:
	clean all
