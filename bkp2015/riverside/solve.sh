#!/bin/sh

tshark  -r ./challenge.pcapng.28c58da9dd07532d45aa68f9b825941e \
        -Y "usb.request_in && usb.transfer_type == URB_INTERRUPT && usb.device_address ==12" \
        -V |
grep "Leftover Capture Data" |
cut -c24-32 |
ruby draw.rb
