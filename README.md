# DRTLS Decoder

Decode frames captured by DWM1001 sniffer ([Link](https://github.com/djtfoo/dwm1001-sniffer))

## Requirements
Python 3
- Required Packages: argparse, Serial, struct

## How to Run
To run this script:
```
python uwb-sniffer.py -p PORT [-b BAUDRATE] [-t TIMEOUT]
```
Only the port must be specified. The default baud rate is 912600, the baud rate of the DWM1001 sniffer application.

The program outputs (stdout) can be redirected to a file:
```
python uwb-sniffer.py -p PORT [-b BAUDRATE] [-t TIMEOUT] > log.txt
```

## TODO
- Common superclass for message classes
- Implement a GUI