import argparse
import serial

import frame_data as fd

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-p', '--serial-port',
                        help='Serial port to connect to.', required=True)
    parser.add_argument('-b', '--baud-rate',
                        help='Baud rate (DWM1001 sniffer application uses 115200).', required=False)
    parser.add_argument('-t', '--timeout',
                        help='readline timeout in seconds (default is 3.0).', required=False)
    options = parser.parse_args()

    # Parse options
    baud_rate = 115200 if (options.baud_rate == None) else options.baud_rate
    timeout = 3.0 if (options.timeout == None) else float(options.timeout)
    # Connect to Serial port
    ser = serial.Serial(options.serial_port, baud_rate, timeout=timeout)

    # Continuously read frame data until program is stopped
    while True:
        line = ser.readline()
        if len(line) == 0:
            print("No data received; serial timeout")
            continue
        #print(line.decode("utf-8"))
        # print(line)

        # Decode frame
        line = str(line)[2:len(line)]
        frame = fd.FrameData(line)  # TODO: line.decode("utf-8") produces one extra byte at the end
        print(frame.data_breakdown(0))
        print("---------------------")

if __name__ == '__main__':
    main()