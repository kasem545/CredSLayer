# coding: utf-8

import socket
import os
import traceback
from argparse import ArgumentParser

from credslayer.core import manager, logger


def build_argument_parser() -> ArgumentParser:
    parser = ArgumentParser(
        description='Helps you find credentials and other interesting stuff in network captures.')
    parser.add_argument("pcapfiles",
                        nargs='*',
                        help='pcap files you want to analyse')
    parser.add_argument('-l', '--listen',
                        help='start active processing on specified interface',
                        metavar='INTERFACE')
    parser.add_argument('-lo', '--listen-output',
                        help='output captured packets to a pcap file',
                        metavar='FILE')
    parser.add_argument('-o', '--output',
                        help='output captured credentials to a file',
                        metavar='FILE')
    parser.add_argument('-s', '--string-inspection',
                        choices=["enable", "disable"],
                        help='whether you want to look for interesting strings (email addresses, '
                             'credit cards, ...) or not (pretty heavy on the CPU, '
                             'enabled by default on pcap files, disabled on live captures)')
    parser.add_argument('-f', '--filter',
                        metavar='IP',
                        help='process packets involving the specified IP')
    parser.add_argument('-m', '--map',
                        action='append',
                        metavar='PORT:PROTOCOL',
                        help='map a port to a protocol')
    parser.add_argument('-e', '--extract-files',
                        metavar='DIR',
                        help='extract files (images, documents, binaries) from traffic to specified directory')
    parser.add_argument('--file-types',
                        help='comma-separated list of file types to extract (e.g., "jpg,png,pdf"). Default: all types')
    parser.add_argument('--min-file-size',
                        type=int,
                        default=100,
                        metavar='BYTES',
                        help='minimum file size to extract in bytes (default: 100)')
    parser.add_argument('--debug', action='store_true',
                        help='put CredSLayer and pyshark in debug mode')

    return parser


def main():
    parser = build_argument_parser()
    args = parser.parse_args()

    if args.listen:
        if args.pcapfiles:
            parser.error("You cannot specify pcap files to analyse and listen at the same time")

    else:
        if not args.pcapfiles:
            parser.error("Nothing to do...")

        if args.listen_output:
            parser.error("Cannot specify --listen-output/-lo if not in listening mode")

    string_inspection = None

    if args.string_inspection == "enable":
        string_inspection = True
    elif args.string_inspection == "disable":
        string_inspection = False

    ip_filter = None

    if args.filter:

        # tshark display filter
        try:
            socket.inet_aton(args.filter)
            ip_filter = "ip.src == {0} or ip.dst == {0}".format(args.filter)
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, args.filter)
                ip_filter = "ipv6.src == {0} or ipv6.dst == {0}".format(args.filter)
            except socket.error:
                parser.error("Invalid IP address filter")

        # dumpcap capture filter
        if args.listen:
            ip_filter = "host " + args.filter

    decode_map = None

    if args.map:
        decode_map = {}

        for m in args.map:
            tokens = m.split(":")

            if len(tokens) != 2:
                parser.error("Invalid port mapping")

            decode_map["tcp.port==" + tokens[0]] = tokens[1]
            logger.info("CredSLayer will decode traffic on '{}' as '{}'".format(*tokens))

    if args.output:

        if os.path.isfile(args.output):
            parser.error(args.output + " already exists")

        logger.OUTPUT_FILE = open(args.output, "w")

    # Setup file extraction if requested
    file_extractor = None
    allowed_types = None

    if args.extract_files:
        from credslayer.core.file_extractor import FileExtractor, set_file_extractor

        file_extractor = FileExtractor(output_dir=args.extract_files)
        set_file_extractor(file_extractor)

        # Set minimum file size
        file_extractor.min_file_size = args.min_file_size

        # Parse allowed file types
        if args.file_types:
            allowed_types = [ft.strip().lower() for ft in args.file_types.split(',')]
            file_extractor.allowed_types = allowed_types
            logger.info(f"File extraction enabled for types: {', '.join(allowed_types)}")
        else:
            logger.info("File extraction enabled for all file types")

        logger.info(f"Files will be extracted to: {args.extract_files}")

    if args.listen:

        if os.geteuid() != 0:
            print("You must be root to listen on an interface.")
            exit(1)

        if args.listen_output and os.path.isfile(args.listen_output):
            parser.error(args.listen_output + " already exists")

        manager.active_processing(args.listen,
                                  must_inspect_strings=string_inspection,
                                  tshark_filter=ip_filter,
                                  debug=args.debug,
                                  decode_as=decode_map,
                                  pcap_output=args.listen_output)
        exit(0)

    for pcap in args.pcapfiles:

        try:
            manager.process_pcap(pcap,
                                 must_inspect_strings=string_inspection,
                                 tshark_filter=ip_filter,
                                 debug=args.debug,
                                 decode_as=decode_map)

        except Exception as e:
            error_str = str(e)

            if error_str.startswith("[Errno"):  # Clean error message
                errno_end_index = error_str.find("]") + 2
                error_str = error_str[errno_end_index:]
                logger.error(error_str)

            else:
                traceback.print_exc()

    # Print file extraction summary if enabled
    from credslayer.core.file_extractor import get_file_extractor
    file_extractor = get_file_extractor()
    if file_extractor:
        print(file_extractor.get_summary())

    if logger.OUTPUT_FILE:
        logger.OUTPUT_FILE.close()


if __name__ == "__main__":
    main()
