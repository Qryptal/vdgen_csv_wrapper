#!/usr/bin/env python
#
# Copyright (c) Qryptal Pte Ltd. All rights reserved.
# The use of this source code is governed by a MIT-style
# license that can be found in the LICENSE file.

import sys, os
import argparse
import logging
import csv



def main(args, loglevel):
  logging.basicConfig(format="%(levelname)s: %(message)s", level=loglevel)
  logging.debug("Your Arguments: %s" % args)

  #checking for vdgen binary path
  if args.vdgenbinary[0] not in [".","//",]:
    if os.sys.platform == "win32":
      args.vdgenbinary = args.vdgenbinary
    else:
      args.vdgenbinary = ".//" + args.vdgenbinary


  #Open CSV File
  logging.info("Processing file: %s" % args.csvfilename)
  with open(args.csvfilename, 'rb') as csvfile:
    dialect = csv.Sniffer().sniff(csvfile.read(1024))
    csvfile.seek(0)
    reader = csv.reader(csvfile, dialect)

    cert_keys = None
    i = 0
    for row in reader:
      logging.debug("CSV row:%s" % row)

      #first row gives the key names
      if not cert_keys:
        cert_keys = row
      elif row:
        payload = ':'.join('%s:%s' % t for t in zip(cert_keys, row))
        qrfilename = "QR"+"".join([c for c in row[0] if c.isalpha() or c.isdigit() or c==' ']).rstrip()[:40] + ".png"

        # cmd = "%s -t '%s' -f '%s' -p hello -s 164" % (args.vdgenbinary, payload, qrfilename)
        cmd = '%s -t "%s" -f "%s" -p "%s" -s %s' % (args.vdgenbinary, payload, qrfilename, args.passphrase, args.size)
        logging.debug("Cmd:%s", cmd)
        output = os.system(cmd)
        i += 1
  logging.info("Number of certficate QR Codes created: %s" % i)



if __name__ == '__main__':
  parser = argparse.ArgumentParser(
                                    description = "Processes a CSV File and generates QR Codes using vdgen",
                                    epilog = "The first COL of the CSV file is assumed to be the Certificate ID and the generated QR Code images would use that as a filename. The top ROW should contain the headings.",
                                    )

  parser.add_argument(
                      "csvfilename",
                      help = "pass csv CSVFILENAME to the program",
                      metavar = "CSVFILENAME")
  parser.add_argument(
                      "-p",
                      "--passphrase",
                      required=True,
                      help="passphrase for Generator",
                      )
  parser.add_argument(
                      "-b",
                      "--vdgenbinary",
                      help="the name of the vdgen binary file",
                      default="vdgen-win64")
  parser.add_argument(
                      "-s",
                      "--size",
                      help="image size in pixels",
                      default="164")
  parser.add_argument(
                      "-v",
                      "--verbose",
                      help="increase output verbosity",
                      action="store_true")
  args = parser.parse_args()

  # Setup logging
  if args.verbose:
    loglevel = logging.DEBUG
  else:
    loglevel = logging.INFO

  main(args, loglevel)
