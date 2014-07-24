#!/usr/bin/env python
#
# Copyright (c) Qryptal Pte Ltd. All rights reserved.
# The use of this source code is governed by a MIT-style
# license that can be found in the LICENSE file.

import sys, os
import argparse
import logging
import csv
import subprocess



def main(args, loglevel):
  logging.basicConfig(format="%(levelname)s: %(message)s", level=loglevel)
  logging.debug("Your Arguments: %s" % args)

  #checking for vdgen binary path
  if args.vdgenbinary[0] not in [".","//",]:
    if os.sys.platform == "win32":
      args.vdgenbinary = args.vdgenbinary
    else:
      args.vdgenbinary = ".//" + args.vdgenbinary


  #Check if output is CSV
  outcsvwriter = None
  if args.outputcsv:
      outcsvfile = open(args.outputcsv, 'wb')
      outcsvwriter = csv.writer(outcsvfile)
      logging.info("Created  output CSV file:%s", args.outputcsv)

  #Open CSV File
  logging.info("Processing file: %s" % args.csvfilename)
  with open(args.csvfilename, 'rb') as csvfile:
    dialect = csv.Sniffer().sniff(csvfile.readline())
    csvfile.seek(0)
    reader = csv.reader(csvfile, dialect)

    cert_keys = None
    i = 0

    for row in reader:
      logging.debug("CSV row:%s" % row)

      #first row gives the key names
      if not cert_keys:
        cert_keys = row
        if outcsvwriter:
            outcsvwriter.writerow(row+["QRData",])

      elif row:
        payload = ':'.join('%s:%s' % t for t in zip(cert_keys, row))

        if outcsvwriter:
            qrfilename = "CODECONTENT"
            p = subprocess.Popen([args.vdgenbinary,
                                    '-t', "%s" % payload,
                                    '-f', "%s" % qrfilename,
                                    '-p', "%s" % args.passphrase,
                                 ],
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            pout, perr = p.communicate()
            logging.debug("CSV Save result:%s", pout)
            qrdata = pout[14:-2]  #stripping off the header and filler including \n
            outcsvwriter.writerow(row+[qrdata,])
        else:
            qrfilename = args.imageprefix+"".join([c for c in row[0] if c.isalpha() or c.isdigit() or c==' ']).rstrip()[:40] + ".png"
            cmd = '%s -t "%s" -f "%s" -p "%s" -s %s' % (args.vdgenbinary, payload, qrfilename, args.passphrase, args.size)
            logging.debug("Cmd:%s", cmd)
            output = os.system(cmd)
        i += 1
  logging.info("Number of certficate QR Codes created: %s" % i)

  if outcsvwriter:
      outcsvfile.close()



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
                      "-i",
                      "--imageprefix",
                      help="image file prefix",
                      default="QR")
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
  parser.add_argument(
                      "-o",
                      "--outputcsv",
                      help="code content column is added to input csvfilename and no images are generated",
                      metavar="OUTPUTCSV")
  args = parser.parse_args()

  # Setup logging
  if args.verbose:
    loglevel = logging.DEBUG
  else:
    loglevel = logging.INFO

  main(args, loglevel)
