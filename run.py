import schedule
import time
import logging
import sys
import argparse
from argparse import RawTextHelpFormatter
from cisco import dnac


"""cisco-dnac-network-devices-cfg-backup-s3  Console Script.

Copyright (c) 2020 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.

"""

__author__ = "Robert Csapo"
__email__ = "rcsapo@cisco.com"
__version__ = "1.0"
__copyright__ = "Copyright (c) 2020 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"
__app__ = "cisco-dnac-network-devices-cfg-backup-s3"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__app__+" - help section\n\n"
        "Using Environment (os.environ) overrides arguments below",
        formatter_class=RawTextHelpFormatter)
    parser.add_argument(
        "--dnac",
        nargs=3,
        metavar=(
            "DNAC_HOST",
            "DNAC_USER",
            "DNAC_PASS"),
        help="Cisco DNA Center Hostname\nCisco DNA Center Username\n"
        "Cisco DNA Center Password\nCisco DNA Center SSL Verify")
    parser.add_argument(
        "--aws",
        nargs=3,
        metavar=(
            "S3BUCKET",
            "AWS_ACCESS_KEY",
            "AWS_SECRET_KEY"),
        help="AWS S3 Bucket S3BUCKET Name\nAWS S3 AWS_ACCESS_KEY\n"
        "AWS S3 AWS_SECRET_KEY")
    parser.add_argument(
        "--gcp",
        nargs=3,
        metavar=(
            "S3BUCKET",
            "AWS_ACCESS_KEY",
            "AWS_SECRET_KEY"),
        help="Google Cloud Storage S3BUCKET Bucket Name\n"
        "Google Cloud Storage ACCESS_KEY\nGoogle Cloud Storage SECRET_KEY")
    parser.add_argument(
        "--do",
        nargs=4,
        metavar=(
            "S3BUCKET",
            "AWS_ACCESS_KEY",
            "AWS_SECRET_KEY",
            "ENDPOINT_URL"),
        help="DigitalOcean Spaces S3BUCKET Bucket Name\n"
        "DigitalOcean Spaces ACCESS_KEY\nDigitalOcean Spaces SECRET_KEY\n"
        "DigitalOcean Spaces Bucket ENDPOINT_URL")
    parser.add_argument(
        "--minio",
        nargs=4,
        metavar=(
            "S3BUCKET",
            "AWS_ACCESS_KEY",
            "AWS_SECRET_KEY",
            "ENDPOINT_URL"),
        help="MinIO Inc. S3BUCKET Bucket Name\nMinIO Inc. ACCESS_KEY\n"
        "MinIO Inc. SECRET_KEY\nMinIO Inc. Server ENDPOINT_URL")
    parser.add_argument(
        "--insecure",
        default=True,
        action="store_false",
        help="Disables SSL/TLS verification")
    parser.add_argument(
        "--version",
        action="version",
        version=__app__+" v"+__version__)
    args = parser.parse_args()

    """ Logging events with timestamp """
    logging.basicConfig(
            format="%(asctime)s %(levelname)-8s %(message)s",
            level=logging.INFO,
            datefmt="%Y-%m-%d %H:%M:%S"
            )
    logging.info("Starting Application")

    """ Store settings in class """
    dnacApi = dnac.dnacApiClass(args)

    """ Execute first collection of configs """
    try:
        dnac.ciscoDnacCollectCfgs(dnacApi)
    except KeyboardInterrupt:
        print("")
        logging.error("Keyboard Interrupt - Closing application")
        sys.exit()

    """ Set schedule for recurring collections """
    timeOnDay = "03:00"
    logging.info("Next collection scheduled at %s" % (timeOnDay))
    schedule.every().day.at(timeOnDay).do(dnac.ciscoDnacCollectCfgs, dnacApi)
    """ Start recurring collections loop """
    while True:
        try:
            schedule.run_pending()
            time.sleep(1)
        except KeyboardInterrupt:
            print("")
            logging.error("Keyboard Interrupt - Closing application")
            sys.exit()
