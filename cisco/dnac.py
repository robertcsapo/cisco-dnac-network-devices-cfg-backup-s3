import requests
from requests.auth import HTTPBasicAuth
import json
import logging
import os
from storage import providers


class dnacApiClass:
    def __init__(self, args):
        """ Check if using Environment values """
        try:
            self.dnacHost = os.environ["DNAC_HOST"]
            self.dnacUser = os.environ["DNAC_USER"]
            self.dnacPass = os.environ["DNAC_PASS"]
        except KeyError:
            """ If using args, override Environment values """
            if args.dnac is not None:
                self.dnacHost = args.dnac[0]
                self.dnacUser = args.dnac[1]
                self.dnacPass = args.dnac[2]

        """ Check SSL Verify settings for Cisco DNA Center """
        try:
            self.dnacVerify = os.environ["DNAC_SSL_VERIFY"]
        except KeyError:
            try:
                self.dnacVerify = bool(args.insecure)
            except KeyError:
                self.dnacVerify = False

        """ Convert string to bool """
        if type(self.dnacVerify) != bool:
            self.dnacVerify = json.loads(self.dnacVerify.lower())

        """ Disable SSL warnings if user manually set --insecure """
        if self.dnacVerify is False:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        """ If using args, override Environment values """
        if args.aws is not None:
            os.environ["S3BUCKET"] = args.aws[0]
            os.environ["AWS_ACCESS_KEY"] = args.aws[1]
            os.environ["AWS_SECRET_KEY"] = args.aws[2]
            os.environ["STORAGE"] = "AWS"
        if args.gcp is not None:
            os.environ["S3BUCKET"] = args.gcp[0]
            os.environ["AWS_ACCESS_KEY"] = args.gcp[1]
            os.environ["AWS_SECRET_KEY"] = args.gcp[2]
            os.environ["STORAGE"] = "GCP"
        if args.do is not None:
            os.environ["S3BUCKET"] = args.do[0]
            os.environ["AWS_ACCESS_KEY"] = args.do[1]
            os.environ["AWS_SECRET_KEY"] = args.do[2]
            os.environ["ENDPOINT_URL"] = args.do[3]
            os.environ["STORAGE"] = "DO"
        if args.minio is not None:
            os.environ["S3BUCKET"] = args.minio[0]
            os.environ["AWS_ACCESS_KEY"] = args.minio[1]
            os.environ["AWS_SECRET_KEY"] = args.minio[2]
            os.environ["ENDPOINT_URL"] = args.minio[3]
            os.environ["STORAGE"] = "MINIO"
        pass

    def auth(self):
        """ Cisco DNA Center Auth URL """
        url = "https://"+self.dnacHost+"/dna/system/api/v1/auth/token"
        payload = ""
        headers = {
                    "Content-Type": "application/json",
                  }
        response = requests.request(
                                    "POST",
                                    url,
                                    auth=HTTPBasicAuth(
                                                        self.dnacUser,
                                                        self.dnacPass
                                                       ),
                                    data=payload,
                                    headers=headers,
                                    verify=self.dnacVerify
                                    )
        if response.status_code == 200:
            dnacToken = json.loads(response.text)
            if "Token" in dnacToken:
                dnacToken = dnacToken["Token"]
                return(dnacToken)
            else:
                logging.error("Token missing from Cisco DNA Center %s - %s" % (
                    self.dnacHost,
                    response.text)
                    )
                raise Exception("Cisco DNA Center Auth Failure: %s" % (
                    response.text)
                    )
        elif response.status_code == 401:
            """ Dirty fix for issues with /dna/system/api/v1/auth/token """
            """ Check if Cisco DNA Center is still using legacy API Path """
            url = "https://"+self.dnacHost+"/api/system/v1/auth/token"
            response = requests.request(
                                        "POST",
                                        url,
                                        auth=HTTPBasicAuth(
                                            self.dnacUser,
                                            self.dnacPass
                                            ),
                                        data=payload,
                                        headers=headers,
                                        verify=self.dnacVerify
                                        )
            if response.status_code == 200:
                dnacToken = json.loads(response.text)
                dnacToken = dnacToken["Token"]
                return(dnacToken)
            else:
                logging.error("Can't login in to %s - %s" % (
                    self.dnacHost,
                    response.text)
                    )
                raise Exception("Cisco DNA Center Auth Failure: %s" % (
                    response.text)
                    )
        else:
            logging.error("Can't login in to %s - %s" % (
                self.dnacHost,
                response.text)
                )
            raise Exception("Cisco DNA Center Auth Failure: %s" % (
                response.text)
                )


def provider():
    """ Read from Environment that class has set """
    try:
        s3 = providers.identify(os.environ["STORAGE"])
    except KeyError:
        logging.error("Problem with Storage Provider")
        raise Exception(
            "ENV Storage isn't set or "
            "ACCESS/SECRET Keys are missing")
    if s3 is None:
        logging.error("The choosen Storage Provider (%s) isn't supported" % (
            os.environ["STORAGE"])
            )
        raise Exception("Error: Storage Provider is missing")
    logging.info("Object Storage Provider: %s" % (s3["name"]))
    logging.info("S3 Bucket Name: %s" % (s3["bucket"]))
    """ Check if Storage is using Endpoint URL """
    try:
        if s3["url"]:
            logging.info("S3 Bucket URL: %s" % (s3["url"]))
    except KeyError:
        pass

    return(s3)


def ciscoDnacCollectCfgs(self):
    """ Check provider settings """
    s3 = provider()

    """ Get Token from Cisco DNAC - change to dnacentersdk in the future """
    dnacToken = dnacApiClass.auth(self)

    """ Get all cfgs stored on Cisco DNA Center """
    url = "https://"+self.dnacHost+"/api/v1/archive-config"
    headers = {
        "x-auth-token": dnacToken,
        "Content-Type": "application/json"
        }
    response = requests.request(
                                "GET",
                                url,
                                headers=headers,
                                verify=self.dnacVerify
                                )
    if response.status_code != 200:
        logging.error(
            "Can't list archive cfgs from "
            "Cisco DNA Center (HTTP Code %s)" % (
                response.status_code)
            )
        return
    data = json.loads(response.text)

    """ Storing all found network devices - based on Id """
    devices = {}

    """ Looping through all devices with cfg on Cisco DNA Center """
    for device in data["archiveResultlist"]:
        """ Insert unique deviceId's to dict """
        devices[device["deviceId"]] = ""
        """ Remember which archive cfg is the latest """
        latestVersion = ""
        for versions in device["versions"]:
            """ If status is "NOT_APPLICABLE" """
            """ then there's no cfg to grab """
            if versions["startupRunningStatus"] != "NOT_APPLICABLE":
                """ No previous Latest Version """
                """ then this has to be the latest """
                if latestVersion == "":
                    """ Store the latest verions timestamp """
                    latestVersion = versions["createdTime"]
                    """ Pair unique deviceId with latest versionId """
                    devices[device["deviceId"]] = versions["id"]
                elif latestVersion < versions["createdTime"]:
                    """ New latest versionId - based on timestamp """
                    """ Pair unique deviceId with latest versionId """
                    devices[device["deviceId"]] = versions["id"]

    """ Download latest cfg - based on deviceId and versionId """
    for device in data["archiveResultlist"]:
        """ Loop through the list """
        for versions in device["versions"]:
            """ Looking for versionId that matches deviceId """
            if versions["id"] == devices[device["deviceId"]]:
                """ Looping through the files """
                """ in the archive for latest versionId """
                for latest in versions["files"]:
                    """ Only looking for Running and Startup cfg """
                    if "CONFIG" in latest["fileType"]:
                        """ Downloading the cfg from Cisco DNA Center """
                        url = ("https://"+self.dnacHost+"/api/v1%s" % (
                            latest["downloadPath"])
                            )
                        response = requests.request("GET",
                                                    url,
                                                    headers=headers,
                                                    verify=self.dnacVerify)
                        if response.status_code != 200:
                            logging.error(
                                "Can't download %s %s from "
                                "Cisco DNA Center (HTTP Code %s)" % (
                                    device["deviceName"],
                                    latest["fileType"],
                                    response.status_code)
                                )
                            """ Break as this is a major issue """
                            break
                        """ S3 Filename """
                        s3Filename = (
                            device["deviceName"]+"-"+latest["fileType"]+".cfg"
                            )
                        logging.info("Downloading %s %s" % (
                            device["deviceName"],
                            latest["fileType"])
                            )
                        """ Config File Data """
                        cfg = response.text
                        """ Upload the cfg to S3 """
                        try:
                            s3["provider"].put_object(
                                        Bucket=s3["bucket"],
                                        Key=s3Filename,
                                        Body=(bytes(cfg.encode("UTF-8")))
                                        )
                        except Exception as e:
                            raise Exception("Problem with S3 Bucket: %s" % (e))
                        logging.info("Uploaded S3 Bucket (%s)" % (
                            s3["bucket"])
                            )

    logging.info(
        "Total of %s device cfgs (running/startup) uploaded S3 Bucket (%s)" % (
            len(devices),
            s3["bucket"])
        )
