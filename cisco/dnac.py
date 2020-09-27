"""
Cisco DNA Center API Module
"""
import shutil
import random
import string
import json
import logging
import os
import time
import pathlib
import requests
from requests.auth import HTTPBasicAuth
import pyzipper
from storage import providers


class dnacApiClass:
    """
    Cisco DNA Center API Class
    """
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

        """ S3 Provider Settings """
        self.s3 = self.provider()

        """ Supported OS to download cfg """
        self.supported_os = ["IOS-XE"]

        """ Password Generator for Zip File for every task """
        self.zip_pass = self.password_generator()

        """ Unzip path """
        self.unzip_path = "tmp/"
        self.unzip_temp_file = "temp.zip"

        pass

    def password_generator(self):
        """Create a password that matches Cisco DNA Center's requirements
        Min password length is 8 and it should contain atleast one lower case letter, one uppercase letter, one digit and one special characters from -=\\\\;,./~!@#$%^&*()_+{}[]|:?
        """
        punctuation = "-=;,.~!@#$%^&*()_+{}[]|:?"
        password_chars = punctuation + string.ascii_letters + string.digits
        password_list = [
            random.choice(punctuation),
            random.choice(string.ascii_uppercase),
            random.choice(string.ascii_lowercase),
            random.choice(string.digits),
            random.choice(password_chars),
            random.choice(password_chars),
            random.choice(password_chars),
            random.choice(password_chars),
        ]
        password = []
        while password_list:
            password.append(
                password_list.pop(random.randint(0, len(password_list) - 1))
            )
        password = "".join(password)
        return password

    def provider(self):
        """ Read from Environment that class has set """
        try:
            s3 = providers.identify(os.environ["STORAGE"])
        except KeyError:
            logging.error("Problem with Storage Provider")
            raise Exception(
                "ENV Storage isn't set or " "ACCESS/SECRET Keys are missing"
            )
        if s3 is None:
            logging.error(
                "The choosen Storage Provider (%s) isn't supported"
                % (os.environ["STORAGE"])
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

        return s3

    def auth(self):
        """ Cisco DNA Center Auth URL """
        url = "https://" + self.dnacHost + "/dna/system/api/v1/auth/token"
        payload = ""
        headers = {
            "Content-Type": "application/json",
        }
        response = requests.request(
            "POST",
            url,
            auth=HTTPBasicAuth(self.dnacUser, self.dnacPass),
            data=payload,
            headers=headers,
            verify=self.dnacVerify,
        )
        if response.status_code == 200:
            dnacToken = json.loads(response.text)
            if "Token" in dnacToken:
                """
                Only for 1.3 support
                """
                dnacToken = dnacToken["Token"]

                self.dnacToken = dnacToken
                return dnacToken
            else:
                logging.error(
                    "Token missing from Cisco DNA Center %s - %s"
                    % (self.dnacHost, response.text)
                )
                raise Exception("Cisco DNA Center Auth Failure: %s" % (response.text))
        elif response.status_code == 401:
            """ Dirty fix for issues with /dna/system/api/v1/auth/token """
            """ Check if Cisco DNA Center is still using legacy API Path """
            url = "https://" + self.dnacHost + "/api/system/v1/auth/token"
            response = requests.request(
                "POST",
                url,
                auth=HTTPBasicAuth(self.dnacUser, self.dnacPass),
                data=payload,
                headers=headers,
                verify=self.dnacVerify,
            )
            if response.status_code == 200:
                """
                Only for 1.3 support
                """
                dnacToken = json.loads(response.text)
                dnacToken = dnacToken["Token"]

                self.dnacToken = dnacToken
                return dnacToken
            else:
                logging.error(
                    "Can't login in to %s - %s" % (self.dnacHost, response.text)
                )
                raise Exception("Cisco DNA Center Auth Failure: %s" % (response.text))
        else:
            logging.error("Can't login in to %s - %s" % (self.dnacHost, response.text))
            raise Exception("Cisco DNA Center Auth Failure: %s" % (response.text))

    def get_configs(self):
        """
        Get configs for all the devices that is supported
        """

        """ Get list of devices """
        devices = self.get_devices()
        if len(devices) == 0:
            return

        """ Generate a zip file of the cfgs """
        configs = self.get_device_config(devices)
        if configs is None:
            return

        """ Check the task of zip """
        task = self.get_task(task_id=configs["response"]["taskId"], retry=5, delay=5)
        if task is None:
            return

        """ Download the zip file """
        file = self.download_file(task["additionalStatusURL"])
        if file is None:
            return

        """ Unzip it locally """
        unzip = self.unzip_file(task["additionalStatusURL"])
        if unzip is None:
            return

        """ Upload files from extracted zip file """
        upload = self.upload_cfgs()
        if upload is None:
            return

        """ Delete zip file and extracted cfgs """
        cleanup = self.cleanup()
        if cleanup is None:
            return

        return

    def get_devices(self):
        """
        Get all the devices from Cisco DNA Center
        """
        devices = []
        url = f"https://{self.dnacHost}/dna/intent/api/v1/network-device"
        headers = {"x-auth-token": self.dnacToken, "Content-Type": "application/json"}
        response = requests.request("GET", url, headers=headers, verify=self.dnacVerify)
        if response.ok is False:
            logging.error(
                f"Error Cisco DNA Center: Can't list devices {response.status_code}"
            )
            return devices
        data = response.json()
        for device in data["response"]:
            if "softwareType" in device:
                if None is not device["softwareType"]:
                    if device["softwareType"] in self.supported_os:
                        devices.append(device["id"])
        return devices

    def get_device_config(self, devices):
        """
        Cisco DNA Center creates a ZIP file
        """
        logging.info(f"Generating a zip file with cfgs for {len(devices)} devices")
        logging.info(f"Temporary ZIP Password: {self.zip_pass}")
        url = f"https://{self.dnacHost}/dna/intent/api/v1/network-device-archive/cleartext"
        headers = {"x-auth-token": self.dnacToken, "Content-Type": "application/json"}
        payload = {"deviceId": devices, "password": self.zip_pass}
        payload = str(json.dumps(payload))
        response = requests.request(
            "POST", url, headers=headers, data=payload, verify=self.dnacVerify
        )
        if response.ok is False:
            logging.error(
                f"Error Cisco DNA Center: Can't generate zip with device configs {response.status_code}"
            )
            return None
        data = response.json()
        return data

    def get_task(self, task_id, retry=5, delay=5):
        """
        Get Task Status
        Retry mandatory (default 5)
        Sleep/Delay between retries (default 5)
        """
        results = {}
        while retry >= 0:
            url = f"https://{self.dnacHost}/api/v1/task/{task_id}"
            headers = {
                "x-auth-token": self.dnacToken,
                "Content-Type": "application/json",
            }
            response = requests.request(
                "GET", url, headers=headers, verify=self.dnacVerify
            )
            if response.ok is False:
                logging.error(
                    f"Error Cisco DNA Center: Can't get task {task_id} status {response.status_code}"
                )
                return None
            data = response.json()
            logging.info(f"Task Status: {data['response']['progress']}")
            if "endTime" in data["response"]:
                if data["response"]["isError"] is False:
                    results["additionalStatusURL"] = data["response"][
                        "additionalStatusURL"
                    ]
                    results["isError"] = data["response"]["isError"]
                    break
                if data["response"]["isError"] is True:
                    """ If Error, then break """
                    logging.error(
                        f"Error Cisco DNA Center: Can't complete task {task_id} {data['response']['progress']}"
                    )
                    results["isError"] = data["response"]["isError"]
                    break

            if retry == 0:
                """ If no more retries left, give up """
                logging.error(
                    f"Error Cisco DNA Center: Can't complete task {task_id} retries left: {retry}"
                )
                results["isError"] = True
                break
            time.sleep(int(delay))
            retry -= 1
        return results

    def download_file(self, file):
        """
        Downloading file and store locally
        Using unzip path settings for directory
        """
        logging.info(f"Downloading: {file}")
        url = f"https://{self.dnacHost}{file}"
        headers = {"x-auth-token": self.dnacToken, "Content-Type": "application/json"}
        response = requests.request(
            "GET", url, headers=headers, verify=self.dnacVerify, stream=True
        )
        if response.ok is False:
            logging.error(
                f"Error Cisco DNA Center: Can't download zip file {file} with device configs {response.status_code}"
            )
            return None
        pathlib.Path(self.unzip_path).mkdir(parents=True, exist_ok=True)
        handle = open(f"{self.unzip_path}{self.unzip_temp_file}", "wb")
        for chunk in response.iter_content(chunk_size=512):
            if chunk:
                handle.write(chunk)
        handle.close()
        logging.info("Download Complete")
        return True

    def unzip_file(self, file):
        """
        Unzipping file locally
        Using unzip path settings for directory
        """
        logging.info(f"Unzipping {file}")
        try:
            with pyzipper.AESZipFile(f"{self.unzip_path}{self.unzip_temp_file}") as f:
                f.pwd = bytes(self.zip_pass, encoding="utf-8")
                f.extractall(path=str(self.unzip_path))
        except Exception as e:
            logging.error(f"Error Unzipping: {e}")
            return None
        return True

    def upload_cfgs(self):
        """
        Parse through all the folders from the zip file
        Using directory name as device name
        Then uploading it to Storage Provider
        """
        logging.info(f"Uploading to S3 [{self.s3['name']}]")
        results = {}
        results["devices"] = {}
        for path, subdirs, files in os.walk(self.unzip_path):
            path = path.replace("\\", "/")
            directory_name = path.replace(self.unzip_path, "")
            if len(directory_name) != 0:
                results["devices"][directory_name] = []

            for file in files:
                if "zip" not in file:

                    s3_path_file = f"{directory_name}/{file}"
                    full_path_file = f"{path}/{file}"
                    try:
                        self.s3["provider"].upload_file(
                            full_path_file, self.s3["bucket"], s3_path_file
                        )
                        results["devices"][directory_name].append(file)
                    except Exception as e:
                        raise Exception(f"Problem with S3 Bucket: {e}")
                        return None

            if len(directory_name) != 0:
                logging.info(f"Uploaded device: {directory_name}")

        results["total_devices"] = len(results["devices"])
        results["total_cfgs"] = 0
        for files in results["devices"].values():
            results["total_cfgs"] += len(files)

        logging.info(
            f"Total of {results['total_devices']} device cfgs ({results['total_cfgs']}) (running/startup/vlan.dat) uploaded S3 Bucket ({self.s3['bucket']})"
        )
        return results

    def cleanup(self):
        """
        Remove all files in zip, zip file and folders.
        """
        try:
            shutil.rmtree(self.unzip_path)
        except Exception as e:
            logging.info(f"Error cleaning up: {e}")
            return None

        return True


def collect_cfg(self):
    """
    Supported API in Cisco DNA Center 2.1+
    """

    """ Cisco DNA Center Auth """
    dnacApiClass.auth(self)
    """ Collect Cfgs and Upload to S3 """
    dnacApiClass.get_configs(self)
    return


""" Support for 1.3.3 Cisco DNA Center """


def provider():
    """ Read from Environment that class has set """
    try:
        s3 = providers.identify(os.environ["STORAGE"])
    except KeyError:
        logging.error("Problem with Storage Provider")
        raise Exception("ENV Storage isn't set or " "ACCESS/SECRET Keys are missing")
    if s3 is None:
        logging.error(
            "The choosen Storage Provider (%s) isn't supported"
            % (os.environ["STORAGE"])
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

    return s3


""" Support for 1.3.3 Cisco DNA Center """


def ciscoDnacCollectCfgs(self):
    """
    Unsupported API in Cisco DNA Center 1.3
    """

    """ Check provider settings """
    s3 = provider()

    """ Get Token from Cisco DNAC - change to dnacentersdk in the future """
    dnacToken = dnacApiClass.auth(self)

    """ Get all cfgs stored on Cisco DNA Center """
    url = "https://" + self.dnacHost + "/api/v1/archive-config"
    headers = {"x-auth-token": dnacToken, "Content-Type": "application/json"}
    response = requests.request("GET", url, headers=headers, verify=self.dnacVerify)
    if response.status_code != 200:
        logging.error(
            "Can't list archive cfgs from "
            "Cisco DNA Center (HTTP Code %s)" % (response.status_code)
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
                        url = (
                            "https://"
                            + self.dnacHost
                            + "/api/v1%s" % (latest["downloadPath"])
                        )
                        response = requests.request(
                            "GET", url, headers=headers, verify=self.dnacVerify
                        )
                        if response.status_code != 200:
                            logging.error(
                                "Can't download %s %s from "
                                "Cisco DNA Center (HTTP Code %s)"
                                % (
                                    device["deviceName"],
                                    latest["fileType"],
                                    response.status_code,
                                )
                            )
                            """ Break as this is a major issue """
                            break
                        """ S3 Filename """
                        s3Filename = (
                            device["deviceName"] + "-" + latest["fileType"] + ".cfg"
                        )
                        logging.info(
                            "Downloading %s %s"
                            % (device["deviceName"], latest["fileType"])
                        )
                        """ Config File Data """
                        cfg = response.text
                        """ Upload the cfg to S3 """
                        try:
                            self.s3["provider"].put_object(
                                Bucket=self.s3["bucket"],
                                Key=s3Filename,
                                Body=(bytes(cfg.encode("UTF-8"))),
                            )
                        except Exception as e:
                            raise Exception("Problem with S3 Bucket: %s" % (e))
                        logging.info("Uploaded S3 Bucket (%s)" % (self.s3["bucket"]))

    logging.info(
        "Total of %s device cfgs (running/startup) uploaded S3 Bucket (%s)"
        % (len(devices), self.s3["bucket"])
    )
