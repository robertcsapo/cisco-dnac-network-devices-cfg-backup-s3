# cisco-dnac-network-devices-cfg-backup-s3

**Disclaimer**  
_This solution leverages currently unpublished Cisco DNA Center APIs (as of DATE)_  
_Do not use in production_

Download your Cisco Network Device Configuration from [Cisco DNA Center](https://www.cisco.com/c/en/us/products/cloud-systems-management/dna-center/index.html) (REST API).  
Then store them on Object Storage ([S3 compatible](https://en.wikipedia.org/wiki/Amazon_S3#S3_API_and_competing_services)), hosted in Public Cloud/Private Cloud/On-Prem  
* Script downloads and stores (per device)
  * RUNNINGCONFIG
  * STARTUPCONFIG
* _(Limited to Cisco IOS-XE Devices)_

### Why?
* Store your configs, as long as you want
  * Maintain your S3 Provider
* Use S3 provider with Versioning
  * Rollback of cfg
* Replicate your cfg backup storage
  * Cloud S3 Providers SLA
  * On-Prem with Minio (High availability)
    * https://docs.min.io/docs/distributed-minio-quickstart-guide.html

## Demo

### Backup process
![](demo-script.gif)
_(running with docker + docker-compose + aws s3)_

### S3 Storage View
![](demo-s3.gif)
_(aws s3)_

## Prerequisites
* Cisco DNA Center
  * Release: 1.3.0.x - 1.3.3.x
* S3 Storage
  * AWS_ACCESS_KEY
  * AWS_SECRET_KEY
  * ENDPOINT_URL (optional)

## Usage

#### Docker Compose
* Download or clone this repository
  - ```git clone https://github.com/robertcsapo/cisco-dnac-network-devices-cfg-backup-s3```

* Setup
  - Edit the ```docker-compose.yaml``` for your personal settings.  
  _(Default is AWS S3 Storage)_
  - If you want to use other Storage providers.  
  Edit ```docker-compose-<provider>.yaml``` file instead.

* Run service
  - Default
    - ```docker-compose -f docker-compose.yaml up```
  - Another Storage Provider
    - ```docker-compose -f docker-compose-<provider>.yaml up```

* Remove service
  - Default
    - ```docker-compose -f docker-compose.yaml down```
  - Another Storage Provider
    - ```docker-compose -f docker-compose-<provider>.yaml down```

#### Docker

* Setup
- System Args
  * Help section
```
Use this settings if not using Environment or want to override

    -h, --help            show this help message and exit
    --dnac DNAC_HOST DNAC_USER DNAC_PASS
                          Cisco DNA Center Hostname
                          Cisco DNA Center Username
                          Cisco DNA Center Password
                          Cisco DNA Center SSL Verify
    --aws S3BUCKET AWS_ACCESS_KEY AWS_SECRET_KEY
                          AWS S3 Bucket S3BUCKET Name
                          AWS S3 AWS_ACCESS_KEY
                          AWS S3 AWS_SECRET_KEY
    --gcp S3BUCKET AWS_ACCESS_KEY AWS_SECRET_KEY
                          Google Cloud Storage S3BUCKET Bucket Name
                          Google Cloud Storage ACCESS_KEY
                          Google Cloud Storage SECRET_KEY
    --do S3BUCKET AWS_ACCESS_KEY AWS_SECRET_KEY ENDPOINT_URL
                          DigitalOcean Spaces S3BUCKET Bucket Name
                          DigitalOcean Spaces ACCESS_KEY
                          DigitalOcean Spaces SECRET_KEY
                          DigitalOcean Spaces Bucket ENDPOINT_URL
    --minio S3BUCKET AWS_ACCESS_KEY AWS_SECRET_KEY ENDPOINT_URL
                          MinIO Inc. S3BUCKET Bucket Name
                          MinIO Inc. ACCESS_KEY
                          MinIO Inc. SECRET_KEY
                          MinIO Inc. Server ENDPOINT_URL
    --insecure            Disables SSL/TLS verification
    --version             show program's version number and exit
```
  * Example
    - ```docker run robertcsapo/cisco-dnac-network-devices-cfg-backup-s3 --dnac DNAC_HOST DNAC_USER DNAC_PASS --aws S3BUCKET AWS_ACCESS_KEY AWS_SECRET_KEY```

  - Docker with Environment
    * ```docker run robertcsapo/cisco-dnac-network-devices-cfg-backup-s3 -e DNAC_HOST <value> -e DNAC_USER <value> -e DNAC_PASS <value> -e S3BUCKET <value> -e AWS_ACCESS_KEY <value> -e AWS_SECRET_KEY <value> -e STORAGE=AWS ```  
    _(Change STORAGE to another provider if needed)_
    - OS Environments
      - ```DNAC_HOST=dnac.example.tld```
      - ```DNAC_USER=username```
      - ```DNAC_PASS=password```
      - ```STORAGE=AWS (or GCP, DO, MINIO)```
      - ```S3BUCKET=bucket```
      - ```AWS_ACCESS_KEY=key```
      - ```AWS_SECRET_KEY=key```
      _(check docker-compose-<provider>.yaml for OS Environments)_


## Installation (on server/host)

* Docker
  * [How-To](https://docs.docker.com/install/)
* Docker Compose
  * [How-To](https://docs.docker.com/compose/install/)


## Technologies & Frameworks Used

**Cisco Products & Services:**

- [Cisco DNA Center Platform API](https://developer.cisco.com/dnacenter/)
- [Cisco Network Devices](https://developer.cisco.com/site/ios-xe/) (Cisco IOS-XE)

**Third-Party Products & Services:**

- S3 Object Storage
  * Tested Providers _(If more is needed, let me know.)_
    - [Amazon Web Services S3](https://aws.amazon.com/s3/)
    - [Google Cloud Storage](https://cloud.google.com/storage/)
    - [DigitalOcean Spaces](https://www.digitalocean.com/products/spaces/)
    - [Minio](https://min.io/) (On-Prem/Private Cloud/Public Cloud)
      - Minio on Docker
        - ```docker run -p 9000:9000 minio/minio server /data```
- Docker Container
  * [docker-compose](https://docs.docker.com/compose/) (optional)

**Tools & Frameworks:**

- [boto3](https://github.com/boto/boto3) (Amazon Web Services (AWS) Software Development Kit (SDK) for Python)
- [schedule](https://github.com/dbader/schedule) (Python job scheduling for humans.)

## Authors & Maintainers

- Robert Csapo <rcsapo@cisco.com>

## License

This project is licensed to you under the terms of the [Cisco Sample
Code License](./LICENSE).
