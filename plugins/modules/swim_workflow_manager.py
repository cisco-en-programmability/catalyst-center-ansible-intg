#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Madhan Sankaranarayanan, Rishita Chowdhary, Abhishek Maheshwari, Syed Khadeer Ahmed, Ajith Andrew J"
DOCUMENTATION = r"""
---
module: swim_workflow_manager
short_description: Module to manage SWIM (Software Image
  Management) operations in Cisco Catalyst Center
description:
  - Manages operations for image importation, distribution,
    activation, and tagging images as golden.
  - Provides an API to fetch a software image from a
    remote file system via HTTP/FTP and upload it to
    Catalyst Center. Supported file extensions - bin,
    img, tar, smu, pie, aes, iso, ova, tar.gz, qcow2.
  - Provides an API to fetch a software image from a
    local file system and upload it to Catalyst Center.
    Supported file extensions - bin, img, tar, smu,
    pie, aes, iso, ova, tar.gz, qcow2.
  - Provides an API to fetch a software image from Cisco
    Connection Online (CCO) and upload it to Catalyst
    Center. Refer to https://software.cisco.com/download/home
    for suggested images in Cisco Catalyst Center. CCO
    functionality is available starting from Cisco Catalyst
    version 2.3.7.6.
  - Provides an API to tag or untag an image as golden
    for a given family of devices.
  - Provides an API to distribute a software image to
    a device. The software image must be imported into
    Catalyst Center before it can be distributed.
version_added: '6.6.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Madhan Sankaranarayanan (@madhansansel) Rishita
  Chowdhary (@rishitachowdhary) Abhishek Maheshwari
  (@abmahesh) Syed Khadeer Ahmed (@syed-khadeerahmed)
  Ajith Andrew J (@ajithandrewj)
options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst
      Center config after applying the playbook config.
    type: bool
    default: false
  state:
    description: The state of Catalyst Center after
      module completion.
    type: str
    choices: [merged]
    default: merged
  config:
    description: List of details of SWIM image being
      managed
    type: list
    elements: dict
    required: true
    suboptions:
      import_image_details:
        description: Details of image being imported
        type: dict
        suboptions:
          type:
            description: Specifies the source of the
              image import. Supported values are 'local'
              for local file import, 'remote' for remote
              URL import, or 'CCO' for import from Cisco
              Connection Online.
            type: str
          local_image_details:
            description: Details of the local path of
              the image to be imported.
            type: dict
            suboptions:
              file_path:
                description: Provide the absolute file
                  path needed to import an image from
                  your local system (Eg "/path/to/your/file").
                  Accepted files formats are - .gz,.bin,.img,.tar,.smu,.pie,.aes,.iso,.ova,.tar_gz,.qcow2,.nfvispkg,.zip,.spa,.rpm.
                type: str
              is_third_party:
                description: Query parameter to determine
                  if the image is from a third party
                  (optional).
                type: bool
              third_party_application_type:
                description: Specify the ThirdPartyApplicationType
                  query parameter to indicate the type
                  of third-party application. Allowed
                  values include WLC, LINUX, FIREWALL,
                  WINDOWS, LOADBALANCER, THIRDPARTY,
                  etc.(optional). WLC (Wireless LAN
                  Controller) - It's a network device
                  that manages and controls multiple
                  wireless access points (APs) in a
                  centralized manner. LINUX - It's an
                  open-source operating system that
                  provides a complete set of software
                  packages and utilities. FIREWALL -
                  It's a network security device that
                  monitors and controls incoming and
                  outgoing network traffic based on
                  predetermined security rules.It acts
                  as a barrier between a trusted internal
                  network and untrusted external networks
                  (such as the internet), preventing
                  unauthorized access. WINDOWS - It's
                  an operating system known for its
                  graphical user interface (GUI) support,
                  extensive compatibility with hardware
                  and software, and widespread use across
                  various applications. LOADBALANCER
                  - It's a network device or software
                  application that distributes incoming
                  network traffic across multiple servers
                  or resources. THIRDPARTY - It refers
                  to third-party images or applications
                  that are not part of the core system.
                  NAM (Network Access Manager) - It's
                  a network management tool or software
                  application that provides centralized
                  control and monitoring of network
                  access policies, user authentication,
                  and device compliance. WAN Optimization
                  - It refers to techniques and technologies
                  used to improve the performance and
                  efficiency of WANs. It includes various
                  optimization techniques such as data
                  compression, caching, protocol optimization,
                  and traffic prioritization to reduce
                  latency, increase throughput, and
                  improve user experience over WAN connections.
                  Unknown - It refers to an unspecified
                  or unrecognized application type.
                  Router - It's a network device that
                  forwards data packets between computer
                  networks. They are essential for connecting
                  multiple networks together and directing
                  traffic between them.
                type: str
              third_party_image_family:
                description: Provide the ThirdPartyImageFamily
                  query parameter to identify the family
                  of the third-party image. Image Family
                  name like PALOALTO, RIVERBED, FORTINET,
                  CHECKPOINT, SILVERPEAK etc. (optional).
                type: str
              third_party_vendor:
                description: Include the ThirdPartyVendor
                  query parameter to specify the vendor
                  of the third party.
                type: str
          url_details:
            description: URL details for SWIM import
            type: dict
            suboptions:
              payload:
                description: Swim Import Via Url's payload.
                type: list
                elements: dict
                suboptions:
                  application_type:
                    description: An optional parameter
                      that specifies the type of application.
                      Allowed values include WLC, LINUX,
                      FIREWALL, WINDOWS, LOADBALANCER,
                      THIRDPARTY, etc. This is only
                      applicable for third-party image
                      types(optional). WLC (Wireless
                      LAN Controller) - It's network
                      device that manages and controls
                      multiple wireless access points
                      (APs) in a centralized manner.
                      LINUX - It's an open source which
                      provide complete operating system
                      with a wide range of software
                      packages and utilities. FIREWALL
                      - It's a network security device
                      that monitors and controls incoming
                      and outgoing network traffic based
                      on predetermined security rules.It
                      acts as a barrier between a trusted
                      internal network and untrusted
                      external networks (such as the
                      internet), preventing unauthorized
                      access. WINDOWS - It's an OS which
                      provides GUI support for various
                      applications, and extensive compatibility
                      with hardware and software. LOADBALANCER
                      - It's a network device or software
                      application that distributes incoming
                      network traffic across multiple
                      servers or resources. THIRDPARTY
                      - It refers to third-party images
                      or applications that are not part
                      of the core system. NAM (Network
                      Access Manager) - It's a network
                      management tool or software application
                      that provides centralized control
                      and monitoring of network access
                      policies, user authentication,
                      and device compliance. WAN Optimization
                      - It refers to techniques and
                      technologies used to improve the
                      performance and efficiency of
                      WANs. It includes various optimization
                      techniques such as data compression,
                      caching, protocol optimization,
                      and traffic prioritization to
                      reduce latency, increase throughput,
                      and improve user experience over
                      WAN connections. Unknown - It
                      refers to an unspecified or unrecognized
                      application type. Router - It's
                      a network device that forwards
                      data packets between computer
                      networks. They are essential for
                      connecting multiple networks together
                      and directing traffic between
                      them.
                    type: str
                  image_family:
                    description: Represents the name
                      of the image family and is applicable
                      only when uploading third-party
                      images. Image Family name like
                      PALOALTO, RIVERBED, FORTINET,
                      CHECKPOINT, SILVERPEAK etc. (optional).
                    type: str
                  source_url:
                    description: A mandatory parameter
                      for importing a SWIM image via
                      a remote URL. This parameter is
                      required when using a URL to import
                      an image..(For example, http://{host}/swim/cat9k_isoxe.16.12.10s.SPA.bin,
                      ftp://user:password@{host}/swim/cat9k_isoxe.16.12.10s.SPA.iso)
                      source url can be either str or
                      list
                    type: list
                    elements: str
                  is_third_party:
                    description: Flag indicates whether
                      the image is uploaded from a third
                      party (optional).
                    type: bool
                  vendor:
                    description: The name of the vendor,
                      that applies only to third-party
                      image types when importing via
                      URL (optional).
                    type: str
              schedule_at:
                description: ScheduleAt query parameter.
                  Epoch Time (The number of milli-seconds
                  since January 1 1970 UTC) at which
                  the distribution should be scheduled
                  (optional).
                type: str
              schedule_desc:
                description: ScheduleDesc query parameter.
                  Custom Description (optional).
                type: str
              schedule_origin:
                description: ScheduleOrigin query parameter.
                  Originator of this call (optional).
                type: str
          cco_image_details:
            description:
              - Parameters related to importing a software
                image from Cisco Connection Online (CCO)
                into Catalyst Center.
              - This API fetches the specified image
                from CCO and uploads it to Catalyst
                Center.
              - Supported from Cisco Catalyst Center
                version 2.3.7.6 onward.
              - Refer to the Cisco software download
                portal (https://software.cisco.com/download/home)
                for recommended images.
            type: dict
            suboptions:
              image_name:
                description:
                  - Specifies the name of the software
                    image to be imported from Cisco.com.
                  - This parameter is mandatory to initiate
                    the download from CCO.
                  - Accepts either a single image name
                    as a string or multiple image names
                    as a list.
                type: list
                elements: str
      tagging_details:
        description: Details for tagging or untagging
          an image as golden
        type: dict
        suboptions:
          image_name:
            description: SWIM image name which will
              be tagged or untagged as golden.
            type: str
          device_role:
            description: |
              Specifies the device role(s) for tagging or untagging the image as golden.
              Permissible values:
              - 'ALL': Applies the golden tag to all devices, regardless of role.
              - 'UNKNOWN': Tags devices without a specified classification.
              - 'ACCESS': Tags devices that connect end-user devices (e.g., access switches).
              - 'BORDER ROUTER': Tags devices linking different network segments or domains.
              - 'DISTRIBUTION': Tags devices aggregating traffic toward the core.
              - 'CORE': Tags backbone devices handling high-volume network traffic.
              Behavior:
              - If 'device_role' is a single string (e.g., `"ACCESS"`), only that role is tagged as golden.
              - If 'device_role' contains multiple roles (e.g., `"ACCESS,CORE"`), all specified roles are tagged as golden.
              To replace an existing golden tag for a specific role:
              - **Unassign** the tag from the current role (e.g., `ACCESS`).
              - **Assign** the tag to the new role (e.g., `CORE`).
              Examples:
              - device_role: "ACCESS" tags only the `ACCESS` role as golden.
              - device_role: "ACCESS,CORE" tags both `ACCESS` and `CORE` roles as golden.
            type: str
          device_image_family_name:
            description: Device Image family name(Eg
              Cisco Catalyst 9300 Switch)
            type: str
          site_name:
            description: Site name for which SWIM image
              will be tagged/untagged as golden. If
              not provided, SWIM image will be mapped
              to global site.
            type: str
          tagging:
            description: Booelan value to tag/untag
              SWIM image as golden If True then the
              given image will be tagged as golden.
              If False then the given image will be
              un-tagged as golden.
            type: bool
      image_distribution_details:
        description: |
          Parameters for specifying the target device(s) for SWIM image distribution. The device can be identified using one of the following options:
          - device_serial_number
          - device_ip_address
          - device_hostname
          - device_mac_address
          - site_name (if specified, the image will be distributed to all devices within the site)
          At least one of these parameters must be provided. If 'site_name' is provided, additional filters
          such as 'device_role', 'device_family_name', and 'device_series_name' can be used to further narrow down the devices within the site.
          - SAPRO devices are not eligible for image distribution.
        type: dict
        suboptions:
          device_role:
            description: Device Role and  permissible
              Values are ALL, UNKNOWN, ACCESS, BORDER
              ROUTER, DISTRIBUTION and CORE. ALL - This
              role typically represents all devices
              within the network, regardless of their
              specific roles or functions. UNKNOWN -
              This role is assigned to devices whose
              roles or functions have not been identified
              or classified within Cisco Catalsyt Center.
              This could happen if the platform is unable
              to determine the device's role based on
              available information. ACCESS - This role
              typically represents switches or access
              points that serve as access points for
              end-user devices to connect to the network.
              These devices are often located at the
              edge of the network and provide connectivity
              to end-user devices. BORDER ROUTER - These
              are devices that connect different network
              domains or segments together. They often
              serve as gateways between different networks,
              such as connecting an enterprise network
              to the internet or connecting multiple
              branch offices. DISTRIBUTION - This role
              represents function as distribution switches
              or routers in hierarchical network designs.
              They aggregate traffic from access switches
              and route it toward the core of the network
              or toward other distribution switches.
              CORE - This role typically represents
              high-capacity switches or routers that
              form the backbone of the network. They
              handle large volumes of traffic and provide
              connectivity between different parts of
              network, such as connecting distribution
              switches or providing interconnection
              between different network segments.
            type: str
          device_family_name:
            description: Specify the name of the device
              family such as Switches and Hubs, etc.
            type: str
          site_name:
            description: Used to get device details
              associated to this site.
            type: str
          device_series_name:
            description: This parameter specifies the
              name of the device series. It is used
              to identify a specific series of devices,
              such as Cisco Catalyst 9300 Series Switches,
              within the Cisco Catalyst Center.
            type: str
            version_added: 6.12.0
          image_name:
            description: Specifies the name of the SWIM
              image to be distributed.
            type: str
          sub_package_images:
            description: Specifies a list of SWIM sub-package
              image names.
            type: list
            elements: str
          device_serial_number:
            description: Device serial number where
              the image needs to be distributed
            type: str
          device_ip_address:
            description: Device IP address where the
              image needs to be distributed
            type: str
          device_hostname:
            description: Device hostname where the image
              needs to be distributed
            type: str
          device_mac_address:
            description: Device MAC address where the
              image needs to be distributed
            type: str
      image_activation_details:
        description: |
          Parameters for specifying the target device(s) for SWIM image activation. The device can be identified using one of the following options:
          - device_serial_number
          - device_ip_address
          - device_hostname
          - device_mac_address
          - site_name (if specified, the image will be activated on all devices within the site)
          At least one of these parameters must be provided. If 'site_name' is provided, additional filters
          such as 'device_role', 'device_family_name', and 'device_series_name' can be used to further narrow down the devices within the site.
          - SAPRO devices are not eligible for image activation.
        type: dict
        suboptions:
          device_role:
            description: Defines the device role, with
              permissible values including ALL, UNKNOWN,
              ACCESS, BORDER ROUTER, DISTRIBUTION, and
              CORE.
            type: str
          device_family_name:
            description: Specify the name of the device
              family such as Switches and Hubs, etc.
            type: str
          site_name:
            description: Used to get device details
              associated to this site.
            type: str
          device_series_name:
            description: This parameter specifies the
              name of the device series. It is used
              to identify a specific series of devices,
              such as Cisco Catalyst 9300 Series Switches,
              within the Cisco Catalyst Center.
            type: str
            version_added: 6.12.0
          activate_lower_image_version:
            description: ActivateLowerImageVersion flag.
            type: bool
          device_upgrade_mode:
            description: It specifies the mode of upgrade
              to be applied to the devices having the
              following values - 'install', 'bundle',
              and 'currentlyExists'. install - This
              mode instructs Cisco Catalyst Center to
              perform a clean installation of the new
              image on the target devices. When this
              mode is selected, the existing image on
              the device is completely replaced with
              the new image during the upgrade process.
              This ensures that the device runs only
              the new image version after the upgrade
              is completed. bundle - This mode instructs
              Cisco Catalyst Center bundles the new
              image with the existing image on the device
              before initiating the upgrade process.
              This mode allows for a more efficient
              upgrade process by preserving the existing
              image on the device while adding the new
              image as an additional bundle. After the
              upgrade, the device can run either the
              existing image or the new bundled image,
              depending on the configuration. currentlyExists
              - This mode instructs Cisco Catalyst Center
              to checks if the target devices already
              have the desired image version installed.
              If image already present on devices, no
              action is taken and upgrade process is
              skipped for those devices. This mode is
              useful for avoiding unnecessary upgrades
              on devices that already have the correct
              image version installed, thereby saving
              time.
            type: str
          distribute_if_needed:
            description: Enable the distribute_if_needed
              option when activating the SWIM image.
            type: bool
          image_name:
            description: Specifies the name of the SWIM
              image to be activated.
            type: str
          sub_package_images:
            description: Specifies a list of SWIM sub-package
              image names.
            type: list
            elements: str
          device_serial_number:
            description: Device serial number where
              the image needs to be activated
            type: str
          device_ip_address:
            description: Device IP address where the
              image needs to be activated
            type: str
          device_hostname:
            description: Device hostname where the image
              needs to be activated
            type: str
          device_mac_address:
            description: Device MAC address where the
              image needs to be activated
            type: str
          schedule_validate:
            description: ScheduleValidate query parameter.
              ScheduleValidate, validates data before
              schedule (optional).
            type: bool
requirements:
  - dnacentersdk == 2.7.3
  - python >= 3.9
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.import_software_image_via_url,
    software_image_management_swim.SoftwareImageManagementSwim.tag_as_golden_image,
    software_image_management_swim.SoftwareImageManagementSwim.trigger_software_image_distribution,
    software_image_management_swim.SoftwareImageManagementSwim.trigger_software_image_activation,
  - Paths used are
    post /dna/intent/api/v1/image/importation/source/url,
    post /dna/intent/api/v1/image/importation/golden,
    post /dna/intent/api/v1/image/distribution,
    post
    /dna/intent/api/v1/image/activation/device,
    - Added
    the parameter 'dnac_api_task_timeout',
    'dnac_task_poll_interval'
    options in v6.13.2.
"""
EXAMPLES = r"""
---
- name: Import an image from a URL, tag it as golden
    and load it on device
  cisco.dnac.swim_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - import_image_details:
          type: remote
          url_details:
            payload:
              - source_url:
                  - "http://10.10.10.10/stda/cat9k_iosxe.17.12.01.SPA.bin"
                is_third_party: false
        tagging_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          device_role: ACCESS
          device_image_family_name: Cisco Catalyst 9300
            Switch
          site_name: Global/USA/San Francisco/BGL_18
          tagging: true
        image_distribution_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          device_serial_number: FJC2327U0S2
        image_activation_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          schedule_validate: false
          activate_lower_image_version: false
          distribute_if_needed: true
          device_serial_number: FJC2327U0S2
- name: Import an image from local, tag it as golden.
  cisco.dnac.swim_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - import_image_details:
          type: local
          local_image_details:
            file_path: /Users/Downloads/cat9k_iosxe.17.12.01.SPA.bin
            is_third_party: false
        tagging_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          device_role: ACCESS
          device_image_family_name: Cisco Catalyst 9300
            Switch
          site_name: Global/USA/San Francisco/BGL_18
          tagging: true
- name: Import bulk images from URL
  cisco.dnac.swim_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - import_image_details:
          type: remote
          url_details:
            payload:
              - source_url:
                  - "http://10.10.10.10/stda/cat9k_iosxe.17.12.01.SPA.bin"
                  - "http://10.10.10.10/stda/cat9k_iosxe.17.12.02.SPA.bin"
            is_third_party: false
- name: Import image from URL using str
  cisco.dnac.swim_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - import_image_details:
          type: remote
          url_details:
            payload:
              - source_url: "http://10.10.10.10/stda/cat9k_iosxe.17.12.01.SPA.bin"
            is_third_party: false
- name: Import images from CCO (cisco.com)
  cisco.dnac.swim_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - import_image_details:
          type: CCO
          cco_image_details:
            image_name: cat9k_iosxe.17.06.06a.SPA.bin
- name: Import list of images from CCO (cisco.com)
  cisco.dnac.swim_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - import_image_details:
          type: CCO
          cco_image_details:
            image_name:
              - cat9k_iosxe.17.16.01.SPA.bin
              - C9800-SW-iosxe-wlc.17.16.01.SPA.bin
              - C9800-80-universalk9_wlc.17.15.02b.SPA.bin
- name: Tag the given image as golden and load it on
    device
  cisco.dnac.swim_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - tagging_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          device_role: ACCESS
          device_image_family_name: Cisco Catalyst 9300
            Switch
          site_name: Global/USA/San Francisco/BGL_18
          tagging: true
# Remove the golden tag from the specified image for the given device role and assign it to another device role.
- name: Update golden tag assignment for image based
    on device role
  cisco.dnac.swim_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - tagging_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          device_role: CORE
          device_image_family_name: Cisco Catalyst 9300
            Switch
          tagging: false
      - tagging_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          device_role: ACCESS
          device_image_family_name: Cisco Catalyst 9300
            Switch
          tagging: true
- name: Tag the specified image as golden for multiple
    device roles and load it into the device
  cisco.dnac.swim_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - tagging_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          device_role: ACCESS,CORE
          device_image_family_name: Cisco Catalyst 9300
            Switch
          site_name: Global/USA/San Francisco/BGL_18
          tagging: true
- name: Un-tagged the given image as golden and load
    it on device
  cisco.dnac.swim_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - tagging_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          device_role: ACCESS
          device_image_family_name: Cisco Catalyst 9300
            Switch
          site_name: Global/USA/San Francisco/BGL_18
          tagging: false
- name: Distribute the given image on devices associated
    to that site with specified role.
  cisco.dnac.swim_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - image_distribution_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          site_name: Global/USA/San Francisco/BGL_18
          device_role: ALL
          device_family_name: Switches and Hubs
          device_series_name: Cisco Catalyst 9300 Series
            Switches
- name: Activate the given image on devices associated
    to that site with specified role.
  cisco.dnac.swim_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - image_activation_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          site_name: Global/USA/San Francisco/BGL_18
          device_role: ALL
          device_family_name: Switches and Hubs
          device_series_name: Cisco Catalyst 9300 Series
            Switches
          scehdule_validate: false
          activate_lower_image_version: true
          distribute_if_needed: true
"""
RETURN = r"""
#Case: SWIM image is successfully imported, tagged as golden, distributed and activated on a device
response:
  description: A dictionary with activation details as returned by the Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
                        "additionalStatusURL": String,
                        "data": String,
                        "endTime": 0,
                        "id": String,
                        "instanceTenantId": String,
                        "isError": bool,
                        "lastUpdate": 0,
                        "progress": String,
                        "rootId": String,
                        "serviceType": String,
                        "startTime": 0,
                        "version": 0
                  },
      "msg": String
    }
"""

from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    get_dict_result,
)
from ansible.module_utils.basic import AnsibleModule
import os
import time


class Swim(DnacBase):
    """Class containing member attributes for Swim workflow_manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged"]
        self.images_to_import, self.existing_images = [], []

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.
        Parameters:
          - self: The instance of the class containing the 'config' attribute to be validated.
        Returns:
          The method returns an instance of the class with updated attributes:
          - self.msg: A message describing the validation result.
          - self.status: The status of the validation (either 'success' or 'failed').
          - self.validated_config: If successful, a validated version of 'config' parameter.
        Example:
            To use this method, create an instance of the class and call 'validate_input' on it.
          If the validation succeeds, 'self.status' will be 'success' and 'self.validated_config'
          will contain the validated configuration. If it fails, 'self.status' will be 'failed',
          'self.msg' will describe the validation issues.
        """

        if not self.config:
            self.status = "success"
            self.msg = "Configuration is not available in the playbook for validation"
            self.log(self.msg, "ERROR")
            return self

        temp_spec = dict(
            import_image_details=dict(type="dict"),
            tagging_details=dict(type="dict"),
            image_distribution_details=dict(type="dict"),
            image_activation_details=dict(type="dict"),
        )

        # Validate swim params
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)

        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(invalid_params)
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook config params: {0}".format(
            str(valid_temp)
        )
        self.log(self.msg, "INFO")
        self.status = "success"

        return self

    def site_exists(self, site_name):
        """
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            tuple: A tuple containing two values:
            - site_exists (bool): A boolean indicating whether the site exists (True) or not (False).
            - site_id (str or None): The ID of the site if it exists, or None if the site is not found.
        Description:
            This method checks the existence of a site in the Catalyst Center. If the site is found,it sets 'site_exists' to True,
            retrieves the site's ID, and returns both values in a tuple. If the site does not exist, 'site_exists' is set
            to False, and 'site_id' is None. If an exception occurs during the site lookup, an exception is raised.
        """

        site_exists = False
        site_id = None
        response = None

        try:
            response = self.get_site(site_name)
            if response is None:
                raise ValueError
            site = response.get("response")
            site_id = site[0].get("id")
            site_exists = True

        except Exception as e:
            self.status = "failed"
            self.msg = "An exception occurred: Site '{0}' does not exist in the Cisco Catalyst Center.".format(
                site_name
            )
            self.result["response"] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

        return (site_exists, site_id)

    def get_image_id(self, name):
        """
        Retrieve the unique image ID based on the provided image name.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            name (str): The name of the software image to search for.
        Returns:
            str: The unique image ID (UUID) corresponding to the given image name.
        Raises:
            AnsibleFailJson: If the image is not found in the response.
        Description:
            This function sends a request to Cisco Catalyst Center to retrieve details about a software image based on its name.
            It extracts and returns the image ID if a single matching image is found. If no image or multiple
            images are found with the same name, it raises an exception.
        """

        image_response = self.dnac._exec(
            family="software_image_management_swim",
            function="get_software_image_details",
            op_modifies=True,
            params={"image_name": name},
        )
        self.log(
            "Received API response from 'get_software_image_details': {0}".format(
                str(image_response)
            ),
            "DEBUG",
        )
        image_list = image_response.get("response")

        if len(image_list) == 1:
            image_id = image_list[0].get("imageUuid")
            self.log("SWIM image '{0}' has the ID: {1}".format(name, image_id), "INFO")
        else:
            self.msg = "SWIM image '{0}' could not be found".format(name)
            self.log(self.msg, "ERROR")
            self.status = "failed"
            self.result["response"] = self.msg
            self.check_return_status()

        return image_id

    def get_cco_image_id(self, cco_image_name):
        """
        Retrieve the unique image ID from Cisco.com based on the provided image name.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco DNA Center.
            cco_image_name (str): The name of the software image to search for on Cisco.com.

        Returns:
            str: The image ID corresponding to the given image name.
            None: If the image is not present in the Cisco catalyst center
        Raises:
            AnsibleFailJson: If the image ID cannot be found in the response.

        Description:
            This function sends a request to Cisco Catalsyt Center to retrieve a list of software images
            using the 'returns_list_of_software_images' API. It then iterates through the response
            to find a match for the provided 'cco_image_name'. If a match is found, the corresponding
            image ID is returned. If no matching image is found, or if the image ID is not present
            in the response, the function logs an error message and raises an exception.
        """
        try:
            response = self.dnac._exec(
                family="software_image_management_swim",
                function="returns_list_of_software_images",
                op_modifies=True,
            )
            self.log(
                "Received API response from 'returns_list_of_software_images': {0}".format(
                    response
                ),
                "DEBUG",
            )
            response = response.get("response")

            if not response or not isinstance(response, list):
                self.log(
                    "The API response from 'returns_list_of_software_images' is empty or invalid.",
                    "ERROR",
                )
                self.status = "failed"
                self.msg = (
                    "Unable to retrieve the list of software images from Cisco.com."
                )
                self.result["response"] = self.msg
                self.check_return_status()

            for image in response:
                if cco_image_name == image.get("name"):
                    image_id = image.get("id")
                    if image_id:
                        return image_id
            return None
        except Exception as e:
            dnac_host = self.params.get("dnac_host")
            self.msg = "CCO image '{0}' not found in the image repository on Cisco Catalyst Center '{1}'".format(
                cco_image_name, dnac_host
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

    def get_image_name_from_id(self, image_id):
        """
        Retrieve the unique image name based on the provided image id.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            id (str): The unique image ID (UUID) of the software image to search for.
        Returns:
            str: The image name corresponding to the given unique image ID (UUID)
        Raises:
            AnsibleFailJson: If the image is not found in the response.
        Description:
            This function sends a request to Cisco Catalyst Center to retrieve details about a software image based on its id.
            It extracts and returns the image name if a single matching image is found. If no image or multiple
            images are found with the same name, it raises an exception.
        """

        image_response = self.dnac._exec(
            family="software_image_management_swim",
            function="get_software_image_details",
            op_modifies=True,
            params={"image_uuid": image_id},
        )
        self.log(
            "Received API response from 'get_software_image_details': {0}".format(
                str(image_response)
            ),
            "DEBUG",
        )
        image_list = image_response.get("response")

        if len(image_list) == 1:
            image_name = image_list[0].get("name")
            self.log(
                "SWIM image '{0}' has been fetched successfully from Cisco Catalyst Center".format(
                    image_name
                ),
                "INFO",
            )
        else:
            self.msg = "SWIM image with Id '{0}' could not be found in Cisco Catalyst Center".format(
                image_id
            )
            self.log(self.msg, "ERROR")
            self.status = "failed"
            self.result["response"] = self.msg
            self.check_return_status()

        return image_name

    def is_image_exist(self, name):
        """
        Retrieve the unique image ID based on the provided image name.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            name (str): The name of the software image to search for.
        Returns:
            str: The unique image ID (UUID) corresponding to the given image name.
        Raises:
            AnsibleFailJson: If the image is not found in the response.
        Description:
            This function sends a request to Cisco Catalyst Center to retrieve details about a software image based on its name.
            It extracts and returns the image ID if a single matching image is found. If no image or multiple
            images are found with the same name, it raises an exception.
        """

        image_exist = False
        image_response = self.dnac._exec(
            family="software_image_management_swim",
            function="get_software_image_details",
            op_modifies=True,
            params={"image_name": name},
        )
        self.log(
            "Received API response from 'get_software_image_details': {0}".format(
                str(image_response)
            ),
            "DEBUG",
        )
        image_list = image_response.get("response")

        if len(image_list) == 1:
            image_exist = True

        return image_exist

    def get_device_id(self, params):
        """
        Retrieve the unique device ID based on the provided parameters.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            params (dict): A dictionary containing parameters to filter devices.
        Returns:
            str or None: The unique device ID corresponding to the filtered device, or None if an error occurs.
        Raises:
            AnsibleFailJson: If the device ID cannot be found in the response.
        Description:
            This function sends a request to Cisco Catalyst Center to retrieve a list of devices based on the provided
            filtering parameters. If a single matching device is found, it extracts and returns the device ID. If
            no device or multiple devices match the criteria, it raises an exception.
        """
        try:
            response = self.dnac._exec(
                family="devices",
                function="get_device_list",
                op_modifies=True,
                params=params,
            )
            self.log(
                "Received API response from 'get_device_list': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )

            device_list = response.get("response")

            if not device_list:
                self.log(
                    "Device list is empty; no devices found for given parameters.",
                    "WARNING",
                )
                raise ValueError("No devices found")

            if len(device_list) == 1:
                device_id = device_list[0].get("id")
                self.log(
                    "Successfully retrieved device ID: {0}".format(device_id), "INFO"
                )
                return device_id

            self.log(
                "Multiple devices found for parameters: {0}".format(params), "ERROR"
            )
            raise ValueError("Multiple devices found")

        except ValueError as ve:
            msg = "Error: {0}. Unable to fetch unique device ID with parameters: {1}".format(
                str(ve), params
            )
            self.log(msg, "ERROR")
            return None

        except Exception as e:
            msg = "An unexpected error occurred while retrieving device ID: {0}".format(
                str(e)
            )
            self.log(msg, "ERROR")
            return None

    def get_device_uuids(
        self, site_name, device_family, device_role, device_series_name=None
    ):
        """
        Retrieve a list of device UUIDs based on the specified criteria.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_name (str): The name of the site for which device UUIDs are requested.
            device_family (str): The family/type of devices to filter on.
            device_role (str): The role of devices to filter on. If None, 'ALL' roles are considered.
            device_series_name(str): Specifies the name of the device series.
        Returns:
            list: A list of device UUIDs that match the specified criteria.
        Description:
            The function checks the reachability status and role of devices in the given site.
            Only devices with "Reachable" status are considered, and filtering is based on the specified
            device family and role (if provided).
        """

        device_uuid_list = []
        device_id_list, site_response_list = [], []
        if not site_name:
            site_names = "Global/.*"
            self.log(
                "Site name not specified; defaulting to 'Global' to fetch all devices under this category",
                "INFO",
            )

        (site_exists, site_id) = self.site_exists(site_name)
        if not site_exists:
            self.log(
                """Site '{0}' is not found in the Cisco Catalyst Center, hence unable to fetch associated
                        devices.""".format(
                    site_name
                ),
                "INFO",
            )
            return device_uuid_list

        if device_series_name:
            if device_series_name.startswith(".*") and device_series_name.endswith(
                ".*"
            ):
                self.log(
                    "Device series name '{0}' is already in the regex format".format(
                        device_series_name
                    ),
                    "INFO",
                )
            else:
                device_series_name = ".*" + device_series_name + ".*"

        if self.dnac_version <= self.version_2_3_5_3:
            site_params = {"site_id": site_id, "device_family": device_family}

            try:
                response = self.dnac._exec(
                    family="sites",
                    function="get_membership",
                    op_modifies=True,
                    params=site_params,
                )

            except Exception as e:
                self.log(
                    "Unable to fetch the device(s) associated to the site '{0}' due to '{1}'".format(
                        site_name, str(e)
                    ),
                    "WARNING",
                )
                return device_uuid_list

            self.log(
                "Received API response from 'get_membership': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )
            response = response.get("device")

            for item in response:
                if item["response"]:
                    for item_dict in item["response"]:
                        site_response_list.append(item_dict)
        else:
            site_type = self.get_sites_type(site_name)
            site_info = {}

            self.log("Starting site hierarchy processing for: '{0}' (Type: {1})".format(site_name, site_type), "INFO")
            if site_type == "building":
                self.log(
                    "Processing site as a building: {site_name}".format(site_name=site_name),
                    "DEBUG",
                )

                site_info = {}

                self.log("Fetching parent site data for building: {0}".format(site_name), "DEBUG")
                parent_site_data = self.get_site(site_name)

                if parent_site_data.get("response"):
                    self.log(
                        "Parent site data found for building: '{0}'. Processing {1} items.".format(
                            site_name,
                            len(parent_site_data.get('response') or [])
                        ),
                        "DEBUG"
                    )
                    for item in parent_site_data["response"]:
                        if "nameHierarchy" in item and "id" in item:
                            site_info[item["nameHierarchy"]] = item["id"]
                            self.log("Added parent site '{0}' with ID '{1}' to site_info.".format(item['nameHierarchy'], item['id']), "DEBUG")
                        else:
                            self.log(
                                "Missing 'nameHierarchy' or 'id' in parent site item: {0}".format(str(item)),
                                "WARNING"
                            )
                    self.log("Parent site data: {0}".format(str(parent_site_data)), "DEBUG")
                else:
                    self.log("No data found for parent site: {0}".format(site_name), "WARNING")
                self.log("Current site_info after parent processing: {0}".format(site_info), "DEBUG")
                wildcard_site_name = site_name + "/.*"
                self.log("Attempting to fetch child sites for building with wildcard: {0}".format(wildcard_site_name), "DEBUG")
                child_site_data = self.get_site(wildcard_site_name)

                if child_site_data and child_site_data.get("response"):
                    self.log(
                        "Child site data found for building: '{0}'. Processing {1} items.".format(
                            wildcard_site_name,
                            len(child_site_data.get('response') or [])
                        ),
                        "DEBUG"
                    )
                    for item in child_site_data["response"]:
                        if "nameHierarchy" in item and "id" in item:
                            site_info[item["nameHierarchy"]] = item["id"]
                            self.log("Added child site '{0}' with ID '{1}' to site_info.".format(item['nameHierarchy'], item['id']), "DEBUG")
                        else:
                            self.log(
                                "Missing 'nameHierarchy' or 'id' in child site item: {0}".format(str(item)),
                                "WARNING"
                            )
                    self.log("Child site data found and logged for: {0}".format(wildcard_site_name), "DEBUG")
                    site_names = wildcard_site_name
                else:
                    self.log("No child site data found under: {0}".format(wildcard_site_name), "DEBUG")
                    site_names = site_name

            elif site_type == "area":
                self.log(
                    "Processing site as an area: {site_name}".format(site_name=site_name),
                    "DEBUG",
                )

                wildcard_site_name = site_name + "/.*"
                self.log("Attempting to fetch child sites for area using wildcard:: {0}".format(wildcard_site_name), "DEBUG")
                child_site_data = self.get_site(wildcard_site_name)
                self.log("Child site data: {0}".format(str(child_site_data)), "DEBUG")

                if child_site_data and child_site_data.get("response"):
                    self.log("Child sites found for area: '{0}'. Setting site_names to wildcard.".format(wildcard_site_name), "DEBUG")
                    site_names = wildcard_site_name
                else:
                    self.log("No child sites found under area: '{0}'. Using original site name: '{1}'.".format(wildcard_site_name, site_name), "DEBUG")
                    site_names = site_name

            elif site_type == "floor":
                self.log(
                    "Processing site as a floor: {site_name}".format(
                        site_name=site_name
                    ),
                    "DEBUG",
                )
                site_names = site_name

            else:
                self.log(
                    "Unknown site type '{site_type}' for site '{site_name}'.".format(
                        site_type=site_type, site_name=site_name
                    ),
                    "ERROR",
                )

            if site_type in ["area", "floor"]:
                self.log("Fetching site names for pattern: {0}".format(site_names), "DEBUG")
                get_site_names = self.get_site(site_names)
                self.log("Fetched site names: {0}".format(str(get_site_names)), "DEBUG")

                for item in get_site_names.get('response', []):
                    if 'nameHierarchy' in item and 'id' in item:
                        site_info[item['nameHierarchy']] = item['id']
                    else:
                        self.log(
                            "Missing 'nameHierarchy' or 'id' in site item: {0}".format(str(item)),
                            "WARNING"
                        )
            self.log("Site information retrieved: {0}".format(str(site_info)), "DEBUG")

            for site_name, site_id in site_info.items():
                offset = 1
                limit = self.get_device_details_limit()

                while True:
                    try:
                        response = self.dnac._exec(
                            family="site_design",
                            function="get_site_assigned_network_devices",
                            params={
                                "site_id": site_id,
                                "offset": offset,
                                "limit": limit,
                            },
                        )
                        self.log(
                            "Received API response from 'get_site_assigned_network_devices' for site '{0}': {1}".format(
                                site_name, response
                            ),
                            "DEBUG",
                        )

                        devices = response.get("response", [])
                        if not devices:
                            self.log(
                                "No more devices found for site '{0}'.".format(
                                    site_name
                                ),
                                "INFO",
                            )
                            break

                        for device in devices:
                            device_id_list.append(device.get("deviceId"))

                        offset += limit

                    except Exception as e:
                        self.log(
                            "Unable to fetch devices for site '{0}' due to '{1}'".format(
                                site_name, e
                            ),
                            "WARNING",
                        )
                        break

            for device_id in device_id_list:
                self.log("Processing device_id: {0}".format(device_id))
                try:
                    device_list_response = self.dnac._exec(
                        family="devices",
                        function="get_device_list",
                        params={"id": device_id},
                    )

                    self.log(
                        "Received API response from 'get_device_list': {0}".format(
                            str(device_list_response)
                        ),
                        "DEBUG",
                    )

                    device_response = device_list_response.get("response")
                    if not device_response:
                        self.log(
                            "No device data found for device_id: {0}".format(device_id),
                            "INFO",
                        )
                        continue

                    for device in device_response:
                        if device.get("instanceUuid") in device_id_list:
                            if (
                                device_family is None
                                or device.get("family") == device_family
                            ):
                                site_response_list.append(device)

                except Exception as e:
                    self.log(
                        "Unable to fetch devices for site '{0}' due to: {1}".format(
                            site_name, str(e)
                        ),
                        "WARNING",
                    )
                    return device_uuid_list

        self.device_ips = []
        for item in site_response_list:
            device_ip = item["managementIpAddress"]
            self.device_ips.append(device_ip)

        if device_role.upper() == "ALL":
            device_role = None

        device_params = {
            "series": device_series_name,
            "family": device_family,
            "role": device_role,
        }
        offset = 0
        limit = self.get_device_details_limit()
        initial_exec = False
        site_memberships_ids, device_response_ids = [], []

        while True:
            try:
                if initial_exec:
                    device_params["limit"] = limit
                    device_params["offset"] = offset * limit
                    device_list_response = self.dnac._exec(
                        family="devices",
                        function="get_device_list",
                        params=device_params,
                    )
                else:
                    initial_exec = True
                    device_list_response = self.dnac._exec(
                        family="devices",
                        function="get_device_list",
                        op_modifies=True,
                        params=device_params,
                    )
                self.log(
                    "Received API response from 'device_list_response': {0}".format(
                        str(device_list_response)
                    ),
                    "DEBUG",
                )
                offset = offset + 1
                device_response = device_list_response.get("response")

                if not device_response:
                    self.log(
                        "Failed to retrieve devices associated with the site '{0}' due to empty API response.".format(
                            site_name
                        ),
                        "INFO",
                    )
                    break

                for item in site_response_list:
                    if item["reachabilityStatus"] != "Reachable":
                        self.log(
                            """Device '{0}' is currently '{1}' and cannot be included in the SWIM distribution/activation
                                    process.""".format(
                                item["managementIpAddress"], item["reachabilityStatus"]
                            ),
                            "INFO",
                        )
                        continue
                    self.log(
                        """Device '{0}' from site '{1}' is ready for the SWIM distribution/activation
                                process.""".format(
                            item["managementIpAddress"], site_name
                        ),
                        "INFO",
                    )
                    site_memberships_ids.append(item["instanceUuid"])

                for item in device_response:
                    if item["reachabilityStatus"] != "Reachable":
                        self.log(
                            """Unable to proceed with the device '{0}' for SWIM distribution/activation as its status is
                                    '{1}'.""".format(
                                item["managementIpAddress"], item["reachabilityStatus"]
                            ),
                            "INFO",
                        )
                        continue
                    self.log(
                        """Device '{0}' matches to the specified filter requirements and is set for SWIM
                            distribution/activation.""".format(
                            item["managementIpAddress"]
                        ),
                        "INFO",
                    )
                    device_response_ids.append(item["instanceUuid"])
            except Exception as e:
                self.msg = "An exception occured while fetching the device uuids from Cisco Catalyst Center: {0}".format(
                    str(e)
                )
                self.log(self.msg, "ERROR")
                return device_uuid_list

        if not device_response_ids or not site_memberships_ids:
            self.log(
                "Failed to retrieve devices associated with the site '{0}' due to empty API response.".format(
                    site_name
                ),
                "INFO",
            )
            return device_uuid_list

        # Find the intersection of device IDs with the response get from get_membership api and get_device_list api with provided filters
        device_uuid_list = set(site_memberships_ids).intersection(
            set(device_response_ids)
        )

        return device_uuid_list

    def get_device_family_identifier(self, family_name):
        """
        Retrieve and store the device family identifier based on the provided family name.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            family_name (str): The name of the device family for which to retrieve the identifier.
        Returns:
            None
        Raises:
            AnsibleFailJson: If the family name is not found in the response.
        Description:
            This function sends a request to Cisco Catalyst Center to retrieve a list of device family identifiers.It then
            searches for a specific family name within the response and stores its associated identifier. If the family
            name is found, the identifier is stored; otherwise, an exception is raised.
        """

        have = {}
        if self.dnac_version >= self.version_2_2_3_3:
            response = self.dnac._exec(
                family="software_image_management_swim",
                function="get_device_family_identifiers",
            )
            self.log(
                "Received API response from 'get_device_family_identifiers': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )
            device_family_db = response.get("response")
        else:
            self.status = "failed"
            self.msg = "This version : '{0}' has no 'get_device_family_identifiers' functionality ".format(
                self.payload.get("dnac_version")
            )
            self.result["response"] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

        if device_family_db:
            device_family_details = get_dict_result(
                device_family_db, "deviceFamily", family_name
            )

            if device_family_details:
                device_family_identifier = device_family_details.get(
                    "deviceFamilyIdentifier"
                )
                have["device_family_identifier"] = device_family_identifier
                self.log(
                    "Family device indentifier: {0}".format(
                        str(device_family_identifier)
                    ),
                    "INFO",
                )
            else:
                self.msg = "Device Family: {0} not found".format(str(family_name))
                self.log(self.msg, "ERROR")
                self.module.fail_json(msg=self.msg, response=self.msg)
            self.have.update(have)

    def get_have(self):
        """
        Retrieve and store various software image and device details based on user-provided information.
        Returns:
            self: The current instance of the class with updated 'have' attributes.
        Raises:
            AnsibleFailJson: If required image or device details are not provided.
        Description:
            This function populates the 'have' dictionary with details related to software images, site information,
            device families, distribution devices, and activation devices based on user-provided data in the 'want' dictionary.
            It validates and retrieves the necessary information from Cisco Catalyst Center to support later actions.
        """

        if self.want.get("tagging_details"):
            have = {}
            tagging_details = self.want.get("tagging_details")
            if tagging_details.get("image_name"):
                name = tagging_details.get("image_name").split("/")[-1]
                image_id = self.get_image_id(name)
                have["tagging_image_id"] = image_id

            elif self.have.get("imported_image_id"):
                have["tagging_image_id"] = self.have.get("imported_image_id")

            else:
                self.log("Image details for tagging not provided", "CRITICAL")
                self.module.fail_json(
                    msg="Image details for tagging not provided", response=[]
                )

            # check if given site exists, store siteid
            # if not then use global site
            site_name = tagging_details.get("site_name")
            if site_name and site_name != "Global":
                site_exists = False
                (site_exists, site_id) = self.site_exists(site_name)
                if site_exists:
                    have["site_id"] = site_id
                    self.log(
                        "Site {0} exists having the site id: {1}".format(
                            site_name, str(site_id)
                        ),
                        "DEBUG",
                    )
            else:
                # For global site, use -1 as siteId
                have["site_id"] = "-1"
                self.log("Site Name not given by user. Using global site.", "WARNING")

            self.have.update(have)
            # check if given device family name exists, store indentifier value
            family_name = tagging_details.get("device_image_family_name")
            self.get_device_family_identifier(family_name)

        if self.want.get("distribution_details"):
            have = {}
            distribution_details = self.want.get("distribution_details")
            site_name = distribution_details.get("site_name")
            if site_name:
                site_exists = False
                (site_exists, site_id) = self.site_exists(site_name)

                if site_exists:
                    have["site_id"] = site_id
                    self.log(
                        "Site '{0}' exists and has the site ID: {1}".format(
                            site_name, str(site_id)
                        ),
                        "DEBUG",
                    )

            # check if image for distributon is available
            if distribution_details.get("image_name"):
                name = distribution_details.get("image_name").split("/")[-1]
                image_id = self.get_image_id(name)
                have["distribution_image_id"] = image_id

            elif self.have.get("imported_image_id"):
                have["distribution_image_id"] = self.have.get("imported_image_id")

            else:
                self.log(
                    "Image details required for distribution have not been provided",
                    "ERROR",
                )
                self.module.fail_json(
                    msg="Image details required for distribution have not been provided",
                    response=[],
                )

            device_params = {
                "hostname": distribution_details.get("device_hostname"),
                "serialNumber": distribution_details.get("device_serial_number"),
                "managementIpAddress": distribution_details.get("device_ip_address"),
                "macAddress": distribution_details.get("device_mac_address"),
            }

            if any(device_params.values()):
                device_id = self.get_device_id(device_params)

                if device_id is None:
                    params_list = []
                    for key, value in device_params.items():
                        if value:
                            formatted_param = "{0}: {1}".format(key, value)
                            params_list.append(formatted_param)

                    params_message = ", ".join(params_list)
                    self.status = "failed"
                    self.msg = "The device with the following parameter(s): {0} could not be found in the Cisco Catalyst Center.".format(
                        params_message
                    )
                    self.log(self.msg, "ERROR")
                    self.result["response"] = self.msg
                    self.check_return_status()

                else:
                    self.log(
                        "Device with ID {0} found and added to distribution details.".format(
                            device_id
                        ),
                        "DEBUG",
                    )
                    have["distribution_device_id"] = device_id

            self.have.update(have)

        if self.want.get("activation_details"):
            have = {}
            activation_details = self.want.get("activation_details")
            # check if image for activation is available
            if activation_details.get("image_name"):
                name = activation_details.get("image_name").split("/")[-1]
                image_id = self.get_image_id(name)
                have["activation_image_id"] = image_id

            elif self.have.get("imported_image_id"):
                have["activation_image_id"] = self.have.get("imported_image_id")
            else:
                self.log(
                    "Image details required for activation have not been provided",
                    "ERROR",
                )
                self.module.fail_json(
                    msg="Image details required for activation have not been provided",
                    response=[],
                )

            site_name = activation_details.get("site_name")
            if site_name:
                site_exists = False
                (site_exists, site_id) = self.site_exists(site_name)
                if site_exists:
                    have["site_id"] = site_id
                    self.log(
                        "The site '{0}' exists and has the site ID '{1}'".format(
                            site_name, str(site_id)
                        ),
                        "INFO",
                    )

            device_params = {
                "hostname": activation_details.get("device_hostname"),
                "serialNumber": activation_details.get("device_serial_number"),
                "managementIpAddress": activation_details.get("device_ip_address"),
                "macAddress": activation_details.get("device_mac_address"),
            }

            # Check if any device parameters are provided
            if any(device_params.values()):
                device_id = self.get_device_id(device_params)

                if device_id is None:
                    desired_keys = {
                        "hostname",
                        "serialNumber",
                        "managementIpAddress",
                        "macAddress",
                    }
                    params_list = []

                    # Format only the parameters that are present
                    for key, value in device_params.items():
                        if value and key in desired_keys:
                            formatted_param = "{0}: {1}".format(key, value)
                            params_list.append(formatted_param)

                    params_message = ", ".join(params_list)
                    self.status = "failed"
                    self.msg = "The device with the following parameter(s): {0} could not be found in the Cisco Catalyst Center.".format(
                        params_message
                    )
                    self.log(self.msg, "ERROR")
                    self.result["response"] = self.msg
                    self.check_return_status()

                else:
                    have["activation_device_id"] = device_id
                    self.log(
                        "Device with ID {0} found and added to activation details.".format(
                            device_id
                        ),
                        "DEBUG",
                    )

            self.have.update(have)

        self.log("Current State (have): {0}".format(str(self.have)), "INFO")

        return self

    def get_want(self, config):
        """
        Retrieve and store import, tagging, distribution, and activation details from playbook configuration.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing image import and other details.
        Returns:
            self: The current instance of the class with updated 'want' attributes.
        Raises:
            AnsibleFailJson: If an incorrect import type is specified.
        Description:
            This function parses the playbook configuration to extract information related to image
            import, tagging, distribution, and activation. It stores these details in the 'want' dictionary
            for later use in the Ansible module.
        """

        want = {}
        import_image_details = config.get("import_image_details", {})
        if import_image_details:
            want["import_image"] = True
            want["import_type"] = import_image_details.get("type").lower()
            import_type = want["import_type"]
            if self.dnac_version < self.version_2_3_7_6:
                if import_type == "remote":
                    want["url_import_details"] = import_image_details.get("url_details")
                elif import_type == "local":
                    want["local_import_details"] = import_image_details.get(
                        "local_image_details"
                    )
                else:
                    self.log(
                        "The import type '{0}' provided is incorrect. Only 'local' or 'remote' is supported.".format(
                            import_type
                        ),
                        "CRITICAL",
                    )
                    self.module.fail_json(
                        msg="Incorrect import type. Supported Values: local or remote"
                    )
            else:
                if import_type == "remote":
                    want["url_import_details"] = import_image_details.get("url_details")
                elif import_type == "local":
                    want["local_import_details"] = import_image_details.get(
                        "local_image_details"
                    )
                elif import_type == "cco":
                    cco_import_details = config.get("import_image_details", {}).get(
                        "cco_image_details"
                    )

                    if (
                        cco_import_details is not None
                        and cco_import_details.get("image_name") is not None
                    ):
                        want["cco_import_details"] = cco_import_details
                    else:
                        self.log(
                            "CCO import details are missing from the provided configuration.",
                            "ERROR",
                        )
                        self.module.fail_json(
                            msg="Missing CCO import details in the configuration."
                        )
                else:
                    self.log(
                        "The import type '{0}' provided is incorrect. Only 'local' or 'remote' or 'CCO' is supported.".format(
                            import_type
                        ),
                        "CRITICAL",
                    )
                    self.module.fail_json(
                        msg="Incorrect import type. Only 'local' or 'remote' or 'CCO' is supported."
                    )

        want["tagging_details"] = config.get("tagging_details")
        want["distribution_details"] = config.get("image_distribution_details")
        want["activation_details"] = config.get("image_activation_details")

        self.want = want
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        return self

    def get_diff_import(self):
        """
        Check the image import type and fetch the image ID for the imported image for further use.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        """

        images_failed_to_import = []
        try:
            import_type = self.want.get("import_type")

            if not import_type:
                self.status = "success"
                self.msg = "Error: Details required for importing SWIM image. Please provide the necessary information."
                self.result["response"] = self.msg
                self.result["msg"] = self.msg
                self.log(self.msg, "WARNING")
                self.result["response"] = self.msg
                self.result["changed"] = False
                return self

            self.log("image_type - {0}".format(import_type))
            if import_type == "remote":
                image_names = []
                for item in self.want.get("url_import_details", {}).get("payload", []):
                    source_url = item.get("source_url")  # Fetch once
                    if source_url:
                        if isinstance(source_url, list):
                            image_names.extend(source_url)
                        elif isinstance(source_url, str):
                            image_names.append(source_url)
                        else:
                            self.msg = "Warning: Unexpected type for source_url"
                            self.set_operation_result(
                                "failed", False, self.msg, "ERROR"
                            ).check_return_status()

                self.log(
                    "Image(s) '{0}' to be imported in Cisco Catalyst Center".format(
                        image_names
                    ),
                    "INFO",
                )
            elif import_type == "local":
                image_names = [
                    self.want.get("local_import_details", {}).get("file_path", "")
                ]
                self.log(
                    "Image '{0}' to be imported in Cisco Catalyst Center".format(
                        image_names[0]
                    ),
                    "INFO",
                )
            else:  # CCO import
                image_names = self.want.get("cco_import_details", {}).get(
                    "image_name", ""
                )
                self.log(
                    "Image '{0}' to be imported in Cisco Catalyst Center".format(
                        image_names
                    ),
                    "INFO",
                )

            # Code to check if the image(s) already exist in Catalyst Center
            existing_images, images_to_import = [], []

            if isinstance(image_names, str):
                image_name = image_names.split("/")[-1]
                if self.is_image_exist(image_name):
                    existing_images.append(image_name)
                    self.existing_images.append(image_name)
                    self.log(
                        "Image '{0}' already exists in Cisco Catalyst Center, skipping import.".format(
                            image_name
                        ),
                        "INFO",
                    )
                else:
                    images_to_import.append(image_name)
            else:
                seen = set()
                unique_image_names = []
                duplicate_image_names = set()

                for index, image_name in enumerate(image_names):
                    if image_name not in seen:
                        seen.add(image_name)
                        unique_image_names.append(image_name)
                    else:
                        duplicate_image_names.add(image_name)
                        self.log(
                            "Duplicate image '{0}' detected at index {1}, skipping repeated check.".format(
                                image_name, index
                            ),
                            "WARNING",
                        )

                for image_name in unique_image_names:
                    name = image_name.split("/")[-1]
                    if self.is_image_exist(name):
                        existing_images.append(name)
                        self.existing_images.append(name)
                        self.log(
                            "Image '{0}' already exists in Cisco Catalyst Center, skipping import.".format(
                                name
                            ),
                            "INFO",
                        )
                        continue

                    self.log(
                        "Image '{0}' is ready to be imported into Cisco Catalyst Center.".format(
                            name
                        ),
                        "INFO",
                    )
                    images_to_import.append(name)

            self.log("Image import summary:", "INFO")
            self.log(
                "- Total input images         : {}".format(len(image_names)), "INFO"
            )
            self.log(
                "- Unique images              : {}".format(len(unique_image_names)),
                "INFO",
            )
            self.log(
                "- Duplicate images skipped   : {}".format(len(duplicate_image_names)),
                "INFO",
            )
            self.log(
                "- Images already existing    : {}".format(len(existing_images)), "INFO"
            )
            self.log(
                "- Images ready to import     : {}".format(len(images_to_import)),
                "INFO",
            )

            if existing_images:
                self.log(
                    "Skipping import for existing images: {0}".format(
                        ", ".join(existing_images)
                    ),
                    "INFO",
                )

            import_params = None

            if images_to_import:
                import_key_mapping = {
                    "source_url": "sourceURL",
                    "image_family": "imageFamily",
                    "application_type": "applicationType",
                    "is_third_party": "thirdParty",
                }

                if import_type == "remote":
                    import_image_payload = []
                    temp_payloads = self.want.get("url_import_details").get("payload")

                    for temp_payload in temp_payloads:
                        source_urls = temp_payload.get("source_url", [])

                        if isinstance(source_urls, list):
                            for url in source_urls:
                                if url.split("/")[-1] in images_to_import:
                                    import_payload_dict = {}

                                    if "source_url" in import_key_mapping:
                                        import_payload_dict["sourceURL"] = url

                                    if "image_family" in import_key_mapping:
                                        import_payload_dict["imageFamily"] = (
                                            temp_payload.get("image_family")
                                        )

                                    if "application_type" in import_key_mapping:
                                        import_payload_dict["applicationType"] = (
                                            temp_payload.get("application_type")
                                        )

                                    if "is_third_party" in import_key_mapping:
                                        import_payload_dict["thirdParty"] = (
                                            temp_payload.get("is_third_party")
                                        )

                                    import_image_payload.append(import_payload_dict)

                        elif isinstance(source_urls, str):
                            if source_urls.split("/")[-1] in images_to_import:
                                import_payload_dict = {}

                                if "source_url" in import_key_mapping:
                                    import_payload_dict["sourceURL"] = source_urls

                                if "image_family" in import_key_mapping:
                                    import_payload_dict["imageFamily"] = (
                                        temp_payload.get("image_family")
                                    )

                                if "application_type" in import_key_mapping:
                                    import_payload_dict["applicationType"] = (
                                        temp_payload.get("application_type")
                                    )

                                if "is_third_party" in import_key_mapping:
                                    import_payload_dict["thirdParty"] = (
                                        temp_payload.get("is_third_party")
                                    )

                                import_image_payload.append(import_payload_dict)

                    import_params = dict(
                        payload=import_image_payload,
                        scheduleAt=self.want.get("url_import_details").get(
                            "schedule_at"
                        ),
                        scheduleDesc=self.want.get("url_import_details").get(
                            "schedule_desc"
                        ),
                        scheduleOrigin=self.want.get("url_import_details").get(
                            "schedule_origin"
                        ),
                    )
                    import_function = "import_software_image_via_url"

                elif import_type == "local":
                    file_path = images_to_import[0]
                    import_params = dict(
                        is_third_party=self.want.get("local_import_details").get(
                            "is_third_party"
                        ),
                        third_party_vendor=self.want.get("local_import_details").get(
                            "third_party_vendor"
                        ),
                        third_party_image_family=self.want.get(
                            "local_import_details"
                        ).get("third_party_image_family"),
                        third_party_application_type=self.want.get(
                            "local_import_details"
                        ).get("third_party_application_type"),
                        multipart_fields={
                            "file": (
                                os.path.basename(file_path),
                                open(file_path, "rb"),
                                "application/octet-stream",
                            )
                        },
                        multipart_monitor_callback=None,
                    )
                    import_function = "import_local_software_image"
                else:  # CCO import
                    cco_image_ids = []
                    image_name_id_mapping = []
                    for image_name in images_to_import:
                        cco_image_id = self.get_cco_image_id(image_name)
                        if not cco_image_id:
                            dnac_host = self.params.get("dnac_host")
                            self.msg = "CCO image '{0}' not found in the image repository on Cisco Catalyst Center '{1}'".format(
                                image_name, dnac_host
                            )
                            self.set_operation_result(
                                "failed", False, self.msg, "ERROR"
                            ).check_return_status()
                        cco_image_ids.append(cco_image_id)
                        image_name_id_mapping.append({image_name: cco_image_id})
                    import_function = "download_the_software_image"

                if import_type == "remote" or import_type == "local":
                    try:
                        response = self.dnac._exec(
                            family="software_image_management_swim",
                            function=import_function,
                            op_modifies=True,
                            params=import_params,
                        )
                        self.log(
                            "Received API response from {0}: {1}".format(
                                import_function, str(response)
                            ),
                            "DEBUG",
                        )

                        if (
                            response
                            and isinstance(response, dict)
                            and "response" in response
                        ):
                            task_id = response["response"].get("taskId")
                        else:
                            self.msg = "Invalid API response received in {0}".format(
                                import_function
                            )
                            self.set_operation_result(
                                "failed", False, self.msg, "INFO"
                            ).check_return_status()

                    except Exception as e:
                        self.msg = "An exception occurred in {0} - {1} ".format(
                            import_function, e
                        )
                        self.set_operation_result(
                            "failed", False, self.msg, "INFO"
                        ).check_return_status()

                else:
                    task_ids = []
                    task_id_mapping = []
                    for index, cco_image_id in enumerate(cco_image_ids):
                        import_params = {"id": cco_image_id}
                        try:
                            response = self.dnac._exec(
                                family="software_image_management_swim",
                                function=import_function,
                                op_modifies=True,
                                params=import_params,
                            )
                            self.log(
                                "Received API response from {0}: {1}".format(
                                    import_function, str(response)
                                ),
                                "DEBUG",
                            )

                            if (
                                not response
                                or not isinstance(response, dict)
                                or "response" not in response
                            ):
                                self.log(
                                    "Invalid API response received for {0}".format(
                                        import_function
                                    ),
                                    "WARNING",
                                )
                                continue

                            task_id = response["response"].get("taskId")
                            if not task_id:
                                self.log(
                                    "No taskId found in API response for {0}".format(
                                        import_function
                                    ),
                                    "WARNING",
                                )
                                continue

                            task_ids.append(task_id)
                            task_id_mapping.append(
                                {task_id: image_name_id_mapping[index]}
                            )

                        except Exception as e:
                            self.msg = (
                                "An unknown exception occurred in {0} - {1}".format(
                                    import_function, e
                                )
                            )
                            self.set_operation_result(
                                "failed", False, self.msg, "ERROR"
                            ).check_return_status()

                images_failed_to_import = []

                # Monitor the task progress
                if import_type in ["remote", "local"]:
                    self.log(
                        "Starting SWIM image import process (type: {0}) for task ID: {1}".format(
                            import_type, task_id
                        ),
                        "DEBUG",
                    )
                    task_details = self.get_task_status_from_tasks_by_id(
                        task_id, "import_image(s)", True
                    )
                    self.log(
                        "Checking task status for task ID: {0}".format(task_id), "DEBUG"
                    )

                    if task_details:
                        if images_to_import:
                            images_to_import_str = ", ".join(images_to_import)
                            self.images_to_import.append(images_to_import_str)
                    else:
                        images_to_import_str = ", ".join(images_to_import)
                        images_failed_to_import.append(images_to_import_str)

                    image_name = image_name.split("/")[-1]
                    self.log(
                        "Retrieving imported image ID for: {0}".format(image_name),
                        "DEBUG",
                    )
                    image_id = self.get_image_id(image_name)
                    self.have["imported_image_id"] = image_id
                    self.log("Stored imported image ID: {0}".format(image_id), "INFO")

                else:
                    for task_id in task_ids:
                        self.log("Processing task: {0}".format(task_id))
                        task_details = self.get_task_status_from_tasks_by_id(
                            task_id, "import_image(s)", True
                        )
                        self.log(
                            "Checking task status for task ID: {0}".format(task_id),
                            "DEBUG",
                        )

                        if task_details:
                            for mapping in task_id_mapping:
                                if task_id in mapping:
                                    image_name = list(mapping[task_id].keys())[0]
                                    self.images_to_import.append(image_name)
                        else:
                            for mapping in task_id_mapping:
                                if task_id in mapping:
                                    image_name = list(mapping[task_id].keys())[0]
                                    images_failed_to_import.append(image_name)
                        continue

                    image_name = image_name.split("/")[-1]
                    self.log(
                        "Retrieving imported image ID for: {0}".format(image_name),
                        "DEBUG",
                    )
                    image_id = self.get_image_id(image_name)
                    self.have["imported_image_id"] = image_id
                    self.log("Stored imported image ID: {0}".format(image_id), "INFO")

            imported_images_str = ", ".join(images_to_import)
            imported_images_failed_str = ", ".join(images_failed_to_import)
            skipped_images_str = ", ".join(existing_images)

            messages = []

            if skipped_images_str:
                if imported_images_str:
                    messages.append(
                        "Image(s) {0} were skipped as they already exist in Cisco Catalyst Center.".format(
                            skipped_images_str
                        )
                    )
                    messages.append(
                        "Images {0} have been imported successfully.".format(
                            imported_images_str
                        )
                    )
                else:
                    messages.append(
                        "Image(s) {0} were skipped as they already exist in Cisco Catalyst Center. "
                        "No new images were imported.".format(skipped_images_str)
                    )
            elif imported_images_str:
                if imported_images_failed_str:
                    messages.append(
                        "Image(s) {0} have been imported successfully into Cisco Catalyst Center. "
                        "However, image(s) {1} failed to import.".format(
                            imported_images_str, imported_images_failed_str
                        )
                    )
                else:
                    messages.append(
                        "Image(s) {0} have been imported successfully into Cisco Catalyst Center.".format(
                            imported_images_str
                        )
                    )
            elif imported_images_failed_str:
                messages.append(
                    "Image(s) {0} failed to import into Cisco Catalyst Center.".format(
                        imported_images_failed_str
                    )
                )
            else:
                messages.append("No images were imported.")

            self.msg = " ".join(messages)
            self.log(self.msg, "INFO")
            self.result["msg"] = self.msg
            self.result["response"] = self.msg

            return self

        except Exception as e:
            self.status = "failed"
            self.msg = (
                "Error: Import image details are missing from the playbook or the Import Image API was not "
                "triggered successfully. Please ensure that all necessary details are provided and verify the "
                "status of the Import Image process. Details: {0}".format(str(e))
            )
            self.log(self.msg, "ERROR")
            self.result["response"] = self.msg

        return self

    def get_diff_tagging(self):
        """
        Tag or untag a software image as golden based on provided tagging details.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This function tags or untags a software image as a golden image in Cisco Catalyst Center based on the provided
            tagging details. The tagging action is determined by the value of the 'tagging' attribute
            in the 'tagging_details' dictionary. If 'tagging' is True, the image is tagged as golden, and if 'tagging'
            is False, the golden tag is removed. The function sends the appropriate request to Cisco Catalyst Center and updates the
            task details in the 'result' dictionary. If the operation is successful, 'changed' is set to True.
        """

        tagging_details = self.want.get("tagging_details")
        tag_image_golden = tagging_details.get("tagging")
        image_name = self.get_image_name_from_id(self.have.get("tagging_image_id"))
        device_role = tagging_details.get("device_role", "ALL")
        self.log("Parsed device roles: {0}".format(device_role), "DEBUG")
        device_role_no, already_un_tagged_device_role, already_tagged_device_role = (
            [],
            [],
            [],
        )

        device_roles = [
            "core",
            "distribution",
            "access",
            "border router",
            "unknown",
            "all",
        ]

        for role in device_role.split(","):
            role = role.strip()
            device_role_no.append(role)

            if role.lower() not in device_roles:
                self.status = "failed"
                self.msg = (
                    "Validation Error: The specified device role '{0}' is not recognized. "
                    "Please ensure the role matches one of the known device roles: {1}."
                ).format(role, ", ".join(device_roles))
                self.log(self.msg, "ERROR")
                self.result["response"] = self.msg
                self.check_return_status()

        self.log("Checking golden tag status for each role...", "DEBUG")
        for role in device_role.split(","):
            image_params = {
                "image_id": self.have.get("tagging_image_id"),
                "site_id": self.have.get("site_id"),
                "device_family_identifier": self.have.get("device_family_identifier"),
                "device_role": role.upper(),
            }

            self.log(
                "Parameters for checking tag status for role '{0}': {1}".format(
                    role, image_params
                ),
                "DEBUG",
            )
            response = self.dnac._exec(
                family="software_image_management_swim",
                function="get_golden_tag_status_of_an_image",
                op_modifies=True,
                params=image_params,
            )
            self.log(
                "Received API response from 'get_golden_tag_status_of_an_image': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )

            api_response = response.get("response")
            if api_response:
                image_status = api_response.get("taggedGolden")
                if image_status and tag_image_golden is True:
                    msg = "SWIM Image '{0}' already tagged as Golden image in Cisco Catalyst Center".format(
                        image_name
                    )
                    self.log(msg, "INFO")
                    already_tagged_device_role.append(role)
                elif not image_status and not tag_image_golden:
                    msg = "SWIM Image '{0}' already un-tagged from Golden image in Cisco Catalyst Center".format(
                        image_name
                    )
                    self.log(msg, "INFO")
                    already_un_tagged_device_role.append(role)
            self.log("Verifying if all roles are in the desired tag status...", "DEBUG")

        # Check if all roles are tagged as Golden
        if tag_image_golden:
            if len(already_tagged_device_role) == len(device_role_no):
                self.status = "success"
                self.result["changed"] = False
                self.msg = "SWIM Image '{0}' already tagged as Golden image in Cisco Catalyst Center for the roles - {1}.".format(
                    image_name, device_role
                )
                self.result["msg"] = self.msg
                self.result["response"] = self.msg
                self.log(self.msg, "INFO")
                return self
        else:
            if len(already_un_tagged_device_role) == len(device_role_no):
                self.status = "success"
                self.result["changed"] = False
                self.msg = "SWIM Image '{0}' already un-tagged as Golden image in Cisco Catalyst Center for the roles - {1}.".format(
                    image_name, device_role
                )
                self.result["msg"] = self.msg
                self.result["response"] = self.msg
                self.log(self.msg, "INFO")
                return self

        if tag_image_golden:
            for role in device_role.split(","):
                image_params = dict(
                    imageId=self.have.get("tagging_image_id"),
                    siteId=self.have.get("site_id"),
                    deviceFamilyIdentifier=self.have.get("device_family_identifier"),
                    deviceRole=role.upper(),
                )
                self.log(
                    "Parameters for tagging the image as golden for role {0}: {1}".format(
                        role, str(image_params)
                    ),
                    "INFO",
                )

                response = self.dnac._exec(
                    family="software_image_management_swim",
                    function="tag_as_golden_image",
                    op_modifies=True,
                    params=image_params,
                )
                self.log(
                    "Received API response from 'tag_as_golden_image': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )

        else:
            for role in device_role.split(","):
                image_params = {
                    "image_id": self.have.get("tagging_image_id"),
                    "site_id": self.have.get("site_id"),
                    "device_family_identifier": self.have.get(
                        "device_family_identifier"
                    ),
                    "device_role": role.upper(),
                }
                self.log(
                    "Parameters for un-tagging the image as golden for role {0}: {1}".format(
                        role, str(image_params)
                    ),
                    "INFO",
                )

                response = self.dnac._exec(
                    family="software_image_management_swim",
                    function="remove_golden_tag_for_image",
                    op_modifies=True,
                    params=image_params,
                )
                self.log(
                    "Received API response from 'remove_golden_tag_for_image': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )

        if not response:
            self.status = "failed"
            self.msg = "Did not get the response of API so cannot check the Golden tagging status of image - {0}".format(
                image_name
            )
            self.log(self.msg, "ERROR")
            self.result["response"] = self.msg
            return self

        task_details = {}
        task_id = response.get("response").get("taskId")

        device_family = tagging_details.get("device_image_family_name")
        device_role = tagging_details.get("device_role", "ALL")
        site_name = tagging_details.get("site_name")

        if not site_name:
            site_name = "Global"
        else:
            site_name = tagging_details.get("site_name")

        start_time = time.time()

        while True:
            task_details = self.get_task_details(task_id)
            is_error = task_details.get("isError")
            progress = task_details.get("progress", "")
            failure_reason = task_details.get("failureReason", "")

            if is_error:
                if (
                    not tag_image_golden
                    and "An inheritted tag cannot be un-tagged" in failure_reason
                ):
                    self.msg = failure_reason
                else:
                    action = "Tagging" if tag_image_golden else "Un-Tagging"
                    self.msg = "{0} image {1} golden for site {2} for family {3} for device role {4} failed.".format(
                        action, image_name, site_name, device_family, device_role
                    )
                self.status = "failed"
                self.result["changed"] = False
                self.result["msg"] = self.msg
                self.result["response"] = self.msg
                self.log(self.msg, "ERROR")
                break

            if "successful" in progress:
                action = "Tagging" if tag_image_golden else "Un-Tagging"
                self.msg = "{0} image {1} golden for site {2} for family {3} for device role {4} successful.".format(
                    action, image_name, site_name, device_family, device_role
                )
                self.status = "success"
                self.result["changed"] = True
                self.result["msg"] = self.msg
                self.result["response"] = self.msg
                self.log(self.msg, "INFO")
                break

            elapsed_time = time.time() - start_time
            if elapsed_time >= self.max_timeout:
                self.msg = (
                    "Max timeout of {0} sec has reached for the task id '{1}'. ".format(
                        self.max_timeout, task_id
                    )
                    + "Exiting the loop due to unexpected API status."
                )
                self.log(self.msg, "WARNING")
                self.status = "failed"
                break

            poll_interval = self.params.get("dnac_task_poll_interval")
            self.log(
                "Waiting for the next poll interval of {0} seconds before checking task status again.".format(
                    poll_interval
                ),
                "DEBUG",
            )
            time.sleep(poll_interval)

        return self

    def get_device_ip_from_id(self, device_id):
        """
        Retrieve the management IP address of a device from Cisco Catalyst Center using its ID.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - device_id (str): The unique identifier of the device in Cisco Catalyst Center.
        Returns:
            str: The management IP address of the specified device.
        Raises:
            Exception: If there is an error while retrieving the response from Cisco Catalyst Center.
        Description:
            This method queries Cisco Catalyst Center for the device details based on its unique identifier (ID).
            It uses the 'get_device_list' function in the 'devices' family, extracts the management IP address
            from the response, and returns it. If any error occurs during the process, an exception is raised
            with an appropriate error message logged.
        """

        try:
            response = self.dnac._exec(
                family="devices",
                function="get_device_list",
                op_modifies=True,
                params={"id": device_id},
            )
            self.log(
                "Received API response from 'get_device_list': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )
            response = response.get("response")[0]
            device_ip = response.get("managementIpAddress")

            return device_ip
        except Exception as e:
            error_message = "Error occurred while getting the response of device from Cisco Catalyst Center: {0}".format(
                str(e)
            )
            self.log(error_message, "ERROR")
            raise Exception(error_message)

    def check_swim_task_status(self, swim_task_dict, swim_task_name):
        """
        Check the status of the SWIM (Software Image Management) task for each device.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            swim_task_dict (dict): A dictionary containing the mapping of device IP address to the respective task ID.
            swim_task_name (str): The name of the SWIM task being checked which is either Distribution or Activation.
        Returns:
            tuple: A tuple containing two elements:
                - device_ips_list (list): A list of device IP addresses for which the SWIM task failed.
                - device_count (int): The count of devices for which the SWIM task was successful.
        Description:
            This function iterates through the distribution_task_dict, which contains the mapping of
            device IP address to their respective task ID. It checks the status of the SWIM task for each device by
            repeatedly querying for task details until the task is either completed successfully or fails. If the task
            is successful, the device count is incremented. If the task fails, an error message is logged, and the device
            IP is appended to the device_ips_list and return a tuple containing the device_ips_list and device_count.
        """

        device_ips_list = []
        device_count = 0

        for device_ip, task_id in swim_task_dict.items():
            start_time = time.time()

            while True:
                end_time = time.time()
                max_timeout = self.params.get("dnac_api_task_timeout")

                if (end_time - start_time) >= max_timeout:
                    self.log(
                        """Max timeout of {0} has reached for the task id '{1}' for the device '{2}' and unexpected
                                 task status so moving out to next task id""".format(
                            max_timeout, task_id, device_ip
                        ),
                        "WARNING",
                    )
                    device_ips_list.append(device_ip)
                    break

                task_details = self.get_task_details(task_id)

                if not task_details.get("isError") and (
                    "completed successfully" in task_details.get("progress")
                ):
                    self.result["changed"] = True
                    self.status = "success"
                    self.log(
                        "Image {0} successfully for the device '{1}".format(
                            swim_task_name, device_ip
                        ),
                        "INFO",
                    )
                    device_count += 1
                    break

                if task_details.get("isError"):
                    error_msg = "Image {0} gets failed for the device '{1}'".format(
                        swim_task_name, device_ip
                    )
                    self.log(error_msg, "ERROR")
                    self.result["response"] = task_details
                    device_ips_list.append(device_ip)
                    break
                time.sleep(self.params.get("dnac_task_poll_interval"))

        return device_ips_list, device_count

    def get_diff_distribution(self):
        """
        Get image distribution parameters from the playbook and trigger image distribution.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This function retrieves image distribution parameters from the playbook's 'distribution_details' and triggers
            the distribution of the specified software image to the specified device. It monitors the distribution task's
            progress and updates the 'result' dictionary. If the operation is successful, 'changed' is set to True.
        """

        self.log("Retrieving distribution details from the playbook.", "DEBUG")

        distribution_details = self.want.get("distribution_details")
        if not distribution_details:
            self.log(
                "No distribution details found. Skipping image distribution.", "ERROR"
            )
            return self

        site_name = distribution_details.get("site_name")
        device_family = distribution_details.get("device_family_name")
        device_role = distribution_details.get("device_role", "ALL")
        device_series_name = distribution_details.get("device_series_name")

        self.log(
            "Fetching device UUIDs for site '{0}', family '{1}', role '{2}', and series '{3}'.".format(
                site_name, device_family, device_role, device_series_name
            ),
            "DEBUG",
        )

        device_uuid_list = self.get_device_uuids(
            site_name, device_family, device_role, device_series_name
        )
        image_id = self.have.get("distribution_image_id")
        distribution_device_id = self.have.get("distribution_device_id")
        device_ip = self.get_device_ip_from_id(distribution_device_id)
        image_name = self.want.get("distribution_details").get("image_name")
        sub_package_images = self.want.get("distribution_details").get(
            "sub_package_images"
        )

        self.log(
            "Fetched device details: "
            "UUID list: {0}, "
            "Image ID: {1}, "
            "Distribution Device ID: {2}, "
            "Device IP: {3}, "
            "Image Name: {4}, "
            "Sub-package Images: {5}".format(
                device_uuid_list if device_uuid_list else "Not Available",
                image_id if image_id else "Not Available",
                distribution_device_id if distribution_device_id else "Not Available",
                device_ip if device_ip else "Not Available",
                image_name if image_name else "Not Available",
                sub_package_images if sub_package_images else "Not Available",
            ),
            "DEBUG",
        )

        self.complete_successful_distribution = False
        self.partial_successful_distribution = False
        self.single_device_distribution = False

        all_images_for_distribution = []
        all_images_for_distribution.append(image_name)

        if sub_package_images:
            all_images_for_distribution.extend([str(img) for img in sub_package_images])
            self.log(
                "Identified images for distribution: {0}".format(
                    all_images_for_distribution
                ),
                "DEBUG",
            )

        image_ids = {
            image: self.get_image_id(image) for image in all_images_for_distribution
        }
        self.log("Resolved image IDs: {0}".format(image_ids), "DEBUG")

        final_msg = ""
        success_msg_parts = []
        failed_msg_parts = []

        if distribution_device_id:
            self.log(
                "Starting image distribution for device IP {0} (ID: {1}) with software version {2}.".format(
                    device_ip, distribution_device_id, image_name
                ),
                "INFO",
            )

            elg_device_ip, device_id = self.check_device_compliance(
                distribution_device_id, image_name
            )
            self.log(
                "Device compliance check completed. IP: {0}, Device ID: {1}".format(
                    elg_device_ip, device_id
                ),
                "DEBUG",
            )

            if not elg_device_ip:
                self.msg = (
                    "The image '{0}' is already distributed on device {1}".format(
                        image_name, device_ip
                    )
                )
                self.set_operation_result("success", False, self.msg, "INFO")
                return self

            success_distribution_list = []
            failed_distribution_list = []

            for image_name, image_id in image_ids.items():
                self.log(
                    "Initiating image distribution for '{0}' (ID: {1}) to device {2}".format(
                        image_name, image_id, elg_device_ip
                    ),
                    "INFO",
                )
                distribution_params = {
                    "payload": [{"deviceUuid": device_id, "imageUuid": image_id}]
                }
                self.log(
                    "Generated distribution parameters: {0}".format(
                        distribution_params
                    ),
                    "DEBUG",
                )

                response = self.dnac._exec(
                    family="software_image_management_swim",
                    function="trigger_software_image_distribution",
                    op_modifies=True,
                    params=distribution_params,
                )
                self.log(
                    "Received API response from 'trigger_software_image_distribution': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )

                if (
                    not response
                    or "response" not in response
                    or "taskId" not in response["response"]
                ):
                    failed_msg = "Failed to initiate image distribution for '{0}' (ID: {1}) to the device with IP {2}.".format(
                        image_name, image_id, elg_device_ip
                    )
                    failed_msg_parts.append(failed_msg)
                    failed_distribution_list.append(image_name)
                    self.log(failed_msg, "ERROR")
                    continue

                task_id = response["response"]["taskId"]
                self.log(
                    "Tracking distribution task with Task ID: {0}".format(task_id),
                    "INFO",
                )

                while True:
                    task_details = self.get_task_details(task_id)
                    self.log("Task details received: {0}".format(task_details), "DEBUG")

                    if not task_details.get(
                        "isError"
                    ) and "completed successfully" in task_details.get("progress"):
                        success_msg = (
                            "'{0}' (ID: {1}) successfully distributed.".format(
                                image_name, image_id
                            )
                        )
                        success_msg_parts.append(success_msg)
                        success_distribution_list.append(image_name)
                        self.log(success_msg, "INFO")
                        break

                    if task_details.get("isError"):
                        failed_msg = "Image '{0}' (ID: {1}) distribution failed for device {2}.".format(
                            image_name, image_id, elg_device_ip
                        )
                        failed_msg_parts.append(failed_msg)
                        failed_distribution_list.append(image_name)
                        self.log(failed_msg, "ERROR")
                        break

            if success_msg_parts:
                final_msg += "Successfully distributed: " + "; ".join(success_msg_parts)
            if failed_msg_parts:
                if final_msg:
                    final_msg += ". "
                final_msg += (
                    "Failed to distribute: " + "; ".join(failed_msg_parts) + "."
                )

            if not success_distribution_list and failed_distribution_list:
                self.msg = final_msg
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()
            elif success_distribution_list and failed_distribution_list:
                self.msg = final_msg
                self.set_operation_result("success", True, self.msg, "INFO")
                self.partial_successful_distribution = True
            else:
                self.msg = final_msg
                self.set_operation_result("success", True, self.msg, "INFO")
                self.complete_successful_distribution = True

            return self
        self.log("Starting SWIM image distribution process", "INFO")
        if len(device_uuid_list) == 0:
            self.status = "success"
            self.msg = "The SWIM image distribution task could not proceed because no eligible devices were found"
            self.result["msg"] = self.msg
            self.result["response"] = self.msg
            self.log(self.msg, "WARNING")
            return self

        self.log(
            "Device UUIDs involved in Image Distribution: {0}".format(
                str(device_uuid_list)
            ),
            "INFO",
        )

        distribution_task_dict = {}
        success_distribution_list = []
        failed_distribution_list = []
        already_distributed_devices = []
        elg_device_list = []
        device_ip_for_not_elg_list = []

        for device_uuid in device_uuid_list:
            device_ip = self.get_device_ip_from_id(device_uuid)
            self.log("Processing device: {0}".format(device_ip), "DEBUG")
            distributed = False

            for img_name, img_id in image_ids.items():
                self.log(
                    "Checking compliance for image '{0}' on device {1}".format(
                        img_name, device_ip
                    ),
                    "DEBUG",
                )
                elg_device_ip, device_id = self.check_device_compliance(
                    device_uuid, img_name
                )

                if not elg_device_ip:
                    device_ip_for_not_elg = self.get_device_ip_from_id(device_uuid)
                    device_ip_for_not_elg_list.append(device_ip_for_not_elg)
                    self.log(
                        "Device {0} is not eligible for image '{1}'".format(
                            device_ip, img_name
                        ),
                        "WARNING",
                    )
                    continue

                self.log(
                    "Device {0} is eligible for distribution of image {1}".format(
                        elg_device_ip, image_name
                    ),
                    "INFO",
                )
                elg_device_list.append(elg_device_ip)

                self.log(
                    "Starting distribution of '{0}' to device {1}".format(
                        img_name, device_ip
                    ),
                    "INFO",
                )
                distribution_params = dict(
                    payload=[dict(deviceUuid=device_id, imageUuid=img_id)]
                )
                self.log(
                    "Distribution Params: {0}".format(str(distribution_params)), "INFO"
                )

                response = self.dnac._exec(
                    family="software_image_management_swim",
                    function="trigger_software_image_distribution",
                    op_modifies=True,
                    params=distribution_params,
                )
                self.log(
                    "Received API response from 'trigger_software_image_distribution': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )

                if response:
                    task_id = response.get("response", {}).get("taskId")
                    distribution_task_dict[(device_ip, img_name)] = task_id
                    distributed = True

            if not distributed:
                already_distributed_devices.append(device_ip)

        # Check task status sequentially
        self.log("Checking task statuses for distributed images", "INFO")

        for (device_ip, img_name), task_id in distribution_task_dict.items():
            task_name = "Distribution to {0}".format(device_ip)
            success_msg = "Successfully distributed image {0} to device {1}".format(
                img_name, device_ip
            )

            status_check = self.get_task_status_from_tasks_by_id(
                task_id, task_name, success_msg
            )

            if status_check.status == "success":
                success_distribution_list.append((device_ip, img_name))
            else:
                failed_distribution_list.append((device_ip, img_name))

        success_image_map = {}
        failed_image_map = {}

        for device_ip, img_name in success_distribution_list:
            if img_name not in success_image_map:
                success_image_map[img_name] = []
            success_image_map[img_name].append(device_ip)

        for device_ip, img_name in failed_distribution_list:
            if img_name not in failed_image_map:
                failed_image_map[img_name] = []
            failed_image_map[img_name].append(device_ip)

        success_msg_parts = [
            "{} to {}".format(img, ", ".join(devices))
            for img, devices in success_image_map.items()
        ]

        failed_msg_parts = [
            "{} to {}".format(img, ", ".join(devices))
            for img, devices in failed_image_map.items()
        ]

        final_msg = ""
        if success_msg_parts:
            final_msg += "Successfully distributed: " + "; ".join(success_msg_parts)
        if failed_msg_parts:
            if final_msg:
                final_msg += ". "
            final_msg += "Failed to distribute: " + "; ".join(failed_msg_parts) + "."

        self.log("Final Distribution Summary: {0}".format(final_msg), "INFO")

        if not success_distribution_list and failed_distribution_list:
            self.msg = final_msg
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()
        elif success_distribution_list and failed_distribution_list:
            self.msg = final_msg
            self.set_operation_result("success", True, self.msg, "INFO")
            self.partial_successful_distribution = True
        elif device_ip_for_not_elg_list:
            self.msg = "Devices not eligible for image distribution: " + ", ".join(device_ip_for_not_elg_list)
            self.set_operation_result("success", False, self.msg, "WARNING")
        else:
            self.msg = final_msg
            self.set_operation_result("success", True, self.msg, "INFO")
            self.complete_successful_distribution = True

        return self

    def check_device_compliance(self, device_uuid, image_name):
        """
        Check the compliance status of a device's image.
        Parameters:
            self (object): An instance of the class interacting with Cisco DNA Center.
            device_uuid (str): The unique identifier of the device to check compliance for.
            image_name (str): The expected image name for compliance verification.
        Returns:
            tuple: A tuple containing:
                - device_ip (str or None): The IP address of the non-compliant device if it is not compliant, otherwise None.
                - device_id (str or None): The device UUID if it is non-compliant, otherwise None.
        Description:
            This function queries Cisco DNA Center for the compliance status of a given device's software image.
            If the device is found to be "NON_COMPLIANT," it retrieves the device's IP address and returns it along with the device UUID.
            If the device is compliant, a debug log is generated, and None is returned.
            In case of an exception, an error is logged, and the function updates the result status accordingly.
        """

        try:
            response = self.dnac._exec(
                family="compliance",
                function="compliance_details_of_device",
                params={"device_uuid": device_uuid, "category": "IMAGE"},
            )

            self.log(
                "Received API response from 'compliance_details_of_device': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )
            response = response.get("response")[0]

            if response.get("status") == "NON_COMPLIANT":
                device_ip = self.get_device_ip_from_id(device_uuid)
                device_id = device_uuid
                self.log(
                    "Device {0} (IP: {1}) is NON_COMPLIANT.".format(
                        device_id, device_ip
                    ),
                    "WARNING",
                )
                return device_ip, device_id

            self.log(
                "The device with device id - {0} already distributed/activated with the image - {1} ".format(
                    device_uuid, image_name
                )
            )
            return None, None

        except Exception as e:
            self.msg = "Error in compliance_details_of_device due to {0}".format(e)
            self.set_operation_result(
                "failed", False, self.msg, "INFO"
            ).check_return_status()

    def get_diff_activation(self):
        """
        Get image activation parameters from the playbook and trigger image activation.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This function retrieves image activation parameters from the playbook's 'activation_details' and triggers the
            activation of the specified software image on the specified device. It monitors the activation task's progress and
            updates the 'result' dictionary. If the operation is successful, 'changed' is set to True.
        """
        self.log("Retrieving distribution details from the playbook.", "DEBUG")

        activation_details = self.want.get("activation_details")
        if not activation_details:
            self.log(
                "No distribution details found. Skipping image activation.", "ERROR"
            )
            return self

        site_name = activation_details.get("site_name")
        device_family = activation_details.get("device_family_name")
        device_role = activation_details.get("device_role", "ALL")
        device_series_name = activation_details.get("device_series_name")

        self.log(
            "Fetching device UUIDs for site '{0}', family '{1}', role '{2}', and series '{3}'.".format(
                site_name, device_family, device_role, device_series_name
            ),
            "DEBUG",
        )

        device_uuid_list = self.get_device_uuids(
            site_name, device_family, device_role, device_series_name
        )
        image_id = self.have.get("activation_image_id")
        activation_device_id = self.have.get("activation_device_id")
        device_ip = self.get_device_ip_from_id(activation_device_id)
        image_name = self.want.get("activation_details").get("image_name")
        sub_package_images = self.want.get("activation_details").get(
            "sub_package_images"
        )

        self.log(
            "Fetched device details: "
            "UUID list: {0}, "
            "Image ID: {1}, "
            "Distribution Device ID: {2}, "
            "Device IP: {3}, "
            "Image Name: {4}, "
            "Sub-package Images: {5}".format(
                device_uuid_list if device_uuid_list else "Not Available",
                image_id if image_id else "Not Available",
                activation_device_id if activation_device_id else "Not Available",
                device_ip if device_ip else "Not Available",
                image_name if image_name else "Not Available",
                sub_package_images if sub_package_images else "Not Available",
            ),
            "DEBUG",
        )

        self.complete_successful_activation = False
        self.partial_successful_activation = False
        self.single_device_activation = False

        self.log("Fetching image activation parameters from playbook.", "INFO")

        all_images_for_activation = []
        all_images_for_activation.append(image_name)

        if sub_package_images:
            all_images_for_activation.extend([str(img) for img in sub_package_images])

        image_ids = {
            image: self.get_image_id(image) for image in all_images_for_activation
        }
        self.log(
            "Images identified for activation: {0}".format(", ".join(image_ids.keys())),
            "INFO",
        )

        if activation_device_id:
            success_msg_parts = []
            failed_msg_parts = []

            self.log(
                "Starting image activation for device IP {0} with ID {1}, targeting software version {2}.".format(
                    device_ip, activation_device_id, image_name
                ),
                "INFO",
            )

            elg_device_ip, device_id = self.check_device_compliance(
                self.have.get("activation_device_id"), image_name
            )

            if not elg_device_ip:
                self.msg = "The image '{0}' has already been activated on the device '{1}'.".format(
                    image_name, device_ip
                )
                self.set_operation_result("success", False, self.msg, "ERROR")
                return self

            self.log(
                "Device {0} is eligible for activation of image '{1}'.".format(
                    device_ip, image_name
                ),
                "INFO",
            )

            success_activation_list = []
            failed_activation_list = []

            for image_name, image_id in image_ids.items():
                payload = [
                    {
                        "activateLowerImageVersion": activation_details.get(
                            "activate_lower_image_version"
                        ),
                        "deviceUpgradeMode": activation_details.get(
                            "device_upgrade_mode"
                        ),
                        "distributeIfNeeded": activation_details.get(
                            "distribute_if_needed"
                        ),
                        "deviceUuid": self.have.get("activation_device_id"),
                        "imageUuidList": [image_id],
                    }
                ]

                activation_params = {
                    "schedule_validate": activation_details.get("schedule_validate"),
                    "payload": payload,
                }

                self.log(
                    "Activation Params: {0}".format(str(activation_params)), "INFO"
                )

                response = self.dnac._exec(
                    family="software_image_management_swim",
                    function="trigger_software_image_activation",
                    op_modifies=True,
                    params=activation_params,
                )
                self.log(
                    "Received API response from 'trigger_software_image_activation': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )

                if (
                    not response
                    or "response" not in response
                    or "taskId" not in response["response"]
                ):
                    failed_msg = "Failed to initiate activation for image '{0}' (ID: {1}) on device with IP {2}.".format(
                        image_name, image_id, elg_device_ip
                    )
                    failed_msg_parts.append(failed_msg)
                    failed_activation_list.append(image_name)
                    self.log(failed_msg, "ERROR")
                    continue

                task_id = response["response"]["taskId"]
                self.log(
                    "Tracking activation task with Task ID: {0}".format(task_id), "INFO"
                )

                while True:
                    task_details = self.get_task_details(task_id)

                    if not task_details.get(
                        "isError"
                    ) and "completed successfully" in task_details.get("progress"):
                        success_msg = "'{0}' (ID: {1})".format(image_name, image_id)
                        success_msg_parts.append(success_msg)
                        success_activation_list.append(image_name)
                        self.log(
                            "Image '{0}' (ID: {1}) activation success.".format(
                                image_name, image_id
                            ),
                            "INFO",
                        )
                        break

                    if task_details.get("isError"):
                        failed_msg = "Activation of image '{0}' (ID: {1}) to the device with IP {2} has failed. Error: {3}".format(
                            image_name,
                            image_id,
                            elg_device_ip,
                            task_details.get("progress", "Unknown error"),
                        )
                        failed_msg_parts.append(failed_msg)
                        failed_activation_list.append(image_name)
                        self.log(failed_msg, "ERROR")
                        break

            final_msg = ""
            if success_msg_parts:
                final_msg += "Successfully activated: " + "; ".join(success_msg_parts)
            if failed_msg_parts:
                if final_msg:
                    final_msg += ". "
                final_msg += "Failed to activate: " + "; ".join(failed_msg_parts) + "."

            self.log("Final activation status: {0}".format(final_msg), "INFO")

            if not success_activation_list and failed_activation_list:
                self.msg = final_msg
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()
            elif success_activation_list and failed_activation_list:
                self.msg = final_msg
                self.set_operation_result("success", True, self.msg, "INFO")
                self.partial_successful_activation = True
            else:
                self.msg = final_msg
                self.set_operation_result("success", True, self.msg, "INFO")
                self.complete_successful_activation = True

            return self

        if len(device_uuid_list) == 0:
            self.status = "success"
            self.msg = "The SWIM image activation task could not proceed because no eligible devices were found."
            self.result["msg"] = self.msg
            self.result["response"] = self.msg
            self.log(self.msg, "WARNING")
            return self

        self.log(
            "Device UUIDs involved in Image Activation: {0}".format(
                str(device_uuid_list)
            ),
            "INFO",
        )

        activation_task_dict = {}
        success_activation_list = []
        failed_activation_list = []
        already_activated_devices = []
        elg_device_list = []
        device_ip_for_not_elg_list = []

        for device_uuid in device_uuid_list:
            device_ip = self.get_device_ip_from_id(device_uuid)
            activated = False
            self.log("Checking compliance for device {0}".format(device_ip), "INFO")

            for image_name, image_id in image_ids.items():

                elg_device_ip, device_id = self.check_device_compliance(
                    device_uuid, image_name
                )

                if not elg_device_ip:
                    device_ip_for_not_elg = self.get_device_ip_from_id(device_uuid)
                    device_ip_for_not_elg_list.append(device_ip_for_not_elg)
                    self.log(
                        "Device {0} is not eligible for activation of image '{1}'".format(
                            device_ip, image_name
                        ),
                        "WARNING",
                    )
                    continue

                self.log(
                    "Device {0} is eligible for activation of image {1}".format(
                        elg_device_ip, image_name
                    ),
                    "INFO",
                )
                elg_device_list.append(elg_device_ip)

                self.log(
                    "Starting activation of image '{0}' on device {1}".format(
                        image_name, device_ip
                    ),
                    "INFO",
                )

                payload = [
                    dict(
                        activateLowerImageVersion=activation_details.get(
                            "activate_lower_image_version"
                        ),
                        deviceUpgradeMode=activation_details.get("device_upgrade_mode"),
                        distributeIfNeeded=activation_details.get(
                            "distribute_if_needed"
                        ),
                        deviceUuid=device_id,
                        imageUuidList=[image_id],
                    )
                ]

                activation_params = dict(
                    schedule_validate=activation_details.get("schedule_validate"),
                    payload=payload,
                )
                self.log(
                    "Activation Params: {0}".format(str(activation_params)), "INFO"
                )

                response = self.dnac._exec(
                    family="software_image_management_swim",
                    function="trigger_software_image_activation",
                    op_modifies=True,
                    params=activation_params,
                )
                self.log(
                    "Received API from from 'trigger_software_image_activation': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )

                if response:
                    task_id = response.get("response", {}).get("taskId")
                    activation_task_dict[(device_ip, image_name)] = task_id
                    self.log(
                        "Task ID {0} assigned for image {1} activation on device {2}".format(
                            task_id, image_name, device_ip
                        ),
                        "INFO",
                    )
                    activated = True

            if not activated:
                already_activated_devices.append(device_ip)
                self.log(
                    "Image already activated on device {0}".format(device_ip), "INFO"
                )

        # Check activation status sequentially
        for (device_ip, img_name), task_id in activation_task_dict.items():
            task_name = "Activation for {0}".format(device_ip)
            self.log(
                "Checking activation status for device {0}, image {1}, Task ID {2}".format(
                    device_ip, img_name, task_id
                ),
                "INFO",
            )
            success_msg = "Successfully activated image {0} on device {1}".format(
                img_name, device_ip
            )

            status_check = self.get_task_status_from_tasks_by_id(
                task_id, task_name, success_msg
            )

            if status_check.status == "success":
                success_activation_list.append((device_ip, img_name))
                self.log(
                    "Activation successful for device {0}, image {1}".format(
                        device_ip, img_name
                    ),
                    "INFO",
                )
            else:
                failed_activation_list.append((device_ip, img_name))
                self.log(
                    "Activation failed for device {0}, image {1}".format(
                        device_ip, img_name
                    ),
                    "ERROR",
                )

        success_image_map = {}
        failed_image_map = {}

        for device_ip, img_name in success_activation_list:
            success_image_map.setdefault(img_name, []).append(device_ip)

        for device_ip, img_name in failed_activation_list:
            failed_image_map.setdefault(img_name, []).append(device_ip)

        # Building message parts
        success_msg_parts = [
            "{} to {}".format(img, ", ".join(devices))
            for img, devices in success_image_map.items()
        ]

        failed_msg_parts = [
            "{} to {}".format(img, ", ".join(devices))
            for img, devices in failed_image_map.items()
        ]

        # Final single-line message formation
        final_msg = ""
        if success_msg_parts:
            final_msg += "Successfully activated: " + "; ".join(success_msg_parts)
        if failed_msg_parts:
            if final_msg:
                final_msg += ". "
            final_msg += "Failed to activate: " + "; ".join(failed_msg_parts) + "."

        if not success_activation_list and failed_activation_list:
            self.msg = final_msg
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()
        elif success_activation_list and failed_activation_list:
            self.msg = final_msg
            self.set_operation_result("success", True, self.msg, "INFO")
            self.partial_successful_activation = True
        else:
            self.msg = final_msg
            self.set_operation_result("success", True, self.msg, "INFO")
            self.complete_successful_activation = True

        return self

    def get_diff_merged(self, config):
        """
        Get tagging details and then trigger distribution followed by activation if specified in the playbook.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing tagging, distribution, and activation details.
        Returns:
            self: The current instance of the class with updated 'result' and 'have' attributes.
        Description:
            This function checks the provided playbook configuration for tagging, distribution, and activation details. It
            then triggers these operations in sequence if the corresponding details are found in the configuration.The
            function monitors the progress of each task and updates the 'result' dictionary accordingly. If any of the
            operations are successful, 'changed' is set to True.
        """

        if config.get("tagging_details"):
            self.get_diff_tagging().check_return_status()

        if config.get("image_distribution_details"):
            self.get_diff_distribution().check_return_status()

        if config.get("image_activation_details"):
            self.get_diff_activation().check_return_status()

        return self

    def verify_diff_imported(self, import_type):
        """
        Verify the successful import of a software image into Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            import_type (str): The type of import, either 'remote' or 'local'.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method verifies the successful import of a software image into Cisco Catalyst Center.
            It checks whether the image exists in Catalyst Center based on the provided import type.
            If the image exists, the status is set to 'success', and a success message is logged.
            If the image does not exist, a warning message is logged indicating a potential import failure.
        """
        names_of_images = []
        existence_status = {}

        if import_type == "remote":
            image_names = [
                url
                for item in self.want.get("url_import_details", {}).get("payload", [])
                for url in (
                    item.get("source_url")
                    if isinstance(item.get("source_url"), list)
                    else [item.get("source_url")]
                )
            ]
        elif import_type == "local":
            image_names = self.want.get("local_import_details", {}).get("file_path")
        else:
            image_names = self.want.get("cco_import_details", {}).get("image_name")

        if import_type == "remote" or import_type == "cco":
            if isinstance(image_names, str):
                name = image_names.split("/")[-1]
                image_exist = self.is_image_exist(name)
                names_of_images.append(name)
            else:
                for image_name in image_names:
                    name = image_name.split("/")[-1]
                    image_exist = self.is_image_exist(name)
                    existence_status[name] = image_exist
                    names_of_images.append(name)

                    if image_exist:
                        self.log(
                            "Image '{0}' exists in the Cisco Catalyst Center.".format(
                                name
                            ),
                            "INFO",
                        )
                    else:
                        self.log(
                            "Image '{0}' does NOT exist in the Cisco Catalyst Center.".format(
                                name
                            ),
                            "WARNING",
                        )

        else:
            name = image_names.split("/")[-1]
            image_exist = self.is_image_exist(name)
            existence_status[name] = image_exist
            names_of_images.append(name)
            if image_exist:
                self.log(
                    "Image '{0}' exists in the Cisco Catalyst Center.".format(name),
                    "INFO",
                )
            else:
                self.log(
                    "Image '{0}' does NOT exist in the Cisco Catalyst Center.".format(
                        name
                    ),
                    "WARNING",
                )

        imported_images = ", ".join(names_of_images)

        if all(existence_status.values()):
            self.status = "success"
            self.msg = "The requested image '{0}' has been imported into the Cisco Catalyst Center and its presence has been verified.".format(
                imported_images
            )
            self.log(self.msg, "INFO")
        else:
            self.log(
                "The playbook input for SWIM image '{0}' does not align with the Cisco Catalyst Center,"
                "indicating that the image may not have been imported successfully.".format(
                    name
                ),
                "INFO",
            )

        return self

    def verify_diff_tagged(self):
        """
        Verify the Golden tagging status of a software image in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method verifies the tagging status of a software image in Cisco Catalyst Center.
            It retrieves tagging details from the input, including the desired tagging status and image ID.
            Using the provided image ID, it obtains image parameters required for checking the image status.
            The method then queries Catalyst Center to get the golden tag status of the image.
            If the image status matches the desired tagging status, a success message is logged.
            If there is a mismatch between the playbook input and the Catalyst Center, a warning message is logged.
        """

        tagging_details = self.want.get("tagging_details")
        tag_image_golden = tagging_details.get("tagging")
        image_id = self.have.get("tagging_image_id")
        image_name = self.get_image_name_from_id(image_id)
        device_role = tagging_details.get("device_role", "ALL")

        for role in device_role.split(","):
            image_params = dict(
                image_id=self.have.get("tagging_image_id"),
                site_id=self.have.get("site_id"),
                device_family_identifier=self.have.get("device_family_identifier"),
                device_role=role.upper(),
            )
            self.log(
                "Parameters for checking the status of image: {0}".format(
                    str(image_params)
                ),
                "INFO",
            )

            response = self.dnac._exec(
                family="software_image_management_swim",
                function="get_golden_tag_status_of_an_image",
                op_modifies=True,
                params=image_params,
            )
            self.log(
                "Received API response from 'get_golden_tag_status_of_an_image': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )

            response = response.get("response")
            if response:
                image_status = response["taggedGolden"]
                self.log(
                    "Current golden tag status for image '{0}': {1}".format(
                        image_name, image_status
                    ),
                    "DEBUG",
                )
                if image_status == tag_image_golden:
                    if tag_image_golden:
                        self.msg = """The requested image '{0}' has been tagged as golden in the Cisco Catalyst Center and
                                its status has been successfully verified.""".format(
                            image_name
                        )
                        self.log(self.msg, "INFO")
                    else:
                        self.msg = """The requested image '{0}' has been un-tagged as golden in the Cisco Catalyst Center and
                                image status has been verified.""".format(
                            image_name
                        )
                        self.log(self.msg, "INFO")
            else:
                self.log(
                    """Mismatch between the playbook input for tagging/un-tagging image as golden and the Cisco Catalyst Center indicates that
                            the tagging/un-tagging task was not executed successfully.""",
                    "INFO",
                )

        return self

    def verify_diff_distributed(self):
        """
        Verify the distribution status of a software image in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method verifies the distribution status of a software image in Cisco Catalyst Center.
            It retrieves the image ID and name from the input and if distribution device ID is provided, it checks the distribution status for that
            list of specific device and logs the info message based on distribution status.
        """

        image_id = self.have.get("distribution_image_id")
        image_name = self.get_image_name_from_id(image_id)

        if self.have.get("distribution_device_id"):
            if self.single_device_distribution:
                self.msg = """The requested image '{0}', associated with the device ID '{1}', has been successfully distributed in the Cisco Catalyst Center
                     and its status has been verified.""".format(
                    image_name, self.have.get("distribution_device_id")
                )
                self.log(self.msg, "INFO")
            else:
                self.log(
                    """Mismatch between the playbook input for distributing the image to the device with ID '{0}' and the actual state in the
                         Cisco Catalyst Center suggests that the distribution task might not have been executed
                         successfully.""".format(
                        self.have.get("distribution_device_id")
                    ),
                    "INFO",
                )
        elif self.complete_successful_distribution:
            self.msg = """The requested image '{0}', with ID '{1}', has been successfully distributed to all devices within the specified
                     site in the Cisco Catalyst Center.""".format(
                image_name, image_id
            )
            self.log(self.msg, "INFO")
        elif self.partial_successful_distribution:
            self.msg = """T"The requested image '{0}', with ID '{1}', has been partially distributed across some devices in the Cisco Catalyst
                     Center.""".format(
                image_name, image_id
            )
            self.log(self.msg, "INFO")
        else:
            self.msg = """The requested image '{0}', with ID '{1}', failed to be distributed across devices in the Cisco Catalyst
                     Center.""".format(
                image_name, image_id
            )
            self.log(self.msg, "INFO")

        return self

    def verify_diff_activated(self):
        """
        Verify the activation status of a software image in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method verifies the activation status of a software image in Cisco Catalyst Center and retrieves the image ID and name from
            the input. If activation device ID is provided, it checks the activation status for that specific device. Based on activation status
            a corresponding message is logged.
        """

        image_id = self.have.get("activation_image_id")
        image_name = self.get_image_name_from_id(image_id)

        if self.have.get("activation_device_id"):
            if self.single_device_activation:
                self.msg = """The requested image '{0}', associated with the device ID '{1}', has been successfully activated in the Cisco Catalyst
                         Center and its status has been verified.""".format(
                    image_name, self.have.get("activation_device_id")
                )
                self.log(self.msg, "INFO")
            else:
                self.log(
                    """Mismatch between the playbook's input for activating the image '{0}' on the device with ID '{1}' and the actual state in
                         the Cisco Catalyst Center suggests that the activation task might not have been executed
                         successfully.""".format(
                        image_name, self.have.get("activation_device_id")
                    ),
                    "INFO",
                )
        elif self.complete_successful_activation:
            self.msg = """The requested image '{0}', with ID '{1}', has been successfully activated on all devices within the specified site in the
                     Cisco Catalyst Center.""".format(
                image_name, image_id
            )
            self.log(self.msg, "INFO")
        elif self.partial_successful_activation:
            self.msg = """"The requested image '{0}', with ID '{1}', has been partially activated on some devices in the Cisco
                     Catalyst Center.""".format(
                image_name, image_id
            )
            self.log(self.msg, "INFO")
        else:
            self.msg = """The activation of the requested image '{0}', with ID '{1}', failed on devices in the Cisco
                     Catalyst Center.""".format(
                image_name, image_id
            )
            self.log(self.msg, "INFO")

        return self

    def verify_diff_merged(self, config):
        """
        Verify the merged status(Importing/Tagging/Distributing/Actiavting) the SWIM Image in devices in Cisco Catalyst Center.
        Args:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): The configuration details to be verified.
        Return:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the merged status of a configuration in Cisco Catalyst Center by retrieving the current state
            (have) and desired state (want) of the configuration, logs the states, and validates whether the specified
            SWIM operation performed or not.
        """

        self.get_have()
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        import_type = self.want.get("import_type")
        if import_type:
            self.verify_diff_imported(import_type).check_return_status()

        tagged = self.want.get("tagging_details")
        if tagged:
            self.verify_diff_tagged().check_return_status()

        distribution_details = self.want.get("distribution_details")
        if distribution_details:
            self.verify_diff_distributed().check_return_status()

        activation_details = self.want.get("activation_details")
        if activation_details:
            self.verify_diff_activated().check_return_status()

        return self

    def update_swim_profile_messages(self):
        """
        Verify the merged status (Importing/Tagging/Distributing/Activating) of the SWIM Image in devices in Cisco Catalyst Center.
        Args:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Return:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the merged status of a configuration in Cisco Catalyst Center by retrieving the current state
            (have) and desired state (want) of the configuration. It logs the current and desired states, and validates whether
            the specified SWIM operation (Importing, Tagging, Distributing, or Activating) has been successfully performed or not.
        """

        if self.images_to_import or self.existing_images:
            imported_images_str = ", ".join(self.images_to_import)
            skipped_images_str = ", ".join(self.existing_images)

            messages = []

            if skipped_images_str:
                messages.append(
                    "Image(s) {0} were skipped as they already exist in Cisco Catalyst Center.".format(
                        skipped_images_str
                    )
                )

            if imported_images_str:
                messages.append(
                    "Image(s) {0} have been imported successfully into Cisco Catalyst Center.".format(
                        imported_images_str
                    )
                )
                self.result["changed"] = True

            elif not skipped_images_str:
                messages.append("No images were imported.")

            self.msg = " ".join(messages)

            self.result["msg"] = self.msg
            self.result["response"] = self.msg
            self.log(self.msg, "INFO")

            return self


def main():
    """main entry point for module execution"""

    element_spec = {
        "dnac_host": {"required": True, "type": "str"},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": "True"},
        "dnac_version": {"type": "str", "default": "2.2.3.3"},
        "dnac_debug": {"type": "bool", "default": False},
        "dnac_log_level": {"type": "str", "default": "WARNING"},
        "dnac_log_file_path": {"type": "str", "default": "dnac.log"},
        "dnac_log_append": {"type": "bool", "default": True},
        "dnac_log": {"type": "bool", "default": False},
        "validate_response_schema": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"required": True, "type": "list", "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged"]},
    }

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)

    ccc_swims = Swim(module)
    state = ccc_swims.params.get("state")

    if ccc_swims.compare_dnac_versions(ccc_swims.get_ccc_version(), "2.3.5.3") < 0:
        ccc_swims.msg = """The specified version '{0}' does not support the 'swim_workflow_manager' feature.
        Supported versions start from '2.3.5.3' onwards. """.format(
            ccc_swims.get_ccc_version()
        )
        ccc_swims.status = "failed"
        ccc_swims.check_return_status()

    if state not in ccc_swims.supported_states:
        ccc_swims.status = "invalid"
        ccc_swims.msg = "State {0} is invalid".format(state)
        ccc_swims.check_return_status()

    ccc_swims.validate_input().check_return_status()
    config_verify = ccc_swims.params.get("config_verify")

    for config in ccc_swims.validated_config:
        ccc_swims.reset_values()
        ccc_swims.get_want(config).check_return_status()
        ccc_swims.get_diff_import().check_return_status()
        ccc_swims.get_have().check_return_status()
        ccc_swims.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_swims.verify_diff_state_apply[state](config).check_return_status()
    ccc_swims.update_swim_profile_messages()
    module.exit_json(**ccc_swims.result)


if __name__ == "__main__":
    main()
