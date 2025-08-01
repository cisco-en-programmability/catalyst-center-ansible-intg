#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: security_advisories_results_network_devices_info
short_description: Information module for Security Advisories
  Results Network Devices
description:
  - Get all Security Advisories Results Network Devices.
  - Get security advisory network devices.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  networkDeviceId:
    description:
      - NetworkDeviceId query parameter. Id of the network
        device.
    type: str
  scanMode:
    description:
      - >
        ScanMode query parameter. Mode or the criteria
        using which the network device was scanned.
        Available values ESSENTIALS, ADVANTAGE, CX_CLOUD,
        NOT_AVAILABLE.
    type: str
  scanStatus:
    description:
      - >
        ScanStatus query parameter. Status of the scan
        on the network device. Available values NOT_SCANNED,
        IN_PROGRESS, SUCCESS, FAILED, FALL_BACK.
    type: str
  advisoryCount:
    description:
      - AdvisoryCount query parameter. Return network
        devices with advisoryCount greater than this
        advisoryCount.
    type: str
  offset:
    description:
      - >
        Offset query parameter. The first record to
        show for this page; the first record is numbered
        1. Default value is 1.
    type: float
  limit:
    description:
      - >
        Limit query parameter. The number of records
        to show for this page. Minimum value is 1. Maximum
        value is 500. Default value is 500.
    type: float
  sortBy:
    description:
      - SortBy query parameter. A property within the
        response to sort by.
    type: str
  order:
    description:
      - >
        Order query parameter. Whether ascending or
        descending order should be used to sort the
        response. Available values asc, desc. Default
        value is asc.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Compliance
      GetSecurityAdvisoryNetworkDevices
    description: Complete reference of the GetSecurityAdvisoryNetworkDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-security-advisory-network-devices
notes:
  - SDK Method used are
    compliance.Compliance.get_security_advisory_network_devices,
  - Paths used are
    get /dna/intent/api/v1/securityAdvisories/results/networkDevices,
"""

EXAMPLES = r"""
---
- name: Get all Security Advisories Results Network
    Devices
  cisco.dnac.security_advisories_results_network_devices_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    networkDeviceId: string
    scanMode: string
    scanStatus: string
    advisoryCount: string
    offset: 0
    limit: 0
    sortBy: string
    order: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": [
        {
          "networkDeviceId": "string",
          "advisoryCount": 0,
          "scanMode": "string",
          "scanStatus": "string",
          "comments": "string",
          "lastScanTime": 0
        }
      ],
      "version": "string"
    }
"""
