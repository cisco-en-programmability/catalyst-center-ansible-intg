#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_bugs_results_network_devices_network_device_id_info
short_description: Information module for Network Bugs
  Results Network Devices Network Device Id
description:
  - Get Network Bugs Results Network Devices Network
    Device Id by id.
  - Get network bug device by device id.
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
      - NetworkDeviceId path parameter. Id of the network
        device.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Compliance
      GetNetworkBugDeviceByDeviceId
    description: Complete reference of the GetNetworkBugDeviceByDeviceId
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-network-bug-device-by-device-id
notes:
  - SDK Method used are
    compliance.Compliance.get_network_bug_device_by_device_id,
  - Paths used are
    get /dna/intent/api/v1/networkBugs/results/networkDevices/{networkDeviceId},
"""

EXAMPLES = r"""
---
- name: Get Network Bugs Results Network Devices Network
    Device Id by id
  cisco.dnac.network_bugs_results_network_devices_network_device_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    networkDeviceId: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "response": {
          "networkDeviceId": "string",
          "bugCount": 0,
          "scanMode": "string",
          "scanStatus": "string",
          "comments": "string",
          "lastScanTime": 0
        },
        "version": "string"
      }
    ]
"""
