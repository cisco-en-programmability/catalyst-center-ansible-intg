#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
DOCUMENTATION = r"""
---
module: eox_status_summary_info
short_description: Information module for Eox Status Summary Info
description:
  - This module represents an alias of the module eox_status_summary_v1_info
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
requirements:
  - dnacentersdk >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for EoX GetEoXSummaryV1
    description: Complete reference of the GetEoXSummaryV1 API.
    link: https://developer.cisco.com/docs/dna-center/#!get-eo-x-summary
notes:
  - SDK Method used are eox.Eox.get_eox_summary_v1,
  - Paths used are get /dna/intent/api/v1/eox-status/summary,
  - It should be noted that this module is an alias of eox_status_summary_v1_info
"""
EXAMPLES = r"""
- name: Get all Eox Status Summary Info
  cisco.dnac.eox_status_summary_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "hardwareCount": 0,
        "softwareCount": 0,
        "moduleCount": 0,
        "totalCount": 0
      },
      "version": "string"
    }
"""
