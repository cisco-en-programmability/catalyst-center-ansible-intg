#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: security_service_insertions_count_info
short_description: Information module for Security Service
  Insertions Count
description:
  - Get all Security Service Insertions Count.
  - Retrieves the count of Security Service Insertions.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA CountOfSecurityServiceInsertions
    description: Complete reference of the CountOfSecurityServiceInsertions
      API.
    link: https://developer.cisco.com/docs/dna-center/#!count-of-security-service-insertions
notes:
  - SDK Method used are
    sda.Sda.count_of_security_service_insertions,
  - Paths used are
    get /dna/intent/api/v1/securityServiceInsertions/count,
"""

EXAMPLES = r"""
---
- name: Get all Security Service Insertions Count
  cisco.dnac.security_service_insertions_count_info:
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
        "count": 0
      },
      "version": "string"
    }
"""
