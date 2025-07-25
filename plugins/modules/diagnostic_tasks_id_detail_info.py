#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: diagnostic_tasks_id_detail_info
short_description: Information module for Diagnostic
  Tasks Id Detail
description:
  - Get all Diagnostic Tasks Id Detail.
  - This API retrieves the details of the diagnostic
    task identified by the specified `id`.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. The `id` of the diagnostic
        task to be retrieved.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Health
      and Performance RetrievesDiagnosticTaskDetailsByID
    description: Complete reference of the RetrievesDiagnosticTaskDetailsByID
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-diagnostic-task-details-by-id
notes:
  - SDK Method used are
    health_and_performance.HealthAndPerformance.retrieves_diagnostic_task_details_by_id,
  - Paths used are
    get /dna/intent/api/v1/diagnosticTasks/{id}/detail,
"""

EXAMPLES = r"""
---
- name: Get all Diagnostic Tasks Id Detail
  cisco.dnac.diagnostic_tasks_id_detail_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
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
        "data": "string",
        "progress": "string",
        "errorCode": "string",
        "failureReason": "string"
      },
      "version": "string"
    }
"""
