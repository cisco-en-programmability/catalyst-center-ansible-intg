#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: icap_radios_id_stats
short_description: Resource module for Icap Radios Id
  Stats
description:
  - Manage operation create of the resource Icap Radios
    Id Stats. - > Retrieves the time series statistics
    of a specific radio by applying complex filters.
    If startTime and endTime are not provided, the API
    defaults to the last 24 hours. For detailed information
    about the usage of the API, please refer to the
    Open API specification document - https //github.com/cisco-en-programmability/catalyst-
    center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-icap-1.0.0-resolved.yaml.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  endTime:
    description: End Time.
    type: int
  filters:
    description: Icap Radios Id Stats's filters.
    elements: dict
    suboptions:
      key:
        description: Key.
        type: str
      operator:
        description: Operator.
        type: str
      value:
        description: Value.
        type: int
    type: list
  headers:
    description: Additional headers.
    type: dict
  id:
    description: Id path parameter. Id is the composite
      key made of AP Base Ethernet macAddress and Radio
      Slot Id. Format apMac_RadioId.
    type: str
  page:
    description: Icap Radios Id Stats's page.
    suboptions:
      limit:
        description: Limit.
        type: int
      offset:
        description: Offset.
        type: int
      timeSortOrder:
        description: Time Sort Order.
        type: str
    type: dict
  startTime:
    description: Start Time.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sensors
      RetrievesSpecificRadioStatisticsOverSpecifiedPeriodOfTime
    description: Complete reference of the RetrievesSpecificRadioStatisticsOverSpecifiedPeriodOfTime
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-specific-radio-statistics-over-specified-period-of-time
notes:
  - SDK Method used are
    sensors.Sensors.retrieves_specific_radio_statistics_over_specified_period_of_time,
  - Paths used are
    post /dna/data/api/v1/icap/radios/{id}/stats,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.icap_radios_id_stats:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    endTime: 0
    filters:
      - key: string
        operator: string
        value: 0
    headers: '{{my_headers | from_json}}'
    id: string
    page:
      limit: 0
      offset: 0
      timeSortOrder: string
    startTime: 0
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
          "timestamp": 0,
          "apMac": "string",
          "radioId": 0,
          "band": "string",
          "utilization": 0,
          "nonWifiUtilization": 0,
          "rxOtherBSSUtilization": 0,
          "rxInBSSUtilization": 0,
          "txUtilization": 0,
          "noiseFloor": 0,
          "channel": 0,
          "channelWidth": 0,
          "txPower": 0,
          "maxTxPower": 0,
          "txBytes": 0,
          "rxBytes": 0,
          "rxPackets": 0,
          "txPackets": 0,
          "rxMgmtPackets": 0,
          "txMgmtPackets": 0,
          "rxErrors": 0,
          "txErrors": 0
        }
      ],
      "page": {
        "limit": 0,
        "offset": 0,
        "count": 0,
        "timeSortOrder": "string"
      },
      "version": "string"
    }
"""
