#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: platform_nodes_configuration_summary_info
short_description: Information module for Platform Nodes
  Configuration Summary
description:
  - Get all Platform Nodes Configuration Summary. -
    > Provides details about the current Cisco Catalyst
    Center node configuration, such as API version,
    node name, NTP server, intracluster link, LACP mode,
    network static routes, DNS server, subnet mask,
    host IP, default gateway, and interface information.
version_added: '3.1.0'
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
  - name: Cisco DNA Center documentation for Platform
      Configuration CiscoCatalystCenterNodesConfigurationSummary
    description: Complete reference of the CiscoCatalystCenterNodesConfigurationSummary
      API.
    link: https://developer.cisco.com/docs/dna-center/#!cisco-catalyst-center-nodes-configuration-summary
notes:
  - SDK Method used are
    platform_configuration.PlatformConfiguration.nodes_configuration_summary,
  - Paths used are
    get /dna/intent/api/v1/nodes-config,
"""

EXAMPLES = r"""
---
- name: Get all Platform Nodes Configuration Summary
  cisco.dnac.platform_nodes_configuration_summary_info:
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
      "version": "string",
      "response": {
        "nodes": [
          {
            "ntp": {
              "servers": [
                "string"
              ]
            },
            "network": [
              {
                "intra_cluster_link": true,
                "lacp_mode": true,
                "inet": {
                  "routes": [
                    {}
                  ],
                  "gateway": "string",
                  "dns_servers": [
                    {}
                  ],
                  "netmask": "string",
                  "host_ip": "string"
                },
                "interface": "string",
                "inet6": {
                  "host_ip": "string",
                  "netmask": "string"
                },
                "lacp_supported": true,
                "slave": [
                  "string"
                ]
              }
            ],
            "proxy": {
              "https_proxy": "string",
              "no_proxy": [
                "string"
              ],
              "https_proxy_username": "string",
              "http_proxy": "string",
              "https_proxy_password": "string"
            },
            "platform": {
              "vendor": "string",
              "product": "string",
              "serial": "string"
            },
            "id": "string",
            "name": "string"
          }
        ]
      }
    }
"""
