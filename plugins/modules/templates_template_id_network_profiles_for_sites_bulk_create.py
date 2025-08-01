#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: templates_template_id_network_profiles_for_sites_bulk_create
short_description: Resource module for Templates Template
  Id Network Profiles For Sites Bulk Create
description:
  - Manage operation create of the resource Templates
    Template Id Network Profiles For Sites Bulk Create.
  - Attaches a list of network profiles to the Day-N
    CLI template by passing the profile IDs and template
    ID.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  items:
    description: Templates Template Id Network Profiles
      For Sites Bulk Create's items.
    elements: list
    suboptions:
      profileId:
        description: The id of the network profile,
          retrievable from `/intent/api/v1/networkProfilesForSites`.
        type: str
    type: list
  templateId:
    description: TemplateId path parameter. The `id`
      of the template, retrievable from `GET /intent/api/v1/templates`.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Templates AttachAListOfNetworkProfilesToADayNCLITemplate
    description: Complete reference of the AttachAListOfNetworkProfilesToADayNCLITemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!attach-a-list-of-network-profiles-to-a-day-ncli-template
notes:
  - SDK Method used are
    configuration_templates.ConfigurationTemplates.attach_a_list_of_network_profiles_to_a_day_n_cli_template,
  - Paths used are
    post /dna/intent/api/v1/templates/{templateId}/networkProfilesForSites/bulk,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.templates_template_id_network_profiles_for_sites_bulk_create:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    items:
      - - profileId: string
    templateId: string
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
        "url": "string",
        "taskId": "string"
      }
    }
"""
