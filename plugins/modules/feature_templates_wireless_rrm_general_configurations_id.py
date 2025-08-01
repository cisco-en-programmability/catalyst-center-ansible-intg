#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: feature_templates_wireless_rrm_general_configurations_id
short_description: Resource module for Feature Templates
  Wireless Rrm General Configurations Id
description:
  - Manage operations update and delete of the resource
    Feature Templates Wireless Rrm General Configurations
    Id.
  - This API allows users to delete a specific RRM General
    configuration feature template by ID.
  - This API allows users to update the details of a
    specific RRM General configuration feature template
    by ID.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  designName:
    description: The feature template design name. `Note
      ` The following characters are not allowed % &
      < > ' /.
    type: str
  featureAttributes:
    description: Feature Templates Wireless Rrm General
      Configurations Id's featureAttributes.
    suboptions:
      coverageHoleDetection:
        description: Global Coverage Hole Detection.
        type: bool
      monitoringChannels:
        description: The monitoringChannels attribute
          represents the scope of monitoring channels.
        type: str
      neighborDiscoverType:
        description: The neighborDiscoverType attribute
          represents the type of neighbor discovery.
        type: str
      radioBand:
        description: Radio Band 2_4GHZ is supported
          only on Cisco IOS-XE based Wireless Controllers
          running 17.9.1 and above.
        type: str
      throughputThreshold:
        description: Throughput Threshold.
        type: int
    type: dict
  id:
    description: Id path parameter. Multicast Configuration
      Feature Template Id.
    type: str
  unlockedAttributes:
    description: Attributes unlocked in design can be
      changed at device provision time. `Note ` unlockedAttributes
      can only contain the attributes defined under
      featureAttributes.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      DeleteRRMGeneralConfigurationFeatureTemplate
    description: Complete reference of the DeleteRRMGeneralConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-rrm-general-configuration-feature-template
  - name: Cisco DNA Center documentation for Wireless
      UpdateRRMGeneralConfigurationFeatureTemplate
    description: Complete reference of the UpdateRRMGeneralConfigurationFeatureTemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-rrm-general-configuration-feature-template
notes:
  - SDK Method used are
    wireless.Wireless.delete_r_r_m_general_configuration_feature_template,
    wireless.Wireless.update_r_r_m_general_configuration_feature_template,
  - Paths used are
    delete /dna/intent/api/v1/featureTemplates/wireless/rrmGeneralConfigurations/{id},
    put /dna/intent/api/v1/featureTemplates/wireless/rrmGeneralConfigurations/{id},
"""

EXAMPLES = r"""
---
- name: Delete by id
  cisco.dnac.feature_templates_wireless_rrm_general_configurations_id:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
- name: Update by id
  cisco.dnac.feature_templates_wireless_rrm_general_configurations_id:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    designName: string
    featureAttributes:
      coverageHoleDetection: true
      monitoringChannels: string
      neighborDiscoverType: string
      radioBand: string
      throughputThreshold: 0
    id: string
    unlockedAttributes:
      - string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
