#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module to manage wireless design operations in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ("Rugvedi Kapse, Madhan Sankaranarayanan")


DOCUMENTATION = r"""
---
module: wireless_design_workflow_manager
short_description: Manage wireless design elements in Cisco Catalyst Center.
description:
  - Manage Wireless Design operations, including creation, update and deletion of SSID(s), Interface(s), Power Profile(s),
    Access Point Profile(s), Radio Frequency Profile(s), Anchor Group(s).
  - APIs to create, update, and delete SSIDs in Cisco Catalyst Center.
  - APIs to create, update, and delete Interfaces in Cisco Catalyst Center.
  - APIs to create, update, and delete Power Profiles in Cisco Catalyst Center.
  - APIs to create, update, and delete RF Profiles in Cisco Catalyst Center.
  - APIs to create, update, and delete AP Profiles in Cisco Catalyst Center.
  - APIs to create, update, and delete Anchor Groups in Cisco Catalyst Center.
version_added: "6.17.0"
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - Rugvedi Kapse (@rukapse)
  - Madhan Sankaranarayanan (@madhansansel)
options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst Center configuration after applying the playbook configuration.
    type: bool
    default: False
  state:
    description: The desired state of Cisco Catalyst Center after module execution.
    type: str
    choices: [merged, deleted]
    default: merged
  config:
    description:
      - A list containing configurations for managing SSIDs, Interfaces, Power Profiles, RF Profiles, AP Profiles, and Anchor Groups in Cisco Catalyst Center.
      - Note - For UPDATE operations it is cruticial to understand when configurations need to be explicitly provided and when not
        - SSIDs - There is no need to provide the destined SSID configuration. This is managed automatically.
        - Interfaces - It is essential to provide the specific configuration for the destined interfaces. Ensure all necessary details are included.
        - Power Profiles - Just like interfaces, the destined configuration for power profiles must be provided. Include all relevant settings.
        - AP Profiles - There is no requirement to provide the destined configuration for AP profiles. These configurations are handled as needed.
        - RF Profiles - Similar to AP profiles, destined RF profiles configurations are not required to be provided.
        - Anchor Groups - It is necessary to provide the destined configuration for anchor groups. Make sure to include all pertinent information.
    type: list
    elements: dict
    required: True
    suboptions:
      ssids:
        description: Configure SSIDs for Enterprise and Guest Wireless Networks.
        type: list
        elements: dict
        suboptions:
          ssid_name:
            description:
              - Specifies the Wireless Network name or SSID name.
              - The maximum length of the SSID name is 32 characters.
              - This parameter is required for creating, updating, or deleting SSIDs.
            type: str
          ssid_type:
            description:
              - Specifies the type of WLAN.
              - This parameter is required for creating, updating, or deleting SSIDs.
              - Required in merged state for creating or updating SSIDs.
            type: str
            choices: ["Enterprise", "Guest"]

requirements:
  - dnacentersdk >= 2.10.3
  - python >= 3.9

notes:
  - SDK Methods used are
    - sites.Sites.get_site
    - site_design.SiteDesigns.get_sites
    - wirelesss.Wireless.create_ssid
    - wirelesss.Wireless.update_ssid
    - wirelesss.Wireless.update_or_overridessid
    - wirelesss.Wireless.delete_ssid
    - wirelesss.Wireless.get_interfaces
    - wirelesss.Wireless.create_interface
    - wirelesss.Wireless.update_interface
    - wirelesss.Wireless.delete_interface
    - wirelesss.Wireless.get_power_profiles
    - wirelesss.Wireless.create_power_profile
    - wirelesss.Wireless.update_power_profile_by_id
    - wirelesss.Wireless.delete_power_profile_by_id
    - wirelesss.Wireless.get_ap_profiles
    - wirelesss.Wireless.create_ap_profile
    - wirelesss.Wireless.update_ap_profile_by_id
    - wirelesss.Wireless.delete_ap_profile_by_id
    - wirelesss.Wireless.get_rf_profiles
    - wirelesss.Wireless.create_rf_profile
    - wirelesss.Wireless.update_rf_profile
    - wirelesss.Wireless.delete_rf_profile
    - wirelesss.Wireless.get_anchor_groups
    - wirelesss.Wireless.create_anchor_group
    - wirelesss.Wireless.update_anchor_group
    - wirelesss.Wireless.delete_anchor_group_by_id

  - Paths used are
    - GET /dna/intent/api/v1/sites
    - GET /dna/intent/api/v1/sites/${siteId}/wirelessSettings/ssids
    - POST /dna/intent/api/v1/sites/${siteId}/wirelessSettings/ssids
    - PUT /dna/intent/api/v1/sites/${siteId}/wirelessSettings/ssids/${id}
    - POST /dna/intent/api/v1/sites/${siteId}/wirelessSettings/ssids/${id}/update
    - DELETE /dna/intent/api/v1/sites/${siteId}/wirelessSettings/ssids/${id}
    - GET /dna/intent/api/v1/wirelessSettings/interfaces
    - POST /dna/intent/api/v1/wirelessSettings/interfaces
    - PUT /dna/intent/api/v1/wirelessSettings/interfaces/${id}
    - DELETE /dna/intent/api/v1/wirelessSettings/interfaces/${id}
    - GET /dna/intent/api/v1/wirelessSettings/powerProfiles
    - POST /dna/intent/api/v1/wirelessSettings/powerProfiles
    - PUT /dna/intent/api/v1/wirelessSettings/powerProfiles/${id}
    - DELETE /dna/intent/api/v1/wirelessSettings/powerProfiles/${id}
    - GET /dna/intent/api/v1/wirelessSettings/apProfiles
    - POST /dna/intent/api/v1/wirelessSettings/apProfiles
    - PUT /dna/intent/api/v1/wirelessSettings/apProfiles/${id}
    - DELETE /dna/intent/api/v1/wirelessSettings/apProfiles/${id}
    - GET /dna/intent/api/v1/wirelessSettings/rfProfiles
    - POST /dna/intent/api/v1/wirelessSettings/rfProfiles
    - PUT /dna/intent/api/v1/wirelessSettings/rfProfiles/${id}
    - DELETE /dna/intent/api/v1/wirelessSettings/rfProfiles/${id}
    - GET /dna/intent/api/v1/wirelessSettings/anchorGroups
    - POST /dna/intent/api/v1/wirelessSettings/anchorGroups
    - PUT /dna/intent/api/v1/wirelessSettings/anchorGroups/${id}
    - DELETE /dna/intent/api/v1/wirelessSettings/anchorGroups/${id}

"""

EXAMPLES = r"""
- name: Add SSIDs
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: '{{dnac_host}}'
    dnac_username: '{{dnac_username}}'
    dnac_password: '{{dnac_password}}'
    dnac_verify: '{{dnac_verify}}'
    dnac_port: '{{dnac_port}}'
    dnac_version: '{{dnac_version}}'
    dnac_debug: '{{dnac_debug}}'
    dnac_log: true
    dnac_log_level: '{{dnac_log_level}}'
    state: merged
    config:
      - ssids:
        - ssid_name: "ssids-test1"
          ssid_type: "Enterprise"
          l2_security:
            l2_auth_type: "OPEN"

        - ssid_name: "ssids-test2"
          ssid_type: "Guest"
          l2_security:
            l2_auth_type: "OPEN"
          l3_security:
            l3_auth_type: "OPEN"

        - ssid_name: "ssids-test3"
          ssid_type: "Enterprise"
          wlan_profile_name: "test_ent_123_profile"
          radio_policy:
            radio_bands: [2.4, 5, 6]
            2_dot_4_ghz_band_policy: "802.11-bg"
            band_select: true
            6_ghz_client_steering: true
          fast_lane: true
          ssid_state:
            admin_status: true
            broadcast_ssid: true
          l2_security:
            l2_auth_type: "WPA2_WPA3_PERSONAL"
            ap_beacon_protection: true
            passphrase_type: "ASCII"
            passphrase: "password123"
          fast_transition: "ENABLE"
          fast_transition_over_the_ds: true
          wpa_encryption: ["CCMP128"]
          auth_key_management: ["PSK", "SAE"]
          aaa:
            aaa_override: false
            mac_filtering: true
            deny_rcm_clients: false
          mfp_client_protection: "OPTIONAL"
          protected_management_frame: "REQUIRED"
          11k_neighbor_list: true
          coverage_hole_detection: true
          wlan_timeouts:
            enable_session_timeout: true
            session_timeout: 3600
            enable_client_execlusion_timeout: true
            client_execlusion_timeout: 1800
          bss_transition_support:
            bss_max_idle_service: true
            bss_idle_client_timeout: 300
            directed_multicast_service: true
          nas_id: ["AP Location"]
          client_rate_limit: 90000

        - ssid_name: "ssids-test4"
          ssid_type: "Enterprise"
          l2_security:
            l2_auth_type: "WPA2_ENTERPRISE"
          fast_transition: "ADAPTIVE"
          fast_transition_over_the_ds: true
          wpa_encryption: ["CCMP128"]
          auth_key_management: ["CCKM", "802.1X-SHA1", "802.1X-SHA2"]
          cckm_timestamp_tolerance: 1000

        - ssid_name: "ssids-test5"
          ssid_type: "Enterprise"
          l2_security:
            l2_auth_type: "WPA2_ENTERPRISE"
          fast_transition: "ADAPTIVE"
          fast_transition_over_the_ds: true
          wpa_encryption: ["GCMP256"]
          auth_key_management: ["SUITE-B-192X"]

        - ssid_name: "ssids-test6"
          ssid_type: "Enterprise"
          l2_security:
            l2_auth_type: "WPA2_ENTERPRISE"
          fast_transition: "DISABLE"
          wpa_encryption: ["GCMP256"]
          auth_key_management: ["SUITE-B-192X"]

        - ssid_name: "ssids-test7"
          ssid_type: "Enterprise"
          l2_security:
            l2_auth_type: "WPA2_ENTERPRISE"
          fast_transition: "ENABLE"
          fast_transition_over_the_ds: true
          wpa_encryption: ["CCMP128"]
          auth_key_management: ["CCKM", "802.1X-SHA1", "802.1X-SHA2", "FT+802.1x"]
          cckm_timestamp_tolerance: 3000

        - ssid_name: "ssids-test8"
          ssid_type: "Enterprise"
          l2_security:
            l2_auth_type: "WPA3_ENTERPRISE"
          fast_transition: "ENABLE"
          fast_transition_over_the_ds: true
          wpa_encryption: ["CCMP128"]
          auth_key_management: ["802.1X-SHA1", "802.1X-SHA2", "FT+802.1x"]

        - ssid_name: "ssids-test9"
          ssid_type: "Enterprise"
          l2_security:
            l2_auth_type: "WPA3_ENTERPRISE"
          fast_transition: "ADAPTIVE"
          fast_transition_over_the_ds: true
          wpa_encryption: ["GCMP128"]
          auth_key_management: ["SUITE-B-1X"]

        - ssid_name: "ssids-test10"
          ssid_type: "Enterprise"
          l2_security:
            l2_auth_type: "WPA3_ENTERPRISE"
          fast_transition: "DISABLE"
          wpa_encryption: ["GCMP256"]
          auth_key_management: ["SUITE-B-192X"]

        - ssid_name: "ssids-test11"
          ssid_type: "Enterprise"
          wlan_profile_name: "ssid-test11_profile"
          radio_policy:
            radio_bands: [2.4, 5, 6]
            2_dot_4_ghz_band_policy: "802.11-bg"
            band_select: true
            6_ghz_client_steering: true
          fast_lane: true
          ssid_state:
            admin_status: true
            broadcast_ssid: true
          l2_security:
            l2_auth_type: "OPEN"
          fast_transition: "DISABLE"
          aaa:
            aaa_override: false
            mac_filtering: true
            deny_rcm_clients: false
          mfp_client_protection: "OPTIONAL"
          protected_management_frame: "REQUIRED"
          11k_neighbor_list: true
          coverage_hole_detection: true
          wlan_timeouts:
            enable_session_timeout: true
            session_timeout: 3600
            enable_client_execlusion_timeout: true
            client_execlusion_timeout: 1800
          bss_transition_support:
            bss_max_idle_service: true
            bss_idle_client_timeout: 300
            directed_multicast_service: true
          nas_id: ["AP Location"]
          client_rate_limit: 90000
          sites_specific_override_settings:
            - site_name_hierarchy: "Global/USA/San Jose"
              l2_security:
                l2_auth_type: "WPA2_PERSONAL"
                passphrase: "password456"
              fast_transition: "ENABLE"
              wpa_encryption: ["CCMP128"]
              auth_key_management: ["PSK"]
            - site_name_hierarchy: "Global/USA/San Jose/BLDG23"
              fast_transition: "DISABLE"
              client_rate_limit: 9000

- name: Update SSIDs
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - ssids:
        - ssid_name: "ssids-test8"
          ssid_type: "Enterprise"
          l2_security:
            l2_auth_type: "WPA2_WPA3_ENTERPRISE"
            ap_beacon_protection: true
          fast_transition: "ENABLE"
          fast_transition_over_the_ds: true
          wpa_encryption: ["CCMP128"]
          auth_key_management: ["CCKM", "802.1X-SHA1", "802.1X-SHA2", "FT+802.1x"]
          cckm_timestamp_tolerance: 3000
          protected_management_frame: "REQUIRED"

        - ssid_name: "ssids-test9"
          ssid_type: "Enterprise"
          l2_security:
            l2_auth_type: "WPA2_WPA3_ENTERPRISE"
            ap_beacon_protection: true
          fast_transition: "DISABLE"
          fast_transition_over_the_ds: true
          wpa_encryption: ["GCMP128", "CCMP256", "GCMP256"]
          auth_key_management: ["SUITE-B-1X", "SUITE-B-192X"]
          protected_management_frame: "REQUIRED"

        - ssid_name: "ssids-test2"
          ssid_type: "Guest"
          sites_specific_override_settings:
            - site_name_hierarchy: "Global/USA/San Jose"
              l2_security:
                l2_auth_type: "WPA2_PERSONAL"
                passphrase: "password456"
              fast_transition: "ENABLE"
              wpa_encryption: ["CCMP128"]
              auth_key_management: ["PSK"]

- name: Delete SSIDs
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - ssids:
        - ssid_name: "ssids-test1"
        - ssid_name: "ssids-test2"
        - ssid_name: "ssids-test3"
        - ssid_name: "ssids-test4"
        - ssid_name: "ssids-test5"
        - ssid_name: "ssids-test6"
        - ssid_name: "ssids-test7"
        - ssid_name: "ssids-test8"
        - ssid_name: "ssids-test9"
        - ssid_name: "ssids-test10"
        - ssid_name: "ssids-test11"
          sites_specific_override_settings:
            - site_name_hierarchy: "Global/USA/San Jose"
              remove_override_in_hierarchy: True

- name: Add Interfaces
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - interfaces:
        - interface_name: "test1"
          vlan_id: 1

        - interface_name: "test2"
          vlan_id: 2

        - interface_name: "test3"
          vlan_id: 3

        - interface_name: "test4"
          vlan_id: 4

        - interface_name: "test5"
          vlan_id: 5

        - interface_name: "test6"
          vlan_id: 6

- name: Update Interfaces
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - interfaces:
        - interface_name: "test1"
          vlan_id: 7

        - interface_name: "test2"
          vlan_id: 8

        - interface_name: "test3"
          vlan_id: 9

        - interface_name: "test6"
          vlan_id: 10

- name: Delete Interfaces
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - interfaces:
        - interface_name: "test1"
        - interface_name: "test2"
        - interface_name: "test3"
        - interface_name: "test4"
        - interface_name: "test5"
        - interface_name: "test6"

- name: Add Power Profiles
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - power_profiles:
        - power_profile_name: "default"
          rules:
            - interface_type: "USB"
            - interface_type: "RADIO"
            - interface_type: "ETHERNET"

        - power_profile_name: "EthernetSpeeds"
          power_profile_description: "Profile for all Ethernet speed settings."
          rules:
            - interface_type: "ETHERNET"
              interface_id: "GIGABITETHERNET0"
              parameter_type: "SPEED"
              parameter_value: "5000MBPS"
            - interface_type: "ETHERNET"
              interface_id: "GIGABITETHERNET0"
              parameter_type: "SPEED"
              parameter_value: "2500MBPS"
            - interface_type: "ETHERNET"
              interface_id: "GIGABITETHERNET0"
              parameter_type: "SPEED"
              parameter_value: "1000MBPS"
            - interface_type: "ETHERNET"
              interface_id: "GIGABITETHERNET0"
              parameter_type: "SPEED"
              parameter_value: "100MBPS"
            - interface_type: "ETHERNET"
              interface_id: "GIGABITETHERNET1"
              parameter_type: "SPEED"
              parameter_value: "5000MBPS"
            - interface_type: "ETHERNET"
              interface_id: "GIGABITETHERNET1"
              parameter_type: "SPEED"
              parameter_value: "2500MBPS"
            - interface_type: "ETHERNET"
              interface_id: "GIGABITETHERNET1"
              parameter_type: "SPEED"
              parameter_value: "1000MBPS"
            - interface_type: "ETHERNET"
              interface_id: "GIGABITETHERNET1"
              parameter_type: "SPEED"
              parameter_value: "100MBPS"

        - power_profile_name: "EthernetState"
          power_profile_description: "Profile for Ethernet state settings."
          rules:
            - interface_type: "ETHERNET"
              interface_id: "LAN1"
              parameter_type: "STATE"
              parameter_value: "DISABLE"
            - interface_type: "ETHERNET"
              interface_id: "LAN2"
              parameter_type: "STATE"
              parameter_value: "DISABLE"
            - interface_type: "ETHERNET"
              interface_id: "LAN3"
              parameter_type: "STATE"
              parameter_value: "DISABLE"

        - power_profile_name: "RadioState"
          power_profile_description: "Profile for radio state settings."
          rules:
            - interface_type: "RADIO"
              interface_id: "6GHZ"
              parameter_type: "STATE"
              parameter_value: "DISABLE"
            - interface_type: "RADIO"
              interface_id: "5GHZ"
              parameter_type: "STATE"
              parameter_value: "DISABLE"
            - interface_type: "RADIO"
              interface_id: "SECONDARY_5GHZ"
              parameter_type: "STATE"
              parameter_value: "DISABLE"
            - interface_type: "RADIO"
              interface_id: "2_4GHZ"
              parameter_type: "STATE"
              parameter_value: "DISABLE"

        - power_profile_name: "RadioSpatialStream"
          power_profile_description: "Profile for radio spatial stream settings."
          rules:
            - interface_type: "RADIO"
              interface_id: "6GHZ"
              parameter_type: "SPATIALSTREAM"
              parameter_value: "FOUR_BY_FOUR"
            - interface_type: "RADIO"
              interface_id: "6GHZ"
              parameter_type: "SPATIALSTREAM"
              parameter_value: "THREE_BY_THREE"
            - interface_type: "RADIO"
              interface_id: "6GHZ"
              parameter_type: "SPATIALSTREAM"
              parameter_value: "TWO_BY_TWO"
            - interface_type: "RADIO"
              interface_id: "6GHZ"
              parameter_type: "SPATIALSTREAM"
              parameter_value: "ONE_BY_ONE"
            - interface_type: "RADIO"
              interface_id: "5GHZ"
              parameter_type: "SPATIALSTREAM"
              parameter_value: "FOUR_BY_FOUR"
            - interface_type: "RADIO"
              interface_id: "5GHZ"
              parameter_type: "SPATIALSTREAM"
              parameter_value: "THREE_BY_THREE"
            - interface_type: "RADIO"
              interface_id: "5GHZ"
              parameter_type: "SPATIALSTREAM"
              parameter_value: "TWO_BY_TWO"
            - interface_type: "RADIO"
              interface_id: "5GHZ"
              parameter_type: "SPATIALSTREAM"
              parameter_value: "ONE_BY_ONE"
            - interface_type: "RADIO"
              interface_id: "SECONDARY_5GHZ"
              parameter_type: "SPATIALSTREAM"
              parameter_value: "FOUR_BY_FOUR"
            - interface_type: "RADIO"
              interface_id: "2_4GHZ"
              parameter_type: "SPATIALSTREAM"
              parameter_value: "FOUR_BY_FOUR"

        - power_profile_name: "UsbState"
          power_profile_description: "Profile for USB state settings."
          rules:
            - interface_type: "USB"
              interface_id: "USB0"
              parameter_type: "STATE"
              parameter_value: "DISABLE"

- name: Update Power Profiles
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - power_profiles:
        - power_profile_name: "default"
          rules:
            - interface_type: "RADIO"
            - interface_type: "ETHERNET"
            - interface_type: "USB"

        - power_profile_name: "EthernetSpeeds"
          rules:
            - interface_type: "ETHERNET"
              interface_id: "GIGABITETHERNET1"
              parameter_type: "SPEED"
              parameter_value: "2500MBPS"
            - interface_type: "ETHERNET"
              interface_id: "GIGABITETHERNET0"
              parameter_type: "SPEED"
              parameter_value: "1000MBPS"
            - interface_type: "ETHERNET"
              interface_id: "GIGABITETHERNET1"
              parameter_type: "SPEED"
              parameter_value: "100MBPS"


        - power_profile_name: "EthernetState"
          power_profile_description: "Updated profile for Ethernet state settings."
          rules:
            - interface_type: "ETHERNET"
              interface_id: "LAN3"
              parameter_type: "STATE"
              parameter_value: "DISABLE"
            - interface_type: "ETHERNET"
              interface_id: "LAN1"
              parameter_type: "STATE"
              parameter_value: "DISABLE"
            - interface_type: "ETHERNET"
              interface_id: "LAN2"
              parameter_type: "STATE"
              parameter_value: "DISABLE"

        - power_profile_name: "RadioState"
          # Removed description to simulate a change
          rules:
            - interface_type: "RADIO"
              interface_id: "2_4GHZ"
              parameter_type: "STATE"
              parameter_value: "DISABLE"
            - interface_type: "RADIO"
              interface_id: "SECONDARY_5GHZ"
              parameter_type: "STATE"
              parameter_value: "DISABLE"
            - interface_type: "RADIO"
              interface_id: "5GHZ"
              parameter_type: "STATE"
              parameter_value: "DISABLE"
            - interface_type: "RADIO"
              interface_id: "6GHZ"
              parameter_type: "STATE"
              parameter_value: "DISABLE"

        - power_profile_name: "RadioSpatialStream"
          power_profile_description: "Updated profile for radio spatial stream settings."
          rules:
            - interface_type: "RADIO"
              interface_id: "6GHZ"
              parameter_type: "SPATIALSTREAM"
              parameter_value: "TWO_BY_TWO"
            - interface_type: "RADIO"
              interface_id: "5GHZ"
              parameter_type: "SPATIALSTREAM"
              parameter_value: "ONE_BY_ONE"
              interface_id: "2_4GHZ"
              parameter_type: "SPATIALSTREAM"
              parameter_value: "FOUR_BY_FOUR"
            - interface_type: "RADIO"
              interface_id: "SECONDARY_5GHZ"
              parameter_type: "SPATIALSTREAM"
              parameter_value: "FOUR_BY_FOUR"

        - power_profile_name: "UsbState"
          power_profile_description: "Updated profile for USB state settings."
          rules:
            - interface_type: "USB"
              interface_id: "USB0"
              parameter_type: "STATE"
              parameter_value: "DISABLE"

        - power_profile_name: "UsbState"
          rules:
            - interface_type: "USB"

- name: Delete Power Profiles
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - power_profiles:
        - power_profile_name: "default"
        - power_profile_name: "EthernetSpeeds"
        - power_profile_name: "EthernetState"
        - power_profile_name: "RadioState"
        - power_profile_name: "RadioSpatialStream"
        - power_profile_name: "UsbState"


- name: Add Power Profiles
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - access_point_profiles:
        - access_point_profile_name: "Profile-test1"

        - access_point_profile_name: "Profile-test2"
          access_point_profile_description: "Main office AP profile 2"

        - access_point_profile_name: "Profile-test3"
          access_point_profile_description: "Main office AP profile 3"
          remote_teleworker: false

        - access_point_profile_name: "Profile-test4"
          remote_teleworker: true


        - access_point_profile_name: "Profile-test5"
          remote_teleworker: true
          management_settings:
            access_point_authentication: "NO-AUTH"

        - access_point_profile_name: "Profile-test6"
          remote_teleworker: false
          management_settings:
            access_point_authentication: "EAP-TLS"

        - access_point_profile_name: "Profile-test32"
          management_settings:
            access_point_authentication: "EAP-PEAP"
            dot1x_username: "user1"
            dot1x_password: "asdfasdfasdfsdf"

        - access_point_profile_name: "Profile-test7"
          management_settings:
            access_point_authentication: "EAP-FAST"
            dot1x_username: "user1"
            dot1x_password: "asdfasdfasdfsdf"

        - access_point_profile_name: "Profile-test8"
          remote_teleworker: true
          management_settings:
            access_point_authentication: "NO-AUTH"
            ssh_enabled: true
            telnet_enabled: false
            management_username: "admin"
            management_password: "securePass"
            management_enable_password: "adflmlssf"

        - access_point_profile_name: "Profile-test9"
          management_settings:
            access_point_authentication: "EAP-PEAP"
            dot1x_username: "user1"
            dot1x_password: "asdfasdfasdfsdf"
            ssh_enabled: true
            telnet_enabled: true
            management_username: "admin"
            management_password: "securePass"
            management_enable_password: "adflmlssf"

        - access_point_profile_name: "Profile-test10"
          management_settings:
            access_point_authentication: "EAP-TLS"
            ssh_enabled: false
            telnet_enabled: false

        - access_point_profile_name: "Profile-test11"
          management_settings:
            access_point_authentication: "EAP-PEAP"
            dot1x_username: "user1"
            dot1x_password: "asdfasdfasdfsdf"
            ssh_enabled: false
            telnet_enabled: true
            management_username: "admin"
            management_password: "securePass"
            management_enable_password: "adflmlssf"

        - access_point_profile_name: "Profile-test12"
          security_settings:
            awips: true
            awips_forensic: false
            rogue_detection: true
            minimum_rssi: -71
            transient_interval: 300
            report_interval: 60
            pmf_denial: false

        - access_point_profile_name: "Profile-test13"
          security_settings:
            awips: true
            awips_forensic: true

        - access_point_profile_name: "Profile-test14"
          remote_teleworker: false
          management_settings:
            access_point_authentication: "EAP-PEAP"
            dot1x_username: "user1"
            dot1x_password: "asdfasdfasdfsdf"
            ssh_enabled: false
            telnet_enabled: true
            management_username: "admin"
            management_password: "securePass"
            management_enable_password: "adflmlssf"
          security_settings:
            awips: true
            awips_forensic: false
            rogue_detection: true
            minimum_rssi: -71
            transient_interval: 300
            report_interval: 60
            pmf_denial: false

        - access_point_profile_name: "Profile-test15"
          mesh_enabled: true
          mesh_settings:
            range: 1000
            backhaul_client_access: true
            rap_downlink_backhaul: "5 GHz"
            ghz_5_radio_band_type: "802.11ax"

        - access_point_profile_name: "Profile-test16"
          mesh_enabled: true
          mesh_settings:
            range: 1000
            backhaul_client_access: true
            rap_downlink_backhaul: "2.4 GHz"
            ghz_2_point_4_radio_band_type: "802.11n"
            bridge_group_name: "Bridge1"

        - access_point_profile_name: "Profile-test17"
          access_point_profile_description: "Main office AP profile 17"
          remote_teleworker: false
          management_settings:
            access_point_authentication: "EAP-PEAP"
            dot1x_username: "user1"
            dot1x_password: "asdfasdfasdfsdf"
            ssh_enabled: false
            telnet_enabled: true
            management_username: "admin"
            management_password: "securePass"
            management_enable_password: "adflmlssf"
          security_settings:
            awips: true
            awips_forensic: false
            rogue_detection: true
            minimum_rssi: -71
            transient_interval: 300
            report_interval: 60
            pmf_denial: false
          mesh_enabled: true
          mesh_settings:
            range: 1000
            backhaul_client_access: true
            rap_downlink_backhaul: "2.4 GHz"
            ghz_2_point_4_radio_band_type: "802.11n"
            bridge_group_name: "Bridge1"

        - access_point_profile_name: "Profile-test18"
          power_settings:
            ap_power_profile_name: "ada"


        - access_point_profile_name: "Profile-test19"
          power_settings:
            ap_power_profile_name: "ada"
            calendar_power_profiles:
              - ap_power_profile_name: "sdfd"
                scheduler_type: "DAILY"
                scheduler_start_time: "08:00 AM"
                scheduler_end_time: "6:00 PM"

        - access_point_profile_name: "Profile-test20"
          power_settings:
            ap_power_profile_name: "ada"
            calendar_power_profiles:
              - ap_power_profile_name: "sdfd"
                scheduler_type: "WEEKLY"
                scheduler_days_list: ["monday", "tuesday"]
                scheduler_start_time: "08:00 AM"
                scheduler_end_time: "6:00 PM"

        - access_point_profile_name: "Profile-test21"
          power_settings:
            ap_power_profile_name: "ada"
            calendar_power_profiles:
              - ap_power_profile_name: "sdfd"
                scheduler_type: "MONTHLY"
                scheduler_dates_list: ["2", "9", "28"]
                scheduler_start_time: "08:00 AM"
                scheduler_end_time: "6:00 PM"

        - access_point_profile_name: "Profile-test22"
          access_point_profile_description: "Main office AP profile 22"
          remote_teleworker: false
          management_settings:
            access_point_authentication: "EAP-PEAP"
            dot1x_username: "user1"
            dot1x_password: "asdfasdfasdfsdf"
            ssh_enabled: false
            telnet_enabled: true
            management_username: "admin"
            management_password: "securePass"
            management_enable_password: "adflmlssf"
          security_settings:
            awips: true
            awips_forensic: false
            rogue_detection: true
            minimum_rssi: -71
            transient_interval: 300
            report_interval: 60
            pmf_denial: false
          mesh_enabled: true
          mesh_settings:
            range: 1000
            backhaul_client_access: true
            rap_downlink_backhaul: "2.4 GHz"
            ghz_2_point_4_radio_band_type: "802.11n"
            bridge_group_name: "Bridge1"
          power_settings:
            ap_power_profile_name: "ada"
            calendar_power_profiles:
              - ap_power_profile_name: "sdfd"
                scheduler_type: "DAILY"
                scheduler_start_time: "08:00 AM"
                scheduler_end_time: "6:00 PM"

        - access_point_profile_name: "Profile-test23"
          access_point_profile_description: "Main office AP profile 23"
          remote_teleworker: false
          management_settings:
            access_point_authentication: "EAP-PEAP"
            dot1x_username: "user1"
            dot1x_password: "asdfasdfasdfsdf"
            ssh_enabled: false
            telnet_enabled: true
            management_username: "admin"
            management_password: "securePass"
            management_enable_password: "adflmlssf"
          security_settings:
            awips: true
            awips_forensic: false
            rogue_detection: true
            minimum_rssi: -71
            transient_interval: 300
            report_interval: 60
            pmf_denial: false
          mesh_enabled: true
          mesh_settings:
            range: 1000
            backhaul_client_access: true
            rap_downlink_backhaul: "2.4 GHz"
            ghz_2_point_4_radio_band_type: "802.11n"
            bridge_group_name: "Bridge1"
          power_settings:
            ap_power_profile_name: "ada"
            calendar_power_profiles:
              - ap_power_profile_name: "sdfd"
                scheduler_type: "WEEKLY"
                scheduler_days_list: ["monday", "tuesday"]
                scheduler_start_time: "08:00 AM"
                scheduler_end_time: "6:00 PM"

        - access_point_profile_name: "Profile-test24"
          access_point_profile_description: "Main office AP profile 24"
          management_settings:
            access_point_authentication: "EAP-PEAP"
            dot1x_username: "user1"
            dot1x_password: "asdfasdfasdfsdf"
            ssh_enabled: false
            telnet_enabled: true
            management_username: "admin"
            management_password: "securePass"
            management_enable_password: "adflmlssf"
          security_settings:
            awips: true
            awips_forensic: false
            rogue_detection: true
            minimum_rssi: -71
            transient_interval: 300
            report_interval: 60
            pmf_denial: false
          mesh_enabled: true
          mesh_settings:
            range: 1000
            backhaul_client_access: true
            rap_downlink_backhaul: "2.4 GHz"
            ghz_2_point_4_radio_band_type: "802.11n"
            bridge_group_name: "Bridge1"
          power_settings:
            ap_power_profile_name: "ada"
            calendar_power_profiles:
              - ap_power_profile_name: "sdfd"
                scheduler_type: "MONTHLY"
                scheduler_dates_list: ["2", "9", "28"]
                scheduler_start_time: "08:00 AM"
                scheduler_end_time: "6:00 PM"

        - access_point_profile_name: "Profile-test25"
          country_code: "India"

        - access_point_profile_name: "Profile-test26"
          country_code: "Australia"
          time_zone: "NOT CONFIGURED"
          maximum_client_limit: 500

        - access_point_profile_name: "Profile-test27"
          time_zone: "CONTROLLER"
          maximum_client_limit: 1100

        - access_point_profile_name: "Profile-test28"
          time_zone: "DELTA FROM CONTROLLER"
          time_zone_offset_hour: -11
          time_zone_offset_minutes: 30
          maximum_client_limit: 900

        - access_point_profile_name: "Profile-test29"
          access_point_profile_description: "Main office AP profile 29"
          management_settings:
            access_point_authentication: "EAP-PEAP"
            dot1x_username: "user1"
            dot1x_password: "asdfasdfasdfsdf"
            ssh_enabled: false
            telnet_enabled: true
            management_username: "admin"
            management_password: "securePass"
            management_enable_password: "adflmlssf"
          security_settings:
            awips: true
            awips_forensic: false
            rogue_detection: true
            minimum_rssi: -71
            transient_interval: 300
            report_interval: 60
            pmf_denial: false
          mesh_enabled: true
          mesh_settings:
            range: 1000
            backhaul_client_access: true
            rap_downlink_backhaul: "2.4 GHz"
            ghz_2_point_4_radio_band_type: "802.11n"
            bridge_group_name: "Bridge1"
          power_settings:
            ap_power_profile_name: "ada"
            calendar_power_profiles:
              - ap_power_profile_name: "sdfd"
                scheduler_type: "DAILY"
                scheduler_start_time: "08:00 AM"
                scheduler_end_time: "6:00 PM"
          country_code: "Australia"
          time_zone: "NOT CONFIGURED"
          maximum_client_limit: 500

        - access_point_profile_name: "Profile-test30"
          access_point_profile_description: "Main office AP profile 30"
          management_settings:
            access_point_authentication: "EAP-PEAP"
            dot1x_username: "user1"
            dot1x_password: "asdfasdfasdfsdf"
            ssh_enabled: false
            telnet_enabled: true
            management_username: "admin"
            management_password: "securePass"
            management_enable_password: "adflmlssf"
          security_settings:
            awips: true
            awips_forensic: false
            rogue_detection: true
            minimum_rssi: -71
            transient_interval: 300
            report_interval: 60
            pmf_denial: false
          mesh_enabled: true
          mesh_settings:
            range: 1000
            backhaul_client_access: true
            rap_downlink_backhaul: "2.4 GHz"
            ghz_2_point_4_radio_band_type: "802.11n"
            bridge_group_name: "Bridge1"
          power_settings:
            ap_power_profile_name: "ada"
            calendar_power_profiles:
              - ap_power_profile_name: "sdfd"
                scheduler_type: "WEEKLY"
                scheduler_days_list: ["monday", "tuesday"]
                scheduler_start_time: "08:00 AM"
                scheduler_end_time: "6:00 PM"
          time_zone: "CONTROLLER"
          maximum_client_limit: 1100

        - access_point_profile_name: "Profile-test31"
          access_point_profile_description: "Main office AP profile 31"
          management_settings:
            access_point_authentication: "EAP-PEAP"
            dot1x_username: "user1"
            dot1x_password: "asdfasdfasdfsdf"
            ssh_enabled: false
            telnet_enabled: true
            management_username: "admin"
            management_password: "securePass"
            management_enable_password: "adflmlssf"
          security_settings:
            awips: true
            awips_forensic: false
            rogue_detection: true
            minimum_rssi: -71
            transient_interval: 300
            report_interval: 60
            pmf_denial: false
          mesh_enabled: true
          mesh_settings:
            range: 1000
            backhaul_client_access: true
            rap_downlink_backhaul: "2.4 GHz"
            ghz_2_point_4_radio_band_type: "802.11n"
            bridge_group_name: "Bridge1"
          power_settings:
            ap_power_profile_name: "ada"
            calendar_power_profiles:
              - ap_power_profile_name: "sdfd"
                scheduler_type: "MONTHLY"
                scheduler_dates_list: ["2", "9", "28"]
                scheduler_start_time: "08:00 AM"
                scheduler_end_time: "6:00 PM"
          time_zone: "DELTA FROM CONTROLLER"
          time_zone_offset_hour: -11
          time_zone_offset_minutes: 30
          maximum_client_limit: 900

        - access_point_profile_name: "Profile-test33"
          access_point_profile_description: "Main office AP profile 31"
          management_settings:
            access_point_authentication: "EAP-PEAP"
            dot1x_username: "user1"
            dot1x_password: "asdfasdfasdfsdf"
            ssh_enabled: false
            telnet_enabled: true
            management_username: "admin"
            management_password: "securePass"
            management_enable_password: "adflmlssf"
          security_settings:
            awips: true
            awips_forensic: false
            rogue_detection: true
            minimum_rssi: -71
            transient_interval: 300
            report_interval: 60
            pmf_denial: false
          mesh_enabled: false
          mesh_settings:
            range: 1000
            backhaul_client_access: true
            rap_downlink_backhaul: "2.4 GHz"
            ghz_2_point_4_radio_band_type: "802.11n"
            bridge_group_name: "Bridge1"
          power_settings:
            ap_power_profile_name: "ada"
            calendar_power_profiles:
              - ap_power_profile_name: "sdfd"
                scheduler_type: "MONTHLY"
                scheduler_dates_list: ["2", "9", "28"]
                scheduler_start_time: "08:00 AM"
                scheduler_end_time: "6:00 PM"
          time_zone: "DELTA FROM CONTROLLER"
          time_zone_offset_hour: -11
          time_zone_offset_minutes: 30
          maximum_client_limit: 900

- name: Update Access Point Profiles
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - access_point_profiles:
        - access_point_profile_name: "Profile-test1"
          access_point_profile_description: "Main office AP profile 1"
          management_settings:
            access_point_authentication: "EAP-PEAP"
            dot1x_username: "user1"
            dot1x_password: "asdfasdfasdfsdf"
            ssh_enabled: false
            telnet_enabled: true
            management_username: "admin"
            management_password: "securePass"
            management_enable_password: "adflmlssf"
          security_settings:
            awips: true
            awips_forensic: false
            rogue_detection: true
            minimum_rssi: -71
            transient_interval: 300
            report_interval: 60
            pmf_denial: false
          mesh_enabled: true
          mesh_settings:
            range: 1000
            backhaul_client_access: true
            rap_downlink_backhaul: "2.4 GHz"
            ghz_2_point_4_radio_band_type: "802.11n"
            bridge_group_name: "Bridge1"
          power_settings:
            ap_power_profile_name: "ada"
            calendar_power_profiles:
              - ap_power_profile_name: "sdfd"
                scheduler_type: "MONTHLY"
                scheduler_dates_list: ["2", "9", "28"]
                scheduler_start_time: "08:00 AM"
                scheduler_end_time: "6:00 PM"
          time_zone: "DELTA FROM CONTROLLER"
          time_zone_offset_hour: -11
          time_zone_offset_minutes: 30
          maximum_client_limit: 900


        - access_point_profile_name: "Profile-test31"

        - access_point_profile_name: "Profile-test30"

        - access_point_profile_name: "Profile-test29"

        - access_point_profile_name: "Profile-test24"
          access_point_profile_description: "Main office AP profile 24"
          management_settings:
            access_point_authentication: "EAP-PEAP"
            dot1x_username: "user1"
            dot1x_password: "asdfasdfasdfsdf"
            ssh_enabled: false
            telnet_enabled: true
            management_username: "admin"
            management_password: "securePasfsdfs"
            management_enable_password: "adflmlsdsfdfdf"
          security_settings:
            awips: true
            awips_forensic: false
            rogue_detection: true
            minimum_rssi: -71
            transient_interval: 300
            report_interval: 60
            pmf_denial: false
          mesh_enabled: true
          mesh_settings:
            range: 1000
            backhaul_client_access: true
            rap_downlink_backhaul: "2.4 GHz"
            ghz_2_point_4_radio_band_type: "802.11n"
            bridge_group_name: "Bridge1"
          power_settings:
            ap_power_profile_name: "ada"
            calendar_power_profiles:
              - ap_power_profile_name: "sdfd"
                scheduler_type: "MONTHLY"
                scheduler_dates_list: ["2", "9", "28"]
                scheduler_start_time: "08:00 AM"
                scheduler_end_time: "6:00 PM"

        - access_point_profile_name: "Profile-test23"
          mesh_enabled: true
          mesh_settings:
            range: 1001

        - access_point_profile_name: "Profile-test22"
          power_settings:
            calendar_power_profiles:
              - ap_power_profile_name: "ada"
                scheduler_type: "DAILY"
                scheduler_start_time: "10:00 AM"
                scheduler_end_time: "6:00 PM"

        - access_point_profile_name: "Profile-test28"
          time_zone: "CONTROLLER"
          time_zone_offset_hour: 0
          time_zone_offset_minutes: 0
          maximum_client_limit: 900

        - access_point_profile_name: "Profile-test2"
          access_point_profile_description: "Updated Main office AP profile 2"

        - access_point_profile_name: "Profile-test3"
          access_point_profile_description: "Updated Main office AP profile 3"
          management_settings:
            access_point_authentication: "EAP-TLS"

- name: Delete Access Point Profiles
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config:
      - access_point_profiles:
        - access_point_profile_name: "Profile-test1"
        - access_point_profile_name: "Profile-test2"
        - access_point_profile_name: "Profile-test3"
        - access_point_profile_name: "Profile-test4"
        - access_point_profile_name: "Profile-test5"
        - access_point_profile_name: "Profile-test6"
        - access_point_profile_name: "Profile-test7"
        - access_point_profile_name: "Profile-test8"
        - access_point_profile_name: "Profile-test9"
        - access_point_profile_name: "Profile-test10"
        - access_point_profile_name: "Profile-test11"
        - access_point_profile_name: "Profile-test12"
        - access_point_profile_name: "Profile-test13"
        - access_point_profile_name: "Profile-test14"
        - access_point_profile_name: "Profile-test15"
        - access_point_profile_name: "Profile-test16"
        - access_point_profile_name: "Profile-test17"
        - access_point_profile_name: "Profile-test18"
        - access_point_profile_name: "Profile-test19"
        - access_point_profile_name: "Profile-test20"
        - access_point_profile_name: "Profile-test21"
        - access_point_profile_name: "Profile-test22"
        - access_point_profile_name: "Profile-test23"
        - access_point_profile_name: "Profile-test24"
        - access_point_profile_name: "Profile-test25"
        - access_point_profile_name: "Profile-test26"
        - access_point_profile_name: "Profile-test27"
        - access_point_profile_name: "Profile-test28"
        - access_point_profile_name: "Profile-test29"
        - access_point_profile_name: "Profile-test30"
        - access_point_profile_name: "Profile-test31"
        - access_point_profile_name: "Profile-test32"
        - access_point_profile_name: "Profile-test33"

- name: Add Radio Frequency Profiles
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: '{{dnac_host}}'
    dnac_username: '{{dnac_username}}'
    dnac_password: '{{dnac_password}}'
    dnac_verify: '{{dnac_verify}}'
    dnac_port: '{{dnac_port}}'
    dnac_version: '{{dnac_version}}'
    dnac_debug: '{{dnac_debug}}'
    dnac_log: true
    dnac_log_level: '{{dnac_log_level}}'
    state: merged
    config:
      - radio_frequency_profiles:
        - radio_frequency_profile_name: "profile-test1"
          default_rf_profile: false
          radio_bands: [2.4]

        - radio_frequency_profile_name: "profile-test2"
          default_rf_profile: false
          radio_bands: [5]

        - radio_frequency_profile_name: "profile-test3"
          default_rf_profile: false
          radio_bands: [6]

        - radio_frequency_profile_name: "profile-test4"
          default_rf_profile: false
          radio_bands: [2.4]
          radio_bands_2_4ghz_settings:
            dca_channels_list: [1, 6, 11]
            suppported_data_rates_list: [11, 12, 18, 2, 24, 36, 48, 5.5, 54, 6, 9]
            mandatory_data_rates_list: [2, 11]
            parent_profile: "HIGH"

        - radio_frequency_profile_name: "profile-test5"
          default_rf_profile: false
          radio_bands: [5]
          radio_bands_5ghz_settings:
            channel_width: "160"
            dca_channels_list:  [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128]
            suppported_data_rates_list: [12,18,24,36,48,54]
            mandatory_data_rates_list: [24]
            parent_profile: "TYPICAL"

        - radio_frequency_profile_name: "profile-test6"
          default_rf_profile: false
          radio_bands: [6]
          radio_bands_6ghz_settings:
            dca_channels_list: [13, 17, 21, 25, 29, 33, 37, 41]
            suppported_data_rates_list: [6,9,12,18,24,36,48,54]
            mandatory_data_rates_list: [6,9]
            parent_profile: "CUSTOM"
            minimum_dbs_channel_width: 20
            maximum_dbs_channel_width: 160

        - radio_frequency_profile_name: "profile-test7"
          default_rf_profile: false
          radio_bands: [2.4]
          radio_bands_2_4ghz_settings:
            parent_profile: "CUSTOM"
            minimum_power_level: 5
            maximum_power_level: 20
            rx_sop_threshold: "MEDIUM"

        - radio_frequency_profile_name: "profile-test8"
          default_rf_profile: false
          radio_bands: [5]
          radio_bands_5ghz_settings:
            parent_profile: "HIGH"
            zero_wait_dfs: true
            client_limit: 50

        - radio_frequency_profile_name: "profile-test9"
          default_rf_profile: false
          radio_bands: [6]
          radio_bands_6ghz_settings:
            parent_profile: "CUSTOM"
            psc_enforcing_enabled: true
            discovery_frames_6ghz: "Broadcast Probe Response"

        - radio_frequency_profile_name: "profile-test10"
          default_rf_profile: false
          radio_bands: [2.4, 5]
          radio_bands_2_4ghz_settings:
            parent_profile: "TYPICAL"
            minimum_power_level: 5
            maximum_power_level: 20
          radio_bands_5ghz_settings:
            parent_profile: "TYPICAL"
            channel_width: "20"
            zero_wait_dfs: true

        - radio_frequency_profile_name: "profile-test11"
          default_rf_profile: false
          radio_bands: [5, 6]
          radio_bands_5ghz_settings:
            parent_profile: "LOW"
            preamble_puncturing: false
            client_limit: 100
          radio_bands_6ghz_settings:
            parent_profile: "CUSTOM"
            psc_enforcing_enabled: true
            maximum_dbs_channel_width: 160
            discovery_frames_6ghz: "None"

        - radio_frequency_profile_name: "profile-test12"
          default_rf_profile: false
          radio_bands: [2.4, 6]
          radio_bands_2_4ghz_settings:
            parent_profile: "CUSTOM"
            minimum_power_level: 5
            maximum_power_level: 20
            rx_sop_threshold: "HIGH"
          radio_bands_6ghz_settings:
            parent_profile: "CUSTOM"
            minimum_dbs_channel_width: 20
            maximum_dbs_channel_width: 80

        - radio_frequency_profile_name: "profile-test13"
          default_rf_profile: false
          radio_bands: [2.4, 5, 6]
          radio_bands_2_4ghz_settings:
            parent_profile: "HIGH"
            minimum_power_level: 5
            maximum_power_level: 20
          radio_bands_5ghz_settings:
            parent_profile: "LOW"
            channel_width: "80"
          radio_bands_6ghz_settings:
            parent_profile: "CUSTOM"
            maximum_dbs_channel_width: 160

        - radio_frequency_profile_name: "profile-test14"
          default_rf_profile: false
          radio_bands: [2.4, 5, 6]
          radio_bands_2_4ghz_settings:
            parent_profile: "HIGH"
            spatial_resuse:
              non_srg_obss_pd: true
              non_srg_obss_pd_max_threshold: -63
          radio_bands_5ghz_settings:
            parent_profile: "LOW"
            flexible_radio_assigment:
              client_aware: true
              client_reset: 5
          radio_bands_6ghz_settings:
            parent_profile: "CUSTOM"
            multi_bssid:
              dot_11be_parameters:
                ofdma_downlink: true
                mu_mimo_downlink: true

        - radio_frequency_profile_name: "profile-test15"
          default_rf_profile: false
          radio_bands: [5, 6]
          radio_bands_5ghz_settings:
            parent_profile: "HIGH"
            zero_wait_dfs: true
            client_limit: 200
          radio_bands_6ghz_settings:
            parent_profile: "CUSTOM"
            broadcast_probe_response_interval: 20


        - radio_frequency_profile_name: "profile-test16"
          default_rf_profile: false
          radio_bands: [6]
          radio_bands_6ghz_settings:
            parent_profile: "CUSTOM"
            multi_bssid:
              target_waketime: true
              twt_broadcast_support: true


        - radio_frequency_profile_name: "profile-test17"
          default_rf_profile: false
          radio_bands: [2.4, 5, 6]
          radio_bands_2_4ghz_settings:
            parent_profile: "LOW"
            dca_channels_list: [1, 6, 11]
            suppported_data_rates_list: [1, 11, 12, 18, 2, 24, 36, 48, 5.5, 54, 6, 9]
            mandatory_data_rates_list: [1, 2]
            minimum_power_level: 3
            maximum_power_level: 20
            rx_sop_threshold: "LOW"
            tpc_power_threshold: -65
            coverage_hole_detection:
              minimum_client_level: 3
              data_rssi_threshold: -80
              voice_rssi_threshold: -75
              exception_level: 5
            client_limit: 50
            spatial_resuse:
              non_srg_obss_pd: true
              non_srg_obss_pd_max_threshold: -63
              srg_obss_pd: true
              srg_obss_pd_min_threshold: -63
              srg_obss_pd_max_threshold: -62
          radio_bands_5ghz_settings:
            parent_profile: "TYPICAL"
            channel_width: "80"
            preamble_puncturing: false
            zero_wait_dfs: true
            dca_channels_list: [36, 40, 44, 48]
            suppported_data_rates_list: [6, 9, 12, 18, 24, 36, 48, 54]
            mandatory_data_rates_list: [6]
            minimum_power_level: 5
            maximum_power_level: 30
            rx_sop_threshold: "HIGH"
            tpc_power_threshold: -70
            coverage_hole_detection:
              minimum_client_level: 4
              data_rssi_threshold: -75
              voice_rssi_threshold: -70
              exception_level: 4
            client_limit: 100
            flexible_radio_assigment:
              client_aware: true
              client_select: 30
              client_reset: 10
            spatial_resuse:
              non_srg_obss_pd: true
              non_srg_obss_pd_max_threshold: -63
              srg_obss_pd: true
              srg_obss_pd_min_threshold: -63
              srg_obss_pd_max_threshold: -62
          radio_bands_6ghz_settings:
            parent_profile: "CUSTOM"
            minimum_dbs_channel_width: 20
            maximum_dbs_channel_width: 160
            preamble_puncturing: true
            psc_enforcing_enabled: true
            dca_channels_list: [37, 53, 69, 85]
            suppported_data_rates_list: [12, 18, 24, 36, 48, 54, 6, 9]
            mandatory_data_rates_list: [6, 12]
            minimum_power_level: 10
            maximum_power_level: 30
            rx_sop_threshold: "CUSTOM"
            custom_rx_sop_threshold: -80
            tpc_power_threshold: -60
            coverage_hole_detection:
              minimum_client_level: 5
              data_rssi_threshold: -72
              voice_rssi_threshold: -68
              exception_level: 6
            client_limit: 150
            flexible_radio_assigment:
              client_reset_count: 10
              client_utilization_threshold: 10
            discovery_frames_6ghz: "FILS Discovery"
            broadcast_probe_response_interval: 10
            standard_power_service: false
            multi_bssid:
              dot_11ax_parameters:
                ofdma_downlink: true
                ofdma_uplink: true
                mu_mimo_downlink: true
                mu_mimodownlink: false
              dot_11be_parameters:
                ofdma_downlink: true
                ofdma_uplink: true
                mu_mimo_downlink: true
                mu_mimodownlink: true
                ofdma_multi_ru: true
              target_waketime: true
              twt_broadcast_support: true
            spatial_resuse:
              non_srg_obss_pd: true
              non_srg_obss_pd_max_threshold: -63
              srg_obss_pd: true
              srg_obss_pd_min_threshold: -63
              srg_obss_pd_max_threshold: -62

- name: Update Radio Frequency Profiles
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: '{{dnac_host}}'
    dnac_username: '{{dnac_username}}'
    dnac_password: '{{dnac_password}}'
    dnac_verify: '{{dnac_verify}}'
    dnac_port: '{{dnac_port}}'
    dnac_version: '{{dnac_version}}'
    dnac_debug: '{{dnac_debug}}'
    dnac_log: true
    dnac_log_level: '{{dnac_log_level}}'
    state: merged
    config:
      - radio_frequency_profiles:
          - radio_frequency_profile_name: profile-test1
            default_rf_profile: false
            radio_bands: [2.4]
            radio_bands_2_4ghz_settings:
              parent_profile: LOW
              minimum_power_level: 3
              maximum_power_level: 15

          - radio_frequency_profile_name: profile-test2
            default_rf_profile: false
            radio_bands: [5]
            radio_bands_5ghz_settings:
              parent_profile: TYPICAL
              channel_width: '40'
              zero_wait_dfs: false

          - radio_frequency_profile_name: profile-test3
            default_rf_profile: false
            radio_bands: [6]
            radio_bands_6ghz_settings:
              parent_profile: CUSTOM
              minimum_dbs_channel_width: 40
              maximum_dbs_channel_width: 80

          - radio_frequency_profile_name: profile-test4
            default_rf_profile: false
            radio_bands: [2.4]
            radio_bands_2_4ghz_settings:
              dca_channels_list: [1, 6]
              suppported_data_rates_list: [1, 11, 12, 18, 2, 24, 36, 48, 5.5, 54, 6, 9]
              mandatory_data_rates_list: [12]
              parent_profile: TYPICAL

          - radio_frequency_profile_name: profile-test5
            default_rf_profile: false
            radio_bands: [5]
            radio_bands_5ghz_settings:
              channel_width: '80'
              dca_channels_list: [52, 56, 60, 64]
              suppported_data_rates_list: [18, 24, 36, 48, 54]
              mandatory_data_rates_list: [24]
              parent_profile: HIGH

          - radio_frequency_profile_name: profile-test7
            default_rf_profile: false
            radio_bands: [2.4]
            radio_bands_2_4ghz_settings:
              parent_profile: LOW
              minimum_power_level: 1
              maximum_power_level: 10

          - radio_frequency_profile_name: profile-test8
            default_rf_profile: false
            radio_bands: [5]
            radio_bands_5ghz_settings:
              parent_profile: TYPICAL
              channel_width: '20'
              zero_wait_dfs: true

          - radio_frequency_profile_name: profile-test9
            default_rf_profile: false
            radio_bands: [6]
            radio_bands_6ghz_settings:
              parent_profile: CUSTOM
              minimum_dbs_channel_width: 20
              maximum_dbs_channel_width: 40

          - radio_frequency_profile_name: profile-test11
            default_rf_profile: false
            radio_bands: [5]
            radio_bands_5ghz_settings:
              channel_width: '160'
              dca_channels_list: [36, 40, 44, 48, 52, 56, 60, 64]
              suppported_data_rates_list: [12, 24, 36, 48, 6, 18, 9, 54]
              mandatory_data_rates_list: [24]
              parent_profile: TYPICAL

          - radio_frequency_profile_name: profile-test12
            default_rf_profile: false
            radio_bands: [6]
            radio_bands_6ghz_settings:
              dca_channels_list: [1, 129, 5, 133, 9, 137, 13, 141, 17, 145]
              suppported_data_rates_list: [12, 18, 24, 36, 48, 54, 6, 9]
              mandatory_data_rates_list: [6, 12]
              parent_profile: CUSTOM
              minimum_dbs_channel_width: 40
              maximum_dbs_channel_width: 80

          - radio_frequency_profile_name: profile-test13
            default_rf_profile: false
            radio_bands: [2.4]
            radio_bands_2_4ghz_settings:
              parent_profile: TYPICAL
              minimum_power_level: 2
              maximum_power_level: 12

          - radio_frequency_profile_name: profile-test14
            default_rf_profile: false
            radio_bands: [5]
            radio_bands_5ghz_settings:
              parent_profile: CUSTOM
              channel_width: '40'
              zero_wait_dfs: false

          - radio_frequency_profile_name: profile-test17
            default_rf_profile: false
            radio_bands: [5]
            radio_bands_5ghz_settings:
              channel_width: '20'
              dca_channels_list: [36, 44, 48]
              suppported_data_rates_list: [12, 24, 36, 48, 6, 18, 9, 54]
              mandatory_data_rates_list: [24]
              parent_profile: LOW


- name: Delete Radio Frequency Profiles
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: '{{dnac_host}}'
    dnac_username: '{{dnac_username}}'
    dnac_password: '{{dnac_password}}'
    dnac_verify: '{{dnac_verify}}'
    dnac_port: '{{dnac_port}}'
    dnac_version: '{{dnac_version}}'
    dnac_debug: '{{dnac_debug}}'
    dnac_log: true
    dnac_log_level: '{{dnac_log_level}}'
    state: merged
    config:
      - radio_frequency_profiles:
        - radio_frequency_profile_name: profile-test1
        - radio_frequency_profile_name: profile-test2
        - radio_frequency_profile_name: profile-test3
        - radio_frequency_profile_name: profile-test4
        - radio_frequency_profile_name: profile-test5
        - radio_frequency_profile_name: profile-test6
        - radio_frequency_profile_name: profile-test7
        - radio_frequency_profile_name: profile-test8
        - radio_frequency_profile_name: profile-test9
        - radio_frequency_profile_name: profile-test10
        - radio_frequency_profile_name: profile-test11
        - radio_frequency_profile_name: profile-test12
        - radio_frequency_profile_name: profile-test13
        - radio_frequency_profile_name: profile-test14
        - radio_frequency_profile_name: profile-test15
        - radio_frequency_profile_name: profile-test16
        - radio_frequency_profile_name: profile-test17

- name: Add Anchor Groups
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: '{{dnac_host}}'
    dnac_username: '{{dnac_username}}'
    dnac_password: '{{dnac_password}}'
    dnac_verify: '{{dnac_verify}}'
    dnac_port: '{{dnac_port}}'
    dnac_version: '{{dnac_version}}'
    dnac_debug: '{{dnac_debug}}'
    dnac_log: true
    dnac_log_level: '{{dnac_log_level}}'
    state: merged
    config:
      - anchor_groups:
          - anchor_group_name: AnchorGroup1
            mobility_anchors:
              - device_name: Device1
                device_ip_address: 192.168.0.10
                device_mac_address: '00:1A:2B:3C:4D:5E'
                device_type: IOS-XE
                device_priority: 1
                device_nat_ip_address: 10.0.0.10
                mobility_group_name: Group1
                managed_device: false
              - device_name: Device2
                device_ip_address: 192.168.0.11
                device_mac_address: '00:1A:2B:3C:4D:5F'
                device_type: AIREOS
                device_priority: 2
                device_nat_ip_address: 10.0.0.11
                mobility_group_name: Group2
                managed_device: false
          - anchor_group_name: AnchorGroup2
            mobility_anchors:
              - device_name: Device1
                device_ip_address: 192.168.0.10
                device_mac_address: '00:1A:2B:3C:4D:5E'
                device_type: IOS-XE
                device_priority: 1
                device_nat_ip_address: 10.0.0.10
                mobility_group_name: Group1
                managed_device: false
              - device_name: Device2
                device_ip_address: 192.168.0.11
                device_mac_address: '00:1A:2B:3C:4D:5F'
                device_type: AIREOS
                device_priority: 2
                device_nat_ip_address: 10.0.0.11
                mobility_group_name: Group2
                managed_device: false
          - anchor_group_name: AnchorGroup3
            mobility_anchors:
              - device_name: Device1
                device_ip_address: 192.168.0.10
                device_mac_address: '00:1A:2B:3C:4D:5E'
                device_type: IOS-XE
                device_priority: 1
                device_nat_ip_address: 10.0.0.10
                mobility_group_name: Group1
                managed_device: false
              - device_name: Device2
                device_ip_address: 192.168.0.11
                device_mac_address: '00:1A:2B:3C:4D:5F'
                device_type: AIREOS
                device_priority: 2
                device_nat_ip_address: 10.0.0.11
                mobility_group_name: Group2
                managed_device: false

- name: Update Anchor Groups
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: '{{dnac_host}}'
    dnac_username: '{{dnac_username}}'
    dnac_password: '{{dnac_password}}'
    dnac_verify: '{{dnac_verify}}'
    dnac_port: '{{dnac_port}}'
    dnac_version: '{{dnac_version}}'
    dnac_debug: '{{dnac_debug}}'
    dnac_log: true
    dnac_log_level: '{{dnac_log_level}}'
    state: merged
    config:
      - anchor_groups:
          - anchor_group_name: AnchorGroup1
            mobility_anchors:
              - device_name: Device1
                device_ip_address: 192.168.0.10
                device_mac_address: '00:1A:2B:3C:4D:5E'
                device_type: IOS-XE
                device_priority: 1
                device_nat_ip_address: 10.0.0.10
                mobility_group_name: Group1
                managed_device: false
              - device_name: Device2
                device_ip_address: 192.168.0.11
                device_mac_address: '00:1A:2B:3C:4D:5F'
                device_type: AIREOS
                device_priority: 3
                device_nat_ip_address: 10.0.0.11
                mobility_group_name: Group2
                managed_device: false

          - anchor_group_name: AnchorGroup2
            mobility_anchors:
              - device_name: Device1
                device_ip_address: 192.168.0.10
                device_mac_address: '00:1A:2B:3C:4D:5E'
                device_type: IOS-XE
                device_priority: 1
                device_nat_ip_address: 10.0.0.10
                mobility_group_name: Group1
                managed_device: false
              - device_name: Device2
                device_ip_address: 192.168.0.11
                device_mac_address: '00:1A:2B:3C:4D:5F'
                device_type: AIREOS
                device_priority: 3
                device_nat_ip_address: 10.0.0.11
                mobility_group_name: Group2
                managed_device: false
              - device_name: NY-IAC-EWLC.cisco.local
                device_ip_address: 204.192.6.200
                device_priority: 2
                managed_device: true

          - anchor_group_name: AnchorGroup3
            mobility_anchors:
              - device_name: Device1
                device_ip_address: 192.168.0.10
                device_mac_address: '00:1A:2B:3C:4D:5E'
                device_type: IOS-XE
                device_priority: 2
                device_nat_ip_address: 10.0.0.10
                mobility_group_name: Group1
                managed_device: false

- name: Delete Anchor Groups
  cisco.dnac.wireless_design_workflow_manager:
    dnac_host: '{{dnac_host}}'
    dnac_username: '{{dnac_username}}'
    dnac_password: '{{dnac_password}}'
    dnac_verify: '{{dnac_verify}}'
    dnac_port: '{{dnac_port}}'
    dnac_version: '{{dnac_version}}'
    dnac_debug: '{{dnac_debug}}'
    dnac_log: true
    dnac_log_level: '{{dnac_log_level}}'
    state: merged
    config:
      - anchor_groups:
          - anchor_group_name: AnchorGroup1
          - anchor_group_name: AnchorGroup2
          - anchor_group_name: AnchorGroup3
"""

RETURN = r"""
# Case_1: Success Scenario
response_1:
  description: A dictionary with  with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response":
        {
          "response": String,
          "version": String
        },
      "msg": String
    }

# Case_2: Error Scenario
response_2:
  description: A string with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: list
  sample: >
    {
      "response": [],
      "msg": String
    }
"""
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts
)
import re


class WirelessDesign(DnacBase):
    """
    A class for managing Wireless Design operations within the Cisco DNA Center using the SDA API.
    """
    def __init__(self, module):
        """
        Initialize an instance of the class.
        Args:
          - module: The module associated with the class instance.
        Returns:
          The method does not return a value.
        """
        super().__init__(module)

    def validate_input(self):
        """
        Validates the input configuration parameters for the playbook.
        Returns:
            object: An instance of the class with updated attributes:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation (either "success" or "failed").
                - self.validated_config: If successful, a validated version of the "config" parameter.
        """
        # Log the start of the validation process
        self.log("Starting validation of input configuration parameters.", "DEBUG")

        # Check if configuration is available
        if not self.config:
            self.status = "success"
            self.msg = "Configuration is not available in the playbook for validation"
            self.log(self.msg, "ERROR")
            return self

        # Expected schema for configuration parameters
        temp_spec = {
            "ssids": {
                "type": "list",
                "elements": "dict",
                "required": False,
                "options": {
                    "ssid_name": {"type": "str"},
                    "ssid_type": {"type": "str"},
                    "wlan_profile_name": {"type": "str"},
                    "radio_policy": {
                        "type": "dict",
                        "radio_bands": {"type": "list"},
                        "2_dot_4_ghz_band_policy": {"type": "str"},
                        "band_select": {"type": 'bool'},
                        "6_ghz_client_steering": {"type": 'bool'},
                    },
                    "fast_lane": {"type": 'bool'},
                    "quality_of_service": {
                        "type": "dict",
                        "egress": {"type": "str"},
                        "ingress": {"type": "str"},
                    },
                    "ssid_state": {
                        "type": "dict",
                        "admin_status": {"type": 'bool'},
                        "broadcast_ssid": {"type": 'bool'},
                    },
                    "l2_security": {
                        "type": "dict",
                        "l2_auth_type": {"type": "str"},
                        "ap_beacon_protection": {"type": 'bool'},
                        "open_ssid": {"type": "str"},
                        "passphrase_type": {"type": "str"},
                        "passphrase": {"type": "str"},
                        "mpsk_settings": {
                            "type": "list",
                            "elements": "dict",
                            "options": {
                                "mpsk_priority": {"type": "int"},
                                "mpsk_passphrase_type": {"type": "str"},
                                "mpsk_passphrase": {"type": "str"},
                            }
                        }
                    },
                    "fast_transition": {"type": "str"},
                    "fast_transition_over_the_ds": {"type": 'bool'},
                    "wpa_encryption": {"type": "str"},
                    "auth_key_management": {"type": "list"},
                    "cckm_timestamp_tolerance": {"type": "int"},
                    "l3_security": {
                        "type": "dict",
                        "l3_auth_type": {"type": "str"},
                        "auth_server": {"type": "str"},
                        "web_auth_url": {"type": "str"},
                        "enable_sleeping_client": {"type": 'bool'},
                        "sleeping_client_timeout": {"type": "int"},
                    },
                    "aaa": {
                        "type": "dict",
                        "auth_servers_ip_address_list": {"type": "list"},
                        "accounting_servers_ip_address_list": {"type": "list"},
                        "aaa_override": {"type": 'bool'},
                        # "identity_psk": {"type": 'bool'},
                        "mac_filtering": {"type": 'bool'},
                        "deny_rcm_clients": {"type": 'bool'},
                        "enable_posture": {"type": 'bool'},
                        "pre_auth_acl_name": {"type": "str"},
                    },
                    "mfp_client_protection": {"type": "str"},
                    "protected_management_frame": {"type": "str"},
                    "11k_neighbor_list": {"type": "str"},
                    "coverage_hole_detection": {"type": 'bool'},
                    "wlan_timeouts": {
                        "type": "dict",
                        "enable_session_timeout": {"type": 'bool'},
                        "session_timeout": {"type": "int"},
                        "enable_client_execlusion_timeout": {"type": 'bool'},
                        "client_execlusion_timeout": {"type": "int"},
                    },
                    "bss_transition_support": {
                        "type": "dict",
                        "bss_max_idle_service": {"type": 'bool'},
                        "bss_idle_client_timeout": {"type": "int"},
                        "directed_multicast_service": {"type": 'bool'},
                    },
                    "nas_id": {"type": "list"},
                    "client_rate_limit": {"type": "int"},
                    "sites_specifc_override_settings": {
                        "type": "list",
                        "elements": "dict",
                        "required": False,
                        "options": {
                            "site_name_hierarchy": {"type": "str"},
                            "wlan_profile_name": {"type": "str"},
                            "l2_security": {
                                "type": "dict",
                                "l2_auth_type": {"type": "str"},
                                "open_ssid": {"type": "str"},
                                "passphrase": {"type": "str"},
                                "mpsk_settings:": {
                                    "type": "list",
                                    "elements": "dict",
                                    "options": {
                                        "mpsk_priority": {"type": "int"},
                                        "mpsk_passphrase_type": {"type": "str"},
                                        "mpsk_passphrase": {"type": "str"},
                                    }
                                },
                            },
                            "fast_transition": {"type": "str"},
                            "fast_transition_over_the_ds": {"type": 'bool'},
                            "wpa_encryption": {"type": "str"},
                            "auth_key_management": {"type": "list"},
                            "aaa": {
                                "type": "dict",
                                "auth_servers_ip_address_list": {"type": "list"},
                                "accounting_servers_ip_address_list": {"type": "list"},
                                "aaa_override": {"type": 'bool'},
                                "mac_filtering": {"type": 'bool'}
                            },
                            "protected_management_frame": {"type": "str"},
                            "nas_id": {"type": "list"},
                            "client_rate_limit": {"type": "int"},
                            "remove_override_in_hierarchy": {"type": "bool"}
                        }
                    }
                }
            },
            "interfaces": {
                "type": "list",
                "elements": "dict",
                "required": False,
                "options": {
                    "interface_name": {"type": "str"},
                    "vlan_id": {"type": "int"}
                }
            },
            "power_profiles": {
                "type": "list",
                "elements": "dict",
                "required": False,
                "options": {
                    "power_profile_name": {"type": "str"},
                    "power_profile_description": {"type": "str"},
                    "rules": {
                        "type": "list",
                        "elements": "dict",
                        "required": False,
                        "options": {
                            "interface_type": {"type": "str"},
                            "interface_id": {"type": "str"},
                            "parameter_type": {"type": "str"},
                            "parameter_value": {"type": "str"}
                        }
                    }
                }
            },
            "access_point_profiles": {
                "type": "list",
                "elements": "dict",
                "required": False,
                "options": {
                    "access_point_profile_name": {"type": "str"},
                    "access_point_profile_description": {"type": "str"},
                    # "device_type": {"type": "str"},
                    "remote_teleworker": {"type": "bool"},
                    "management_settings": {
                        "type": "dict",
                        "access_point_authentication": {"type": "str"},
                        "dot1x_username": {"type": "str"},
                        "dot1x_password": {"type": "str"},
                        "ssh_enabled": {"type": "bool"},
                        "telnet_enabled": {"type": "bool"},
                        "management_username": {"type": "str"},
                        "management_password": {"type": "str"},
                        "management_enable_password": {"type": "str"},
                        "cdp_state": {"type": "bool"},
                    },
                    "security_settings": {
                        "type": "dict",
                        "awips": {"type": "bool"},
                        "awips_forensic": {"type": "bool"},
                        "rogue_detection_enabled": {"type": "bool"},
                        "minimum_rssi": {"type": "int"},
                        "transient_interval": {"type": "int"},
                        "report_interval": {"type": "int"},
                        "pmf_denial": {"type": "bool"},
                    },
                    "mesh_enabled": {"type": "bool"},
                    "mesh_settings": {
                        "type": "dict",
                        "range": {"type": "int"},
                        "backhaul_client_access": {"type": "bool"},
                        "rap_downlink_backhaul": {"type": "str"},
                        "ghz_5_radio_band_type": {"type": "str"},
                        "ghz_2_point_4_radio_band_type": {"type": "str"},
                        "bridge_group_name": {"type": "str"},
                    },
                    "power_settings": {
                        "type": "dict",
                        "ap_powwer_profile_name": {"type": "str"},
                        "calendar_power_profiles": {
                            "type": "list",
                            "elements": "dict",
                            "required": False,
                            "options": {
                                "ap_power_profile_name": {"type": "str"},
                                "scheduler_type": {"type": "str"},
                                "scheduler_start_time": {"type": "str"},
                                "scheduler_end_time": {"type": "str"},
                                "scheduler_days_list": {"type": "list"},
                                "scheduler_dates_list": {"type": "list"},
                            }
                        }
                    },
                    "country_code": {"type": "str"},
                    "time_zone": {"type": "str"},
                    "time_zone_offset_hour": {"type": "int"},
                    "time_zone_offset_minutes": {"type": "int"},
                    "maximum_client_limit": {"type": "int"}
                }
            },
            "radio_frequency_profiles": {
                "type": "list",
                "elements": "dict",
                "required": False,
                "options": {
                    "radio_frequency_profile_name": {"type": "str"},
                    "default_rf_profile": {"type": "bool"},
                    "radio_bands": {"type": "list"},
                    "radio_bands_2_4ghz_settings": {
                        "type": "dict",
                        "parent_profile": {"type": "str"},
                        "dca_channels_list": {"type": "list"},
                        "suppported_data_rates_list": {"type": "list"},
                        "mandatory_data_rates_list": {"type": "list"},
                        "minimum_power_level": {"type": "int"},
                        "maximum_power_level": {"type": "int"},
                        "rx_sop_threshold": {"type": "str"},
                        "custom_rx_sop_threshold": {"type": "int"},
                        "tpc_power_threshold": {"type": "int"},
                        "coverage_hole_detection": {
                            "type": "dict",
                            "minimum_client_level": {"type": "int"},
                            "data_rssi_threshold": {"type": "int"},
                            "voice_rssi_threshold": {"type": "int"},
                            "exception_level": {"type": "int"},
                        },
                        "client_limit": {"type": "int"},
                        "spatial_resuse": {
                            "type": "dict",
                            "non_srg_obss_pd": {"type": "bool"},
                            "non_srg_obss_pd_max_threshold": {"type": "int"},
                            "srg_obss_pd": {"type": "bool"},
                            "srg_obss_pd_min_threshold": {"type": "int"},
                            "srg_obss_pd_max_threshold": {"type": "int"},
                        }

                    },
                    "radio_bands_5ghz_settings": {
                        "type": "dict",
                        "parent_profile": {"type": "str"},
                        "channel_width": {"type": "str"},
                        "preamble_puncturing": {"type": "bool"},
                        "zero_wait_dfs": {"type": "bool"},
                        "dca_channels_list": {"type": "list"},
                        "suppported_data_rates_list": {"type": "list"},
                        "mandatory_data_rates_list": {"type": "list"},
                        "minimum_power_level": {"type": "int"},
                        "maximum_power_level": {"type": "int"},
                        "rx_sop_threshold": {"type": "str"},
                        "custom_rx_sop_threshold": {"type": "int"},
                        "tpc_power_threshold": {"type": "int"},
                        "coverage_hole_detection": {
                            "type": "dict",
                            "minimum_client_level": {"type": "int"},
                            "data_rssi_threshold": {"type": "int"},
                            "voice_rssi_threshold": {"type": "int"},
                            "exception_level": {"type": "int"},
                        },
                        "client_limit": {"type": "int"},
                        "flexible_radio_assigment": {
                            "type": "dict",
                            "client_aware": {"type": "bool"},
                            "client_select": {"type": "int"},
                            "client_reset": {"type": "int"},
                        },
                        "spatial_resuse": {
                            "type": "dict",
                            "non_srg_obss_pd": {"type": "bool"},
                            "non_srg_obss_pd_max_threshold": {"type": "int"},
                            "srg_obss_pd": {"type": "bool"},
                            "srg_obss_pd_min_threshold": {"type": "int"},
                            "srg_obss_pd_max_threshold": {"type": "int"},
                        }
                    },
                    "radio_bands_6ghz_settings": {
                        "type": "dict",
                        "parent_profile": {"type": "str"},
                        "minimum_dbs_channel_width": {"type": "int"},
                        "maximum_dbs_channel_width": {"type": "int"},
                        "preamble_puncturing": {"type": "bool"},
                        "psc_enforcing_enabled": {"type": "bool"},
                        "dca_channels_list": {"type": "list"},
                        "suppported_data_rates_list": {"type": "list"},
                        "mandatory_data_rates_list": {"type": "list"},
                        "minimum_power_level": {"type": "int"},
                        "maximum_power_level": {"type": "int"},
                        "rx_sop_threshold": {"type": "str"},
                        "custom_rx_sop_threshold": {"type": "int"},
                        "tpc_power_threshold": {"type": "int"},
                        "coverage_hole_detection": {
                            "type": "dict",
                            "minimum_client_level": {"type": "int"},
                            "data_rssi_threshold": {"type": "int"},
                            "voice_rssi_threshold": {"type": "int"},
                            "exception_level": {"type": "int"},
                        },
                        "client_limit": {"type": "int"},
                        "flexible_radio_assigment": {
                            "type": "dict",
                            "client_aware": {"type": "bool"},
                            "client_select": {"type": "int"},
                            "client_reset": {"type": "int"},
                        },
                        "discovery_frames_6ghz": {"type": "str"},
                        "broadcast_probe_response_interval": {"type": "int"},
                        "multi_bssid": {
                            "type": "dict",
                            "dot_11ax_parameters": {
                                "type": "dict",
                                "ofdma_downlink": {"type": "bool"},
                                "ofdma_uplink": {"type": "bool"},
                                "mu_mimo_downlink": {"type": "bool"},
                                "mu_mimodownlink": {"type": "bool"},
                            },
                            "dot_11be_parameters": {
                                "type": "dict",
                                "ofdma_downlink": {"type": "bool"},
                                "ofdma_uplink": {"type": "bool"},
                                "mu_mimo_downlink": {"type": "bool"},
                                "mu_mimodownlink": {"type": "bool"},
                                "ofdma_multi_ru": {"type": "bool"},
                            },
                            "target_waketime": {"type": "bool"},
                            "twt_broadcast_support": {"type": "bool"},
                        },
                        "spatial_resuse": {
                            "type": "dict",
                            "non_srg_obss_pd": {"type": "bool"},
                            "non_srg_obss_pd_max_threshold": {"type": "int"},
                            "srg_obss_pd": {"type": "bool"},
                            "srg_obss_pd_min_threshold": {"type": "int"},
                            "srg_obss_pd_max_threshold": {"type": "int"},
                        }
                    }
                }
            },
            "anchor_groups": {
                "type": "list",
                "elements": "dict",
                "required": False,
                "options": {
                    "anchor_group_name": {"type": "str"},
                    "mobility_anchors": {
                        "type": "list",
                        "elements": "dict",
                        "required": False,
                        "options": {
                            "device_name": {"type": "str"},
                            "device_ip_address": {"type": "str"},
                            "device_mac_address": {"type": "str"},
                            "device_type": {"type": "str"},
                            "device_priority": {"type": "int"},
                            "device_nat_ip_address": {"type": "str"},
                            "mobility_group_name": {"type": "str"},
                            "managed_device": {"type": "bool"},
                        }
                    }
                }
            }
        }

        # Validate params against the expected schema
        valid_temp, invalid_params = validate_list_of_dicts(
            self.config, temp_spec
        )

        # Check if any invalid parameters were found
        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(invalid_params)
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        # Set the validated configuration and update the result with success status
        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook configuration parameters using 'validated_input': {0}".format(str(valid_temp))
        self.set_operation_result("success", False, self.msg, "INFO")
        return self

    def validate_required_ssid_params(self, ssid, state="merged"):
        """
        Validates the required parameters for an SSID based on the specified state.
        Args:
            ssid (dict): The SSID configuration parameters.
            state (str): The state of the SSID configuration, either "merged" or "deleted".
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        # Log the start of validation for required SSID parameters
        self.log("Starting validation for required SSID parameters with state: {0}.".format(state), "DEBUG")

        # Determine required parameters based on state
        if state == "merged":
            required_params = ["ssid_name", "ssid_type"]
        elif state == "deleted":
            required_params = ["ssid_name"]
        else:
            self.msg = "Invalid state provided: {}. Allowed states are 'merged' or 'deleted'.".format(state)
            self.fail_and_exit(self.msg)

        # Check for missing required parameters
        missing_params = [param for param in required_params if param not in ssid]
        if missing_params:
            self.msg = ("The following required parameters for SSID configuration are missing: {}. "
                        "Provided parameters: {}").format(", ".join(missing_params), ssid)
            self.fail_and_exit(self.msg)
        else:
            # Validate the length of ssid_name if it is present
            ssid_name = ssid.get("ssid_name")
            if ssid_name and len(ssid_name) > 32:
                self.msg = ("The 'ssid_name' exceeds the maximum length of 32 characters. "
                            "Provided 'ssid_name': {} (length: {})").format(ssid_name, len(ssid_name))
                self.fail_and_exit(self.msg)

            # Log the successful validation of required SSID parameters
            self.log("Required SSID parameters validated successfully for state: {0}.".format(state), "DEBUG")

    def validate_ssid_type_params(self, ssid_type, l2_security, l3_security):
        """
        Validates the parameters based on the SSID type.
        Args:
            ssid_type (str): The type of the SSID ("Enterprise" or "Guest").
            l2_security (dict): The Layer 2 security settings for the SSID.
            l3_security (dict): The Layer 3 security settings for the SSID.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        # Define required parameters based on ssid_type
        required_params = {
            "Enterprise": [("l2_security", l2_security)],
            "Guest": [("l2_security", l2_security), ("l3_security", l3_security)]
        }

        # Log the start of validation for SSID type parameters
        self.log("Starting validation for SSID type parameters for SSID type: {0}.".format(ssid_type), "DEBUG")

        # Validate ssid_type
        if ssid_type not in required_params:
            self.msg = "Invalid ssid_type: {}. Allowed types are 'Enterprise' and 'Guest'.".format(ssid_type)
            self.fail_and_exit(self.msg)

        # # Validate presence of required parameters
        # missing_params = [name for name, value in required_params[ssid_type] if not value]
        # if missing_params:
        #     self.msg = "Missing required parameters for {} SSID: {}.".format(ssid_type, ', '.join(missing_params))
        #     self.log(self.msg, "ERROR")
        #     self.fail_and_exit(self.msg)

        # Log the successful validation of SSID type parameters
        self.log("SSID type parameters validated successfully for SSID type: {0}.".format(ssid_type), "INFO")

    def validate_site_name_hierarchy(self, site_exists, site_id, site_name_hierarchy):
        """
        Validates the site name hierarchy for a given site.
        Args:
            site_exists (bool): Indicates whether the site exists.
            site_id (str): The ID of the site if it exists.
            site_name_hierarchy (str): The hierarchy name of the site to be validated.
        Raises:
            Exception: If the site does not exist, an exception is raised with a descriptive message.
        """
        # Check if the site exists
        if not site_exists:
            # Log and raise an error if the site does not exist
            self.msg = (
                "Error occurred retrieving site details for site '{1}' from the Cisco Catalyst Center.".format(site_name_hierarchy)
            )
            self.fail_and_exit(self.msg)
        else:
            # Log the site ID if the site exists
            self.log("Site '{0}' exists with ID: {1}.".format(site_name_hierarchy, site_id), "DEBUG")

        # Log the successful validation of the site name hierarchy
        self.log("Successfully validated site_name_hierarchy for Site: '{0}'.".format(site_name_hierarchy), "DEBUG")

    def validate_ssid_radio_policy_params(self, ssid_name, radio_policy):
        """
        Validates the radio policy parameters for an SSID.
        Args:
            ssid_name (str): The name of the SSID.
            radio_policy (dict): The radio policy settings to be validated.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        # Define valid radio bands
        valid_radio_bands = {2.4, 5, 6}

        # Validate radio_bands if present in radio_policy
        if "radio_bands" in radio_policy:
            # Convert float to int for comparison
            radio_bands_set = set(map(float, radio_policy['radio_bands']))

            # Check if radio_bands is a list
            if not isinstance(radio_policy['radio_bands'], list):
                self.msg = "Invalid 'radio_bands' for SSID: '{0}'. Must be a list of integers, allowed values are [2.4, 5, 6].".format(ssid_name)
                self.fail_and_exit(self.msg)

            # Check if radio_bands_set is a subset of valid_radio_bands
            if not radio_bands_set.issubset(valid_radio_bands):
                self.msg = "Invalid elements in 'radio_bands' for SSID: '{0}'. Allowed values are [2.4, 5, 6].".format(ssid_name)
                self.fail_and_exit(self.msg)

            # Validate 2_dot_4_ghz_band_policy
            if "2_dot_4_ghz_band_policy" in radio_policy:
                if 2.4 not in radio_bands_set:
                    self.msg = "For SSID: {0} 2_dot_4_ghz_band_policy is specified but 2.4 GHz is not enabled in 'radio_bands'.".format(ssid_name)
                    self.fail_and_exit(self.msg)

            # Validate band_select
            if "band_select" in radio_policy and radio_policy["band_select"]:
                if not (radio_bands_set == {2.4, 5} or radio_bands_set == {2.4, 5, 6}):
                    self.msg = ("Error enabling 'band_select' for SSID: '{0}'. 'band_select' can only be enabled when 'radio_bands' are atleast"
                                " 2.4GHz and 5GHz or Triple band operation [2.4, 5, 6].".format(ssid_name))
                    self.fail_and_exit(self.msg)

            # Validate 6_ghz_client_steering
            if "6_ghz_client_steering" in radio_policy and radio_policy["6_ghz_client_steering"]:
                if 6 not in radio_bands_set:
                    self.msg = ("Error enabling '6_ghz_client_steering' for SSID: '{0}', it can only be enabled if 'radio_bands' "
                                "includes 6 GHz.".format(ssid_name))
                    self.fail_and_exit(self.msg)

        # Validate 2_dot_4_ghz_band_policy
        if "2_dot_4_ghz_band_policy" in radio_policy and radio_policy['2_dot_4_ghz_band_policy'] not in ["802.11-bg", "802.11-g"]:
            self.msg = "Invalid '2_dot_4_ghz_band_policy' provided for SSID: '{0}'. Allowed values are ['802.11-bg',  '802.11-g'].".format(ssid_name)
            self.fail_and_exit(self.msg)

        # Log the successful validation of radio policy parameters
        self.log("Radio policy parameters validated successfully for SSID: {0}.".format(ssid_name), "INFO")

    def validate_qos_params(self, ssid_name, qos, fast_lane_enabled):
        """
        Validates the Quality of Service (QoS) parameters for an SSID.
        Args:
            ssid_name (str): The name of the SSID.
            qos (dict): The Quality of Service settings to be validated.
            fast_lane_enabled (bool): Indicates if Fast Lane is enabled for the SSID.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        # Log the start of validation for QoS parameters
        self.log("Starting validation for Quality of Service parameters for SSID: {0}.".format(ssid_name), "DEBUG")

        # Validate Quality of Service parameters
        if fast_lane_enabled:
            self.msg = ("The Quality of Service selection will not be applicable when Fast Lane is enabled for SSID: '{0}'. "
                        "QoS settings should be empty when 'fast_lane' is enabled.").format(ssid_name)
            self.fail_and_exit(self.msg)

        # Validate egress QoS
        if "egress" in qos:
            egress = qos["egress"]
            if egress:
                if egress.upper() not in ["PLATINUM", "SILVER", "GOLD", "BRONZE"]:
                    self.msg = ("Invalid 'egress' QoS for SSID: '{0}'. Allowed values are ['PLATINUM', 'SILVER', 'GOLD', 'BRONZE'].".format(ssid_name))
                    self.fail_and_exit(self.msg)

        # Validate ingress QoS
        if "ingress" in qos:
            ingress = qos["ingress"]
            if ingress:
                if ingress.upper() not in ["PLATINUM-UP", "SILVER-UP", "GOLD-UP", "BRONZE-UP"]:
                    self.msg = ("Invalid 'ingress' QoS for SSID: '{0}'. Allowed values are ['PLATINUM-UP', 'SILVER-UP', 'GOLD-UP', 'BRONZE-UP']."
                                .format(ssid_name))
                    self.fail_and_exit(self.msg)

        # Log the successful validation of QoS parameters
        self.log("Quality of Service parameters validated successfully for SSID: {0}.".format(ssid_name), "INFO")

    def validate_l2_security_params(self, ssid_name, l2_security, fast_transition, fast_transition_over_the_ds,
                                    wpa_encryption, auth_key_management, cckm_timestamp_tolerance=None):
        """
        Validates the Layer 2 security parameters for an SSID.
        Args:
            ssid_name (str): The name of the SSID.
            l2_security (dict): The Layer 2 security settings to be validated.
            fast_transition (str): The fast transition setting (e.g., "DISABLE", "ENABLE", "ADAPTIVE").
            fast_transition_over_the_ds (bool): Indicates if fast transition over the DS is enabled.
            wpa_encryption (list): A list of WPA encryption methods used.
            auth_key_management (list): A list of authentication key management methods used.
            cckm_timestamp_tolerance (int, optional): Tolerance for CCKM timestamp, if applicable.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        # Extract L2 security parameters
        l2_auth_type = l2_security.get("l2_auth_type")
        # ap_beacon_protection = l2_security.get("ap_beacon_protection", False)
        # open_ssid = l2_security.get("open_ssid")
        # passphrase_type = l2_security.get("passphrase_type")
        # passphrase = l2_security.get("passphrase")
        mpsk_settings = l2_security.get("mpsk_settings")

        # Define valid configurations for each L2 security type
        valid_configurations = {
            "WPA2_ENTERPRISE": {
                "required": ["wpa_encryption", "auth_key_management"],
                "fast_transition_options": {
                    "ADAPTIVE": {
                        "CCMP128": ["CCKM", "802.1X-SHA1", "802.1X-SHA2"],
                        "GCMP128": ["SUITE-B-1X"],
                        "CCMP256": ["SUITE-B-192X"],
                        "GCMP256": ["SUITE-B-192X"]
                    },
                    "DISABLE": {
                        "CCMP128": ["CCKM", "802.1X-SHA1", "802.1X-SHA2"],
                        "GCMP128": ["SUITE-B-1X"],
                        "CCMP256": ["SUITE-B-192X"],
                        "GCMP256": ["SUITE-B-192X"]
                    },
                    "ENABLE": {
                        "CCMP128": ["CCKM", "802.1X-SHA1", "802.1X-SHA2", "FT+802.1x"],
                        "GCMP128": ["SUITE-B-1X"],
                        "CCMP256": ["SUITE-B-192X"],
                        "GCMP256": ["SUITE-B-192X"]
                    }
                },
                "ap_beacon_protection_allowed": False
            },
            "WPA3_ENTERPRISE": {
                "fast_transition_options": {
                    "ADAPTIVE": {
                        "CCMP128": ["802.1X-SHA1", "802.1X-SHA2"],
                        "GCMP128": ["SUITE-B-1X"],
                        "GCMP256": ["SUITE-B-192X"]
                    },
                    "DISABLE": {
                        "CCMP128": ["802.1X-SHA1", "802.1X-SHA2"],
                        "GCMP128": ["SUITE-B-1X"],
                        "GCMP256": ["SUITE-B-192X"]
                    },
                    "ENABLE": {
                        "CCMP128": ["802.1X-SHA1", "802.1X-SHA2", "FT+802.1x"],
                        "GCMP128": ["SUITE-B-1X"],
                        "GCMP256": ["SUITE-B-192X"]
                    }
                },
                "ap_beacon_protection_allowed": True
            },
            "WPA2_WPA3_ENTERPRISE": {
                "required": ["wpa_encryption", "auth_key_management"],
                "fast_transition_options": {
                    "ADAPTIVE": {
                        "CCMP128": ["CCKM", "802.1X-SHA1", "802.1X-SHA2"],
                        "GCMP128": ["SUITE-B-1X"],
                        "CCMP256": ["SUITE-B-192X"],
                        "GCMP256": ["SUITE-B-192X"]
                    },
                    "DISABLE": {
                        "CCMP128": ["CCKM", "802.1X-SHA1", "802.1X-SHA2"],
                        "GCMP128": ["SUITE-B-1X"],
                        "CCMP256": ["SUITE-B-192X"],
                        "GCMP256": ["SUITE-B-192X"]
                    },
                    "ENABLE": {
                        "CCMP128": ["CCKM", "802.1X-SHA1", "802.1X-SHA2", "FT+802.1x"],
                        "GCMP128": ["SUITE-B-1X"],
                        "CCMP256": ["SUITE-B-192X"],
                        "GCMP256": ["SUITE-B-192X"]
                    }
                },
                "ap_beacon_protection_allowed": True
            },
            "WPA2_PERSONAL": {
                "required": ["passphrase", "wpa_encryption", "auth_key_management"],
                "fast_transition_options": {
                    "ADAPTIVE": {
                        "CCMP128": ["PSK", "PSK-SHA2", "Easy-PSK"]
                    },
                    "DISABLE": {
                        "CCMP128": ["PSK", "PSK-SHA2", "Easy-PSK"]
                    },
                    "ENABLE": {
                        "CCMP128": ["PSK", "PSK-SHA2", "Easy-PSK", "FT+PSK"]
                    }
                },
                "ap_beacon_protection_allowed": False
            },
            "WPA3_PERSONAL": {
                "required": ["passphrase", "wpa_encryption", "auth_key_management"],
                "fast_transition_options": {
                    "ENABLE": {
                        "CCMP128": ["SAE", "SAE-EXT-KEY", "FT+SAE", "FT+SAE-EXT-KEY"],
                        "GCMP256": ["SAE-EXT-KEY", "FT+SAE-EXT-KEY"]
                    },
                    "DISABLE": {
                        "CCMP128": ["SAE", "SAE-EXT-KEY"],
                        "GCMP256": ["SAE-EXT-KEY"]
                    }
                },
                "ap_beacon_protection_allowed": True
            },
            "WPA2_WPA3_PERSONAL": {
                "required": ["passphrase", "wpa_encryption", "auth_key_management"],
                "fast_transition_options": {
                    "ENABLE": {
                        "CCMP128": ["SAE", "SAE-EXT-KEY", "PSK", "PSK-SHA2", "FT+SAE", "FT+PSK", "FT+SAE-EXT-KEY"],
                        "GCMP256": ["SAE-EXT-KEY", "FT+SAE-EXT-KEY"]
                    },
                    "DISABLE": {
                        "CCMP128": ["SAE", "SAE-EXT-KEY", "PSK", "PSK-SHA2"],
                        "GCMP256": ["SAE-EXT-KEY"]
                    }
                },
                "ap_beacon_protection_allowed": True
            },
            "OPEN-SECURED": {
                "required": ["wpa_encryption", "auth_key_management"],
                "fast_transition_options": {
                    "DISABLE": {
                        "CCMP128": ["OWE"],
                        "GCMP256": ["OWE"]
                    }
                },
                "ap_beacon_protection_allowed": False
            },
            "OPEN": {
                "required": [],
                "fast_transition_options": {
                    "ADAPTIVE": {},
                    "DISABLE": {},
                    "ENABLE": {}
                },
                "ap_beacon_protection_allowed": False
            }
        }
        # Check if the l2_security type is valid
        if l2_auth_type and l2_auth_type not in valid_configurations:
            valid_l2_auth_types = valid_configurations.keys()
            self.msg = "Invalid 'l2_auth_type': {0} supplied for SSID: {1}. Allowed values are {2}.".format(l2_auth_type, ssid_name, valid_l2_auth_types)
            self.fail_and_exit(self.msg)

        # Validate required params for l2 auth type
        required_l2_auth_params = valid_configurations[l2_auth_type].get("required", [])
        fast_transition_options = valid_configurations[l2_auth_type]["fast_transition_options"].get(fast_transition, {})

        for param in required_l2_auth_params:
            if param == "wpa_encryption":
                if wpa_encryption and not all(encryption in fast_transition_options for encryption in wpa_encryption):
                    allowed_options = ', '.join(fast_transition_options.keys())
                    self.msg = (
                        "For SSID: '{0}', invalid 'wpa_encryption' provided for L2 Authentication type: '{1}' . Provided: {2}. "
                        "Allowed options for fast transition '{3}': {4}.".format(
                            ssid_name, l2_auth_type, wpa_encryption, fast_transition, allowed_options
                        )
                    )
                    self.fail_and_exit(self.msg)

            elif param == "auth_key_management":
                if auth_key_management:
                    # Check each AKM to ensure there is at least one corresponding encryption method
                    for akm in auth_key_management:
                        is_valid_akm = any(
                            akm in fast_transition_options.get(encryption, [])
                            for encryption in wpa_encryption
                        )
                        if not is_valid_akm:
                            allowed_options = ', '.join(
                                f"{encryption}: {', '.join(fast_transition_options.get(encryption, []))}"
                                for encryption in wpa_encryption
                            )
                            self.msg = (
                                "For SSID: '{0}', invalid 'auth_key_management' provided for L2 Authentication type: {1}. Provided: {2}. "
                                "Allowed options for fast transition '{3}': {4}.".format(
                                    ssid_name, l2_auth_type, auth_key_management, fast_transition, allowed_options
                                )
                            )
                            self.fail_and_exit(self.msg)

        # Validate MPSK Settings
        if mpsk_settings:
            # Check if mpsk_settings is a list and if its length is less than 5
            if not isinstance(mpsk_settings, list) or len(mpsk_settings) >= 5:
                self.msg = (
                    "For SSID: '{0}', MPSK settings must be a list with less than 5 entries.".format(ssid_name)
                )
                self.fail_and_exit(self.msg)

            # Iterate over each dictionary in the mpsk_settings list
            for idx, mpsk_setting in enumerate(mpsk_settings):
                # Validate required params for each mpsk_setting
                mpsk_passphrase = mpsk_setting.get("mpsk_passphrase")
                if not mpsk_passphrase:
                    self.msg = (
                        "For SSID: '{0}', MPSK settings entry {1} requires a 'passphrase' to be provided.".format(ssid_name, idx + 1)
                    )
                    self.fail_and_exit(self.msg)

                # Validate priority
                mpsk_priority = mpsk_setting.get("mpsk_priority")
                if mpsk_priority is not None and not (0 <= mpsk_priority <= 4):
                    self.msg = (
                        "For SSID: '{0}', entry {1}, Invalid 'mpsk_priority' in MPSK settings: {2}. "
                        "Allowed values are 0 to 4.".format(ssid_name, idx + 1, mpsk_priority)
                    )
                    self.fail_and_exit(self.msg)

                # Validate passphrase_type
                mpsk_passphrase_type = mpsk_setting.get("mpsk_passphrase_type", "ASCII")
                if mpsk_passphrase_type:
                    if mpsk_passphrase_type not in ["HEX", "ASCII"]:
                        self.msg = (
                            "For SSID: '{0}', entry {1}, invalid passphrase_type in MPSK settings: {2}. "
                            "Allowed values are 'HEX' or 'ASCII'.".format(ssid_name, idx + 1, mpsk_passphrase_type)
                        )
                        self.fail_and_exit(self.msg)

                    # Validate passphrase length based on type
                    if mpsk_passphrase_type == "ASCII":
                        if not (8 <= len(mpsk_passphrase) <= 63):
                            self.msg = (
                                "For SSID: '{0}', entry {1}, invalid ASCII passphrase length in MPSK settings. "
                                "Must be between 8 and 63 characters.".format(ssid_name, idx + 1)
                            )
                            self.fail_and_exit(self.msg)
                    elif mpsk_passphrase_type == "HEX":
                        if len(mpsk_passphrase) != 64:
                            self.msg = (
                                "For SSID: '{0}', entry {1}, invalid HEX passphrase length in MPSK settings. "
                                "Must be exactly 64 characters.".format(ssid_name, idx + 1)
                            )
                            self.fail_and_exit(self.msg)

        # Validate cckm_timestamp_tolerance
        if cckm_timestamp_tolerance:
            if not (1000 <= cckm_timestamp_tolerance <= 5000):
                self.msg = (
                    "For SSID: {0}, invalid 'cckm_timestamp_tolerance': {1}. "
                    "Allowed range is 1000 to 5000.".format(ssid_name, cckm_timestamp_tolerance)
                )
                self.fail_and_exit(self.msg)

    def validate_l3_security_aaa_params(self, ssid_name, ssid_type, l3_security, aaa):
        """
        Validates the Layer 3 security and AAA parameters for an SSID.
        Args:
            ssid_name (str): The name of the SSID.
            ssid_type (str): The type of the SSID (e.g., "Enterprise", "Guest").
            l3_security (dict): The Layer 3 security settings to be validated.
            aaa (dict): The AAA (Authentication, Authorization, and Accounting) settings to be validated.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        # Extract necessary information from l3_security
        l3_auth_type = l3_security.get("l3_auth_type")
        auth_server = l3_security.get("auth_server")
        web_auth_url = l3_security.get("web_auth_url")
        enable_sleeping_client = l3_security.get("enable_sleeping_client", False)
        sleeping_client_timeout = l3_security.get("sleeping_client_timeout", 720)

        # Validate l3_security settings
        if l3_security:
            # Validate l3_auth_type
            if not l3_auth_type:
                self.msg = (
                    "For SSID: '{0}', 'l3_auth_type' not provided, it is a required parameter. "
                    "Valid values are 'OPEN' or 'WEB_AUTH'.".format(ssid_name)
                )
                self.fail_and_exit(self.msg)

            if l3_auth_type not in ["OPEN", "WEB_AUTH"]:
                self.msg = (
                    "For SSID: '{0}', invalid 'l3_auth_type': '{1}'. "
                    "Allowed values are 'OPEN' or 'WEB_AUTH'.".format(ssid_name, l3_auth_type)
                )
                self.fail_and_exit(self.msg)

            # Validate auth_server when l3_auth_type is WEB_AUTH
            if l3_auth_type == "WEB_AUTH":
                if auth_server:
                    if auth_server not in [
                        "Central Web Authentication",
                        "Web Authentication Internal",
                        "Web Authentication External",
                        "Web Passthrough Internal",
                        "Web Passthrough External"
                    ]:
                        self.msg = (
                            "For SSID: '{0}', invalid 'auth_server': '{1}' with 'l3_auth_type' as 'WEB_AUTH'. "
                            "Allowed values are 'Central Web Authentication', 'Web Authentication Internal', "
                            "'Web Authentication External', 'Web Passthrough Internal', 'Web Passthrough External'.".format(ssid_name, auth_server)
                        )
                        self.fail_and_exit(self.msg)

                    # Validate web_auth_url for specific auth_server types
                    if auth_server in ["Web Authentication External", "Web Passthrough External"] and not web_auth_url:
                        self.msg = (
                            "For SSID: '{0}', 'web_auth_url' is required when 'auth_server' is '{1}'.".format(ssid_name, auth_server)
                        )
                        self.fail_and_exit(self.msg)

            # Validate sleeping_client_timeout
            if enable_sleeping_client and (not isinstance(sleeping_client_timeout, int) or sleeping_client_timeout <= 0):
                self.msg = (
                    "For SSID: '{0}', invalid 'sleeping_client_timeout': '{1}'. "
                    "Must be a positive integer.".format(ssid_name, sleeping_client_timeout)
                )
                self.fail_and_exit(self.msg)

        # Validate AAA settings
        if aaa:
            # Extract necessary information from aaa
            auth_servers_ip_list = aaa.get("auth_servers_ip_address_list", [])
            # aaa_override = aaa.get("aaa_override", False)
            mac_filtering = aaa.get("mac_filtering", False)
            enable_posture = aaa.get("enable_posture", False)
            pre_auth_acl_name = aaa.get("pre_auth_acl_name", None)

            # Validate AAA for Guest SSID with Central Web Authentication
            if ssid_type == "Guest" and l3_auth_type == "Central Web Authentication":
                if not auth_servers_ip_list:
                    self.msg = (
                        "For SSID: '{0}', at least one server IP is required in 'auth_servers_ip_address_list' "
                        "when 'l3_auth_type' is 'Central Web Authentication'.".format(ssid_name)
                    )
                    self.fail_and_exit(self.msg)

            # Validate enable_posture and pre_auth_acl_name for Enterprise SSID
            if enable_posture:
                if ssid_type != "Enterprise" and not pre_auth_acl_name:
                    self.msg = (
                        "For SSID: '{0}': The SSID type must be 'Enterprise' to activate 'enable_posture' and 'pre_auth_acl_name' is required "
                        "when it is enabled.".format(ssid_name)
                    )
                    self.fail_and_exit(self.msg)

            # Validate mac_filtering for Guest SSID
            if ssid_type == "Guest":
                if mac_filtering and l3_auth_type and l3_auth_type != "OPEN":
                    self.msg = (
                        "For SSID: '{0}', since it is a Guest SSID the 'mac_filtering' can be enabled only when 'l3_auth_type' is 'OPEN'.".format(ssid_name)
                    )
                    self.fail_and_exit(self.msg)

        # Log the successful validation of L3 Security and AAA parameters
        self.log("All L3 Security and AAA parameters are valid for SSID: '{0}'.".format(ssid_name), "DEBUG")

    def validate_mfp_client_protection_params(self, ssid_name, mfp_client_protection, radio_bands):
        """
        Validates the MFP (Management Frame Protection) client protection parameters for an SSID.
        Args:
            ssid_name (str): The name of the SSID.
            mfp_client_protection (str): The MFP client protection setting to be validated.
            radio_bands (list): A list of radio bands associated with the SSID.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        # Validate mfp_client_protection value against allowed options
        if mfp_client_protection not in ["OPTIONAL", "DISABLED", "REQUIRED"]:
            self.msg = (
                "For SSID: '{0}', invalid 'mfp_client_protection' provided. Valid values are 'OPTIONAL', 'DISABLED', and 'REQUIRED'.".format(ssid_name)
            )
            self.fail_and_exit(self.msg)

        # Validate mfp_client_protection for 6 GHz radio bands
        if radio_bands and radio_bands == [6] and mfp_client_protection != "OPTIONAL":
            self.msg = (
                "For SSID: '{0}', 'mfp_client_protection' must be 'OPTIONAL' for 6GHz radio bands. "
                "Current value is '{1}'.".format(ssid_name, mfp_client_protection)
            )
            self.fail_and_exit(self.msg)

        # Log the successful validation of the MFP client protection setting
        self.log("MFP client protection is valid for SSID: '{0}'.".format(ssid_name), "DEBUG")

    def validate_protected_management_frame_params(self, ssid_name, protected_management_frame):
        """
        Validates the Protected Management Frame (PMF) parameters for an SSID.
        Args:
            ssid_name (str): The name of the SSID.
            protected_management_frame (str): The PMF setting to be validated.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        # Validate if the value is one of the valid options
        if protected_management_frame not in ["OPTIONAL", "DISABLED", "REQUIRED"]:
            self.msg = (
                "For SSID: '{0}', invalid 'protected_management_frame': '{1}'. "
                "Allowed values are 'OPTIONAL', 'DISABLED', or 'REQUIRED'.".format(ssid_name, protected_management_frame)
            )
            self.fail_and_exit(self.msg)

        # Log the successful validation of the protected management frame setting
        self.log("Protected management frame settings are valid for SSID: '{0}'.".format(ssid_name), "DEBUG")

    def validate_wlan_timeouts_params(self, ssid_name, wlan_timeouts):
        """
        Validates the WLAN timeouts parameters for an SSID.
        Args:
            ssid_name (str): The name of the SSID.
            wlan_timeouts (dict): A dictionary containing WLAN timeout settings.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        # Extract relevant information from wlan_timeouts
        enable_session_timeout = wlan_timeouts.get("enable_session_timeout", True)
        session_timeout = wlan_timeouts.get("session_timeout")
        enable_client_execlusion_timeout = wlan_timeouts.get("enable_client_execlusion_timeout", True)
        client_execlusion_timeout = wlan_timeouts.get("client_execlusion_timeout")

        # Validate session_timeout if session timeout is enabled
        if enable_session_timeout:
            # Ensure session_timeout is within the valid range
            if session_timeout and not (1 <= session_timeout <= 86400):
                self.msg = (
                    "For SSID: '{0}', 'session_timeout' must be between 1 and 86400 seconds. "
                    "Current value is '{1}'.".format(ssid_name, session_timeout)
                )
                self.fail_and_exit(self.msg)
        else:
            # Ensure session_timeout is not provided when session timeout is disabled
            if session_timeout is not None:
                self.msg = (
                    "For SSID: '{0}', 'session_timeout' should not be provided when 'enable_session_timeout' is False.".format(ssid_name)
                )
                self.fail_and_exit(self.msg)

        # Validate client_execlusion_timeout if client exclusion is enabled
        if enable_client_execlusion_timeout:
            # Ensure client_execlusion_timeout is within the valid range
            if client_execlusion_timeout and not (0 <= client_execlusion_timeout <= 2147483647):
                self.msg = (
                    "For SSID: '{0}', 'client_execlusion_timeout' must be between 0 and 2147483647 seconds. "
                    "Current value is '{1}'.".format(ssid_name, client_execlusion_timeout)
                )
                self.fail_and_exit(self.msg)
        else:
            # Ensure client_execlusion_timeout is not provided when client exclusion is disabled
            if client_execlusion_timeout is not None:
                self.msg = (
                    "For SSID: '{0}', 'client_execlusion_timeout' should not be provided when 'enable_client_execlusion_timeout' is False.".format(ssid_name)
                )
                self.fail_and_exit(self.msg)

        # Log the successful validation of WLAN timeouts
        self.log("WLAN timeouts are valid for SSID: '{0}'.".format(ssid_name), "DEBUG")

    def validate_bss_transition_support_params(self, ssid_name, bss_transition_support):
        """
        Validates the 11v BSS Transition Support parameters for an SSID.
        Args:
            ssid_name (str): The name of the SSID.
            bss_transition_support (dict): The BSS Transition Support parameters to be validated.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        # Extract necessary information from bss_transition_support
        bss_max_idle_service = bss_transition_support.get("bss_max_idle_service", True)
        bss_idle_client_timeout = bss_transition_support.get("bss_idle_client_timeout")

        # Validate bss_idle_client_timeout and bss_max_idle_service
        if bss_idle_client_timeout:
            # Ensure that bss_max_idle_service is enabled if bss_idle_client_timeout is set
            if not bss_max_idle_service:
                self.msg = (
                    "For SSID: '{0}', 'bss_idle_client_timeout' is provided but 'bss_max_idle_service' is not enabled. "
                    "'bss_max_idle_service' must be True to set 'bss_idle_client_timeout'.".format(ssid_name)
                )
                self.fail_and_exit(self.msg)

            # Check if bss_idle_client_timeout is within the valid range
            if not (15 <= bss_idle_client_timeout <= 100000):
                self.msg = (
                    "For SSID: '{0}', 'bss_idle_client_timeout' must be between 15 and 100000 seconds. "
                    "Current value is '{1}'.".format(ssid_name, bss_idle_client_timeout)
                )
                self.fail_and_exit(self.msg)

        # Log the successful validation of the BSS Transition Support parameters
        self.log("11v BSS Transition Support parameters are valid for SSID: '{0}'.".format(ssid_name), "DEBUG")

    def validate_nas_id_param(self, ssid_name, nas_id):
        """
        Validates the NAS ID parameter for an SSID.
        Args:
            ssid_name (str): The name of the SSID.
            nas_id (list): The NAS ID list to be validated.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        # Predefined valid options for nas_id
        valid_options = [
            "AP ETH Mac Address", "AP IP address", "AP Location",
            "AP MAC Address", "AP Name", "AP Policy Tag",
            "AP Site Tag", "SSID", "System IP Address",
            "System MAC Address", "System Name"
        ]

        # Check the length of nas_id
        if len(nas_id) > 4:
            self.msg = (
                "For SSID: '{0}', 'nas_id' can have a maximum of 4 values. "
                "Current count is '{1}'.".format(ssid_name, len(nas_id))
            )
            self.fail_and_exit(self.msg)

        # Validate each entry in nas_id
        for item in nas_id:
            if item not in valid_options:
                self.msg = (
                    "For SSID: '{0}', 'nas_id' contains an invalid value: '{1}'. "
                    "Allowed values are: {2}.".format(ssid_name, item, ', '.join(valid_options))
                )
                self.fail_and_exit(self.msg)

        # Log the successful validation of the NAS ID
        self.log("NAS ID is valid for SSID: '{0}'.".format(ssid_name), "DEBUG")

    def validate_client_rate_limit_param(self, ssid_name, client_rate_limit):
        """
        Validates the client rate limit parameter for an SSID.
        Args:
            ssid_name (str): The name of the SSID.
            client_rate_limit (int): The client rate limit to be validated.
        Raises:
            Exception: If the validation fails, an exception is raised with a descriptive message.
        """
        # Validate client_rate_limit if provided
        if client_rate_limit:
            # Check if the client_rate_limit is within the valid range
            if not (8000 <= client_rate_limit <= 100000000000):
                self.msg = (
                    "For SSID: '{0}', 'client_rate_limit' must be between 8000 and 100000000000. "
                    "Current value is '{1}'.".format(ssid_name, client_rate_limit)
                )
                self.fail_and_exit(self.msg)

            # Check if the client_rate_limit is a multiple of 500
            if client_rate_limit % 500 != 0:
                self.msg = (
                    "For SSID: '{0}', 'client_rate_limit' must be a multiple of 500. "
                    "Current value is '{1}'.".format(ssid_name, client_rate_limit)
                )
                self.fail_and_exit(self.msg)

        # Log the successful validation of the client rate limit
        self.log("Client rate limit is valid for SSID: '{0}'.".format(ssid_name), "DEBUG")

    def validate_sites_specific_override_settings_params(self, ssid_name, ssid_type, sites_specific_override_settings, global_l3_security, global_l2_security):
        """
        Validates the site-specific override settings for SSIDs.
        Args:
            ssid_name (str): The name of the SSID.
            ssid_type (str): The type of the SSID.
            sites_specific_override_settings (list): A list of dictionaries containing site-specific override settings.
            global_l3_security (dict): The global Layer 3 security settings.
            global_l2_security (dict): The global Layer 2 security settings.
        Raises:
            Exception: If any validation fails, an exception is raised with a descriptive message.
        """
        # Define allowed parameters for site-specific overrides
        allowed_parameters = [
            "site_name_hierarchy",
            "wlan_profile_name",
            "l2_security",
            "fast_transition",
            "fast_transition_over_the_ds",
            "wpa_encryption",
            "auth_key_management",
            "aaa",
            "protected_management_frame",
            "nas_id",
            "client_rate_limit"
        ]

        allowed_l2_security_parameters = [
            "l2_auth_type",
            "open_ssid",
            "passphrase",
            "mpsk_settings"
        ]

        allowed_aaa_parameters = [
            "auth_servers_ip_address_list",
            "accounting_servers_ip_address_list",
            "aaa_override",
            "mac_filtering"
        ]

        # Iterate over each site-specific override
        for idx, site_override in enumerate(sites_specific_override_settings):
            self.log("Validating site-specific override {0} for SSID: '{1}'".format(idx + 1, ssid_name), "DEBUG")

            site_name_hierarchy = site_override.get('site_name_hierarchy')
            if not site_name_hierarchy:
                self.msg = "For SSID: '{0}', Entry {1}: 'site_name_hierarchy' is required.".format(ssid_name, idx + 1)
                self.fail_and_exit(self.msg)

            if site_name_hierarchy == "Global":
                self.msg = ("For SSID: '{0}', Entry {1}: 'site_name_hierarchy' is set to 'Global', which is invalid. "
                            "Site-specific overrides require a site name other than 'Global'.").format(ssid_name, idx + 1)
                self.fail_and_exit(self.msg)

            # Validate parameters in the site override
            for key, value in site_override.items():
                self.log("Validating parameter '{0}' for site-specific override {1} in SSID: '{2}'".format(key, idx + 1, ssid_name), "DEBUG")

                # Handle nested l2_security validation
                if key == "l2_security" and isinstance(value, dict):
                    for l2_key, l2_value in value.items():
                        if l2_key not in allowed_l2_security_parameters:
                            self.msg = ("For SSID: '{0}', Entry {1}, Site '{2}': 'l2_security.{3}' is not an override eligible parameter."
                                        ).format(ssid_name, idx + 1, site_name_hierarchy, l2_key)
                            self.fail_and_exit(self.msg)

                        if l2_key == "mpsk_settings" and isinstance(l2_value, list):
                            for mpsk_idx, mpsk_setting in enumerate(l2_value):
                                if isinstance(mpsk_setting, dict):
                                    for mpsk_key in mpsk_setting:
                                        if mpsk_key not in ["mpsk_priority", "mpsk_passphrase_type", "mpsk_passphrase"]:
                                            self.msg = ("For SSID: '{0}', Entry {1}, Site '{2}': MPSK setting {3}, '{4}' is not an allowed parameter."
                                                        ).format(ssid_name, idx + 1, site_name_hierarchy, mpsk_idx + 1, mpsk_key)
                                            self.fail_and_exit(self.msg)

                # Handle nested aaa validation
                if key == "aaa" and isinstance(value, dict):
                    for aaa_key in value:
                        if aaa_key not in allowed_aaa_parameters:
                            self.msg = ("For SSID: '{0}', Entry {1}, Site '{2}': 'aaa.{3}' is not an override eligible parameter."
                                        ).format(ssid_name, idx + 1, site_name_hierarchy, aaa_key)
                            self.fail_and_exit(self.msg)

                if key not in allowed_parameters:
                    self.msg = ("For SSID: '{0}', Entry {1}, Site '{2}': '{3}' is not an override eligible parameter."
                                ).format(ssid_name, idx + 1, site_name_hierarchy, key)
                    self.fail_and_exit(self.msg)

        self.log("Validation of site-specific override settings for SSID: {0} completed successfully.".format(ssid_name), "DEBUG")

    def validate_ssids_params(self, ssids, state):
        """
        Validates the parameters for SSIDs based on the specified state.
        Args:
            ssids (list): A list of dictionaries containing SSID parameters.
            state (str): The state of the operation, either "merged" or "deleted".
        """
        # Handle 'deleted' state separately
        if state == "deleted":
            if ssids:
                self.log("Validating SSID(s) parameters in 'deleted' state.", "DEBUG")
                for ssid in ssids:
                    ssid_name = ssid.get("ssid_name")
                    self.log("Starting validation of required parameters for SSID: {0}".format(ssid_name), "DEBUG")
                    self.validate_required_ssid_params(ssid, state="deleted")
                    self.log("Completed validation of required parameters for SSID: {0}".format(ssid_name), "DEBUG")

                # Exit after handling the 'deleted' state
                return

        # Iterate through each SSID for validation
        for ssid in ssids:
            self.log("Starting validation of parameters for SSID: '{0}' .".format(ssid), "DEBUG")

            ssid_name = ssid.get("ssid_name")
            ssid_type = ssid.get("ssid_type")

            # Validate required parameters for the SSID
            self.log("Starting validation of required parameters for SSID: {0}".format(ssid_name), "DEBUG")
            self.validate_required_ssid_params(ssid)
            self.log("Completed validation of required parameters for SSID: {0}".format(ssid_name), "DEBUG")

            # Validate SSID type parameters
            l2_security = ssid.get("l2_security")
            l3_security = ssid.get("l3_security")
            self.log("Starting validation of SSID type parameters for SSID: {0}.".format(ssid_name), "DEBUG")
            self.validate_ssid_type_params(ssid_type, l2_security, l3_security)
            self.log("Completed validation of SSID type parameters for SSID: {0}.".format(ssid_name), "DEBUG")

            # Validate radio policy parameters
            self.log("Starting validation of radio policy parameters for SSID: {0}.".format(ssid_name), "DEBUG")
            radio_policy = ssid.get("radio_policy")
            self.log("'radio_policy' for SSID: {0} - {1}".format(ssid_name, radio_policy), "DEBUG")
            if radio_policy:
                self.validate_ssid_radio_policy_params(ssid_name, radio_policy)
            else:
                self.log("Radio policy parameters not provided hence validation is not required.", "INFO")
            self.log("Completed validation of radio policy parameters for SSID: {0}.".format(ssid_name), "DEBUG")

            # Validate quality of service parameters
            self.log("Starting validation of quality of service parameters for SSID: {0}.".format(ssid_name), "DEBUG")
            quality_of_service = ssid.get("quality_of_service")
            self.log("'quality_of_service' for SSID: {0} - {1}".format(ssid_name, quality_of_service), "DEBUG")
            if quality_of_service:
                fast_lane_enabled = ssid.get("fast_lane", False)
                self.log("'fast_lane_enabled' for SSID: {0} - {1}".format(ssid_name, quality_of_service), "DEBUG")
                self.validate_qos_params(ssid_name, quality_of_service, fast_lane_enabled)
            else:
                self.log("Quality of Service parameters not provided hence validation is not required.", "INFO")
            self.log("Completed validation of quality of service parameters for SSID: {0}.".format(ssid_name), "DEBUG")

            # Validate L2 security and related parameters
            self.log("Starting validation of L2 security, fast transition, fast transition over the DS, WPA encryption and AKM parameters for SSID: {0}."
                     .format(ssid_name), "DEBUG")

            if l2_security:
                fast_transition = ssid.get("fast_transition", "DISABLE")
                self.log("'fast_transition' for SSID: {0} - {1}".format(ssid_name, fast_transition), "DEBUG")

                fast_transition_over_the_ds = ssid.get("fast_transition_over_the_ds")
                self.log("'fast_transition_over_the_ds' for SSID: {0} - {1}".format(ssid_name, fast_transition_over_the_ds), "DEBUG")

                wpa_encryption = ssid.get("wpa_encryption")
                self.log("'wpa_encryption' for SSID: {0} - {1}".format(ssid_name, wpa_encryption), "DEBUG")

                auth_key_management = ssid.get("auth_key_management")
                self.log("'auth_key_management' for SSID: {0} - {1}".format(ssid_name, auth_key_management), "DEBUG")

                cckm_timestamp_tolerance = ssid.get("cckm_timestamp_tolerance")
                self.log("'cckm_timestamp_tolerance' for SSID: {0} - {1}".format(ssid_name, cckm_timestamp_tolerance), "DEBUG")

                self.validate_l2_security_params(ssid_name, l2_security, fast_transition, fast_transition_over_the_ds, wpa_encryption,
                                                 auth_key_management, cckm_timestamp_tolerance)
            else:
                self.log("Global L2 security configuration parameters not provided for SSID: '{0}'.".format(ssid_name))
            self.log("Completed validation of L2 security and related parameters for SSID: {0}.".format(ssid_name), "DEBUG")

            # Validate L3 security and AAA configuration parameters
            self.log("Starting validation of L3 security and AAA parameters for SSID: {0}.".format(ssid_name), "DEBUG")
            aaa = ssid.get("aaa")
            if l3_security:
                self.validate_l3_security_aaa_params(ssid_name, ssid_type, l3_security, aaa)
            else:
                self.log("L3 security and AAA parameters not provided hence validation is not required.", "INFO")
            self.log("Completed validation of L3 security and AAA parameters for SSID: {0}.".format(ssid_name), "DEBUG")

            # Validate MFP Client Protection parameters
            self.log("Starting validation of MFP client protection parameters for SSID: {0}.".format(ssid_name), "DEBUG")
            mfp_client_protection = ssid.get("mfp_client_protection")
            if mfp_client_protection:
                self.validate_mfp_client_protection_params(ssid_name, mfp_client_protection, radio_policy.get("radio_bands"))
            else:
                self.log("MFP Client Protection not provided hence validation is not required.", "INFO")
            self.log("Completed validation of MFP client protection for SSID: {0}.".format(ssid_name), "DEBUG")

            # Validate Protected Management Frame (802.11w) parameters
            self.log("Starting validation of Protected Management Frame parameters for SSID: {0}.".format(ssid_name), "DEBUG")
            protected_management_frame = ssid.get("protected_management_frame")
            if protected_management_frame:
                self.validate_protected_management_frame_params(ssid_name, protected_management_frame)
            else:
                self.log("Protected Management Frame params not provided hence validation is not required.", "INFO")
            self.log("Completed validation of Protected Management Frame parameters for SSID: {0}.".format(ssid_name), "DEBUG")

            # Validate WLAN timeouts parameters
            self.log("Starting validation of WLAN timeouts for SSID: {0}.".format(ssid_name), "DEBUG")
            wlan_timeouts = ssid.get("wlan_timeouts", {})
            if wlan_timeouts:
                self.validate_wlan_timeouts_params(ssid_name, wlan_timeouts)
            else:
                self.log("WLAN timeouts params not provided hence validation is not required.", "INFO")
            self.log("Completed validation of WLAN timeouts for SSID: {0}.".format(ssid_name), "DEBUG")

            # Validate 11v BSS Transition Support parameters
            self.log("Starting validation of 11v BSS Transition Support parameters for SSID: {0}.".format(ssid_name), "DEBUG")
            bss_transition_support = ssid.get("11v_bss_transition_support", {})
            if bss_transition_support:
                self.validate_11v_bss_transition_support_params(self, ssid_name, bss_transition_support)
            else:
                self.log("11v BSS Transition Support parameters not provided hence validation is not required.", "INFO")
            self.log("Completed validation of 11v BSS Transition Support parameters for SSID: {0}.".format(ssid_name), "DEBUG")

            # Validate NAS ID
            self.log("Starting validation of NAS ID parameter for SSID: {0}.".format(ssid_name), "DEBUG")
            nas_id = ssid.get("nas_id", [])
            if nas_id:
                self.validate_nas_id_param(ssid_name, nas_id)
            else:
                self.log("NAS ID parameters not provided hence validation is not required.", "INFO")
            self.log("Completed validation of NAS ID parameter for SSID: {0}.".format(ssid_name), "DEBUG")

            # Validate Client Rate Limit
            self.log("Starting validation of Client Rate Limit for SSID: {0}.".format(ssid_name), "DEBUG")
            client_rate_limit = ssid.get("client_rate_limit")
            if client_rate_limit:
                self.validate_client_rate_limit_param(ssid_name, client_rate_limit)
            self.log("Completed validation of Client Rate Limit for SSID: {0}.".format(ssid_name), "DEBUG")

            # Validate site-specific override settings parameters
            self.log("Starting validation of site-specific override settings for SSID: {0}.".format(ssid_name), "DEBUG")
            sites_specific_override_settings = ssid.get("sites_specific_override_settings")
            if sites_specific_override_settings:
                global_l2_security = l2_security
                global_l3_security = l3_security
                self.validate_sites_specific_override_settings_params(
                    ssid_name, ssid_type, sites_specific_override_settings, global_l3_security, global_l2_security)
            else:
                self.log("Site-specific override settings parameters not provided hence validation is not required.", "INFO")

            self.log("Completed validation of site-specific override settings for SSID: {0}.".format(ssid_name), "DEBUG")

    def validate_interfaces_params(self, interfaces, state):
        """
        Validates the required parameters for interfaces based on the specified state.
        Args:
            interfaces (list): A list of dictionaries, each containing parameters for an interface.
            state (str): The state of the operation, either "merged" or "deleted".
        """
        # Log the start of the validation process
        self.log("Starting validation for interfaces with state: {0}".format(state), "INFO")

        # Determine required parameters based on state
        if state == "merged":
            required_params = ["interface_name", "vlan_id"]
        elif state == "deleted":
            required_params = ["interface_name"]
        else:
            self.msg = "Invalid state provided: {}. Allowed states are 'merged' or 'deleted'.".format(state)
            self.fail_and_exit(self.msg)

        # Iterate over each interface dictionary
        for interface in interfaces:
            # Check for missing required parameters
            missing_params = [param for param in required_params if param not in interface]
            if missing_params:
                self.msg = ("The following required parameters for interface configuration are missing: {}. "
                            "Provided parameters: {}").format(", ".join(missing_params), interface)
                self.fail_and_exit(self.msg)

            # Validate interface_name
            interface_name = interface.get("interface_name")
            self.log("Validating 'interface_name' for interface: {0}".format(interface_name), "DEBUG")
            if interface_name:
                if not (1 <= len(interface_name) <= 31):
                    self.msg = ("The 'interface_name' length must be between 1 and 31 characters. "
                                "Provided 'interface_name': {} (length: {})").format(interface_name, len(interface_name))
                    self.fail_and_exit(self.msg)

            # Validate vlan_id if state is "merged"
            if state == "merged":
                vlan_id = interface.get("vlan_id")
                self.log("Validating 'vlan_id' for interface: {0}".format(interface_name), "DEBUG")
                if vlan_id is not None:
                    if not (1 <= vlan_id <= 4094):
                        self.msg = ("The 'vlan_id' must be between 1 and 4094. "
                                    "Provided 'vlan_id': {}").format(vlan_id)
                        self.fail_and_exit(self.msg)

        # Log the successful validation of interface parameters
        self.msg = "Required interface parameters validated successfully for all interfaces."
        self.status = "success"
        self.log(self.msg, "DEBUG")

    def validate_power_profiles_params(self, power_profiles, state):
        """
        Validates the parameters for power profiles based on the specified state.
        Args:
            power_profiles (list): A list of dictionaries containing power profile parameters.
            state (str): The state of the operation, either "merged" or "deleted".
        Raises:
            Exception: If any validation fails, an exception is raised with a descriptive message.
        """
        # Define required parameters based on state
        if state == "merged":
            required_params = ["power_profile_name", "rules"]
        elif state == "deleted":
            required_params = ["power_profile_name"]
        else:
            self.msg = "Invalid state provided: {}. Allowed states are 'merged' or 'deleted'.".format(state)
            self.fail_and_exit(self.msg)

        # Define valid choices for various parameters
        valid_interface_types = ["ETHERNET", "RADIO", "USB"]
        valid_interface_ids = ["GIGABITETHERNET0", "GIGABITETHERNET1", "LAN1", "LAN2", "LAN3", "6GHZ", "5GHZ", "SECONDARY_5GHZ", "2_4GHZ", "USB0"]
        valid_parameter_types = ["SPEED", "SPATIALSTREAM", "STATE"]
        valid_parameter_values = ["5000MBPS", "2500MBPS", "1000MBPS", "100MBPS", "EIGHT_BY_EIGHT", "FOUR_BY_FOUR", "THREE_BY_THREE",
                                  "TWO_BY_TWO", "ONE_BY_ONE", "DISABLE"]

        # Iterate through each power profile for validation
        for profile in power_profiles:
            # Check for missing required parameters
            missing_params = [param for param in required_params if param not in profile]
            if missing_params:
                self.msg = ("The following required parameters for Power Profile are missing: {}. "
                            "Provided parameters: {}").format(", ".join(missing_params), profile)
                self.fail_and_exit(self.msg)

            # Validate power_profile_name length
            power_profile_name = profile.get("power_profile_name")
            if power_profile_name and len(power_profile_name) > 128:
                self.msg = ("The 'power_profile_name' exceeds the maximum length of 128 characters. "
                            "Provided 'power_profile_name': {} (length: {})").format(power_profile_name, len(power_profile_name))
                self.fail_and_exit(self.msg)

            # Validate power_profile_description length
            power_profile_description = profile.get("power_profile_description")
            if power_profile_description and len(power_profile_description) > 128:
                self.msg = ("The 'power_profile_description' exceeds the maximum length of 128 characters. "
                            "Provided 'power_profile_description': {} (length: {})").format(power_profile_description, len(power_profile_description))
                self.fail_and_exit(self.msg)

            # Validate rules for 'merged' state
            rules = profile.get("rules", [])
            if state == "merged" and not rules:
                self.msg = "Rules are required for the 'merged' state but are missing."
                self.fail_and_exit(self.msg)

            # Validate each rule within the profile
            for rule in rules:
                if "interface_type" not in rule:
                    self.msg = ("'interface_type' is required in each rule. "
                                "Provided rule: {}").format(rule)
                    self.fail_and_exit(self.msg)

                interface_type = rule.get("interface_type")
                if interface_type not in valid_interface_types:
                    self.msg = ("Invalid 'interface_type': {}. Must be one of {}.").format(interface_type, valid_interface_types)
                    self.fail_and_exit(self.msg)

                # Additional validation for USB interface
                if interface_type == "USB":
                    if 'interface_id' in rule and rule['interface_id'] != "USB0":
                        self.msg = ("For 'USB' interface_type, if provided, 'interface_id' must be 'USB0'. "
                                    "Provided rule: {}").format(rule)
                        self.fail_and_exit(self.msg)
                    if 'parameter_type' in rule and rule['parameter_type'] != "STATE":
                        self.msg = ("For 'USB' interface_type, if provided, 'parameter_type' must be 'STATE'. "
                                    "Provided rule: {}").format(rule)
                        self.fail_and_exit(self.msg)
                    if 'parameter_value' in rule and rule['parameter_value'] != "DISABLE":
                        self.msg = ("For 'USB' interface_type, if provided, 'parameter_value' must be 'DISABLE'. "
                                    "Provided rule: {}").format(rule)
                        self.fail_and_exit(self.msg)

                # Additional validation for ETHERNET interface
                if interface_type == "ETHERNET":
                    if 'parameter_type' in rule and rule['parameter_type'] not in ["SPEED", "STATE"]:
                        self.msg = ("For 'ETHERNET' interface_type, if provided, 'parameter_type' must be 'SPEED'. "
                                    "Provided rule: {}").format(rule)
                        self.fail_and_exit(self.msg)

                # Validate interface_id
                interface_id = rule.get("interface_id")
                if interface_id and interface_id not in valid_interface_ids:
                    self.msg = ("Invalid 'interface_id': {}. Must be one of {}.").format(interface_id, valid_interface_ids)
                    self.fail_and_exit(self.msg)

                # Validate parameter_type
                parameter_type = rule.get("parameter_type")
                if parameter_type and parameter_type not in valid_parameter_types:
                    self.msg = ("Invalid 'parameter_type': {}. Must be one of {}.").format(parameter_type, valid_parameter_types)
                    self.fail_and_exit(self.msg)

                # Validate parameter_value
                parameter_value = rule.get("parameter_value")
                if parameter_value and parameter_value not in valid_parameter_values:
                    self.msg = ("Invalid 'parameter_value': {}. Must be one of {}.").format(parameter_value, valid_parameter_values)
                    self.fail_and_exit(self.msg)

        # Log successful validation
        self.log("Power Profile parameters validated successfully.", "INFO")

    def is_valid_password(self, password):
        """
        Validates whether a password meets security criteria.
        Args:
            password (str): The password to validate.
        Returns:
            bool: True if the password is valid, False otherwise.
        """
        # Define a set of default or weak passwords to check against
        default_passwords = {"Cisco", "Ocsic", "cisco", "ocsic"}

        # Check if the password matches any default or weak passwords
        if password in default_passwords:
            self.log("Password matches a default or weak password: {0}".format(password), "DEBUG")
            return False

        # Check if the password contains repeated characters
        if any(password[i] == password[i + 1] == password[i + 2] for i in range(len(password) - 2)):
            self.log("Password contains repeated characters: {0}".format(password), "DEBUG")
            return False

        # Check if the password contains simple sequences
        if "abc" in password or "123" in password:
            self.log("Password contains simple sequences: {0}".format(password), "DEBUG")
            return False

        # If all checks pass, the password is considered valid
        return True

    def validate_ap_profile_management_settings(self, management_settings, access_point_profile_name):
        """
        Validates the management settings of an access point profile.
        Args:
            management_settings (dict): Management settings of the profile.
            access_point_profile_name (str): The name of the access point profile.
        Raises:
            Exception: If any validation fails, an exception is raised with a descriptive message.
        """
        # Log the start of validation for management settings
        self.log("Validating management settings for AP Profile: {0}".format(access_point_profile_name), "INFO")

        # Validate access_point_authentication choice
        valid_auth_choices = ["NO-AUTH", "EAP-TLS", "EAP-PEAP", "EAP-FAST"]
        access_point_authentication = management_settings.get("access_point_authentication")
        self.log("Checking 'access_point_authentication' for AP Profile: {0} - Provided value: {1}"
                 .format(access_point_profile_name, access_point_authentication), "DEBUG")

        if access_point_authentication and access_point_authentication not in valid_auth_choices:
            self.msg = (
                "For AP Profile: {0}, the 'access_point_authentication' is invalid: {1}. "
                "Valid choices are: {2}."
            ).format(access_point_profile_name, access_point_authentication, ", ".join(valid_auth_choices))
            self.fail_and_exit(self.msg)
        else:
            self.log("The 'access_point_authentication' value for AP Profile: {0} is valid.".format(access_point_profile_name), "INFO")

        # Define security policy guidelines
        security_policy = (
            "- Password Policy (recommendations, not mandatory):"
            "  - Length: 8-120 characters"
            "  - At least one uppercase character"
            "  - At least one lowercase character"
            "  - At least one digit"
            "- What's Not Allowed:"
            "  - Default passwords (e.g., 'Cisco') and reverse passwords (e.g., 'Ocsic')"
            "  - Alphabets repeated more than twice in sequence (e.g., 'ccc')"
            "  - Digits repeated more than twice in sequence (e.g., '111')"
            "  - Sequential alphabets (e.g., 'abc')"
            "  - Sequential digits (e.g., '123')"
        )

        # Validate management_password
        management_password = management_settings.get("management_password")
        self.log("Checking 'management_password' for AP Profile: {0}".format(access_point_profile_name), "DEBUG")

        if management_password and not self.is_valid_password(management_password):
            self.msg = (
                "For AP Profile: {0}, the 'management_password' does not meet the security criteria.{1}"
            ).format(access_point_profile_name, security_policy)
            self.fail_and_exit(self.msg)
        else:
            self.log("The 'management_password' for AP Profile: {0} meets the security criteria.".format(access_point_profile_name), "INFO")

        # Validate management_enable_password
        management_enable_password = management_settings.get("management_enable_password")
        self.log("Checking 'management_enable_password' for AP Profile: {0}".format(access_point_profile_name), "DEBUG")

        if management_enable_password and not self.is_valid_password(management_enable_password):
            self.msg = (
                "For AP Profile: {0}, the 'management_enable_password' does not meet the security criteria.{1}"
            ).format(access_point_profile_name, security_policy)
            self.fail_and_exit(self.msg)
        else:
            self.log("The 'management_enable_password' for AP Profile: {0} meets the security criteria.".format(access_point_profile_name), "INFO")

    def validate_ap_profile_security_settings(self, security_settings, access_point_profile_name):
        """
        Validates the security settings of an access point profile.
        Args:
            security_settings (dict): Security settings of the profile.
            access_point_profile_name (str): The name of the access point profile.
        Raises:
            Exception: If any validation fails, an exception is raised with a descriptive message.
        """
        # Log the start of validation for security settings
        self.log("Validating security settings for AP Profile: {0}".format(access_point_profile_name), "INFO")

        # Validate minimum_rssi
        minimum_rssi = security_settings.get("minimum_rssi")
        self.log("Checking 'minimum_rssi' for AP Profile: {0} - Provided value: {1}".format(access_point_profile_name, minimum_rssi), "DEBUG")
        if minimum_rssi is not None:
            # Check if the minimum_rssi value is within the valid range
            if not (-128 <= minimum_rssi <= -70):
                self.msg = (
                    "For AP Profile: {0}, the 'minimum_rssi' value is out of range. Provided value: {1}. "
                    "Valid range is -128 to -70 decibel milliwatts."
                ).format(access_point_profile_name, minimum_rssi)
                self.fail_and_exit(self.msg)
            else:
                self.log("The 'minimum_rssi' value for AP Profile: {0} is within the valid range.".format(access_point_profile_name), "INFO")

        # Validate transient_interval
        transient_interval = security_settings.get("transient_interval")
        self.log("Checking 'transient_interval' for AP Profile: {0} - Provided value: {1}".format(access_point_profile_name, transient_interval), "DEBUG")
        if transient_interval is not None:
            # Check if the transient_interval value is within the valid range
            if not (transient_interval == 0 or 120 <= transient_interval <= 1800):
                self.msg = (
                    "For AP Profile: {0}, the 'transient_interval' value is out of range. Provided value: {1}. "
                    "Valid values are 0 or between 120 and 1800."
                ).format(access_point_profile_name, transient_interval)
                self.fail_and_exit(self.msg)
            else:
                self.log("The 'transient_interval' value for AP Profile: {0} is within the valid range.".format(access_point_profile_name), "INFO")

        # Validate report_interval
        report_interval = security_settings.get("report_interval")
        self.log("Checking 'report_interval' for AP Profile: {0} - Provided value: {1}".format(access_point_profile_name, report_interval), "DEBUG")
        if report_interval is not None:
            # Check if the report_interval value is within the valid range
            if not (10 <= report_interval <= 300):
                self.msg = (
                    "For AP Profile: {0}, the 'report_interval' value is out of range. Provided value: {1}. "
                    "Valid range is 10 to 300."
                ).format(access_point_profile_name, report_interval)
                self.fail_and_exit(self.msg)
            else:
                self.log("The 'report_interval' value for AP Profile: {0} is within the valid range.".format(access_point_profile_name), "INFO")

    def validate_ap_profile_mesh_settings(self, mesh_settings, access_point_profile_name):
        """
        Validates the mesh settings of an access point profile.
        Args:
            mesh_settings (dict): Mesh settings of the profile.
            access_point_profile_name (str): The name of the access point profile.
        Raises:
            Exception: If any validation fails, an exception is raised with a descriptive message.
        """
        # Log the start of validation for mesh settings
        self.log("Validating mesh settings for AP Profile: {0}".format(access_point_profile_name), "INFO")

        # Define valid choices for parameters
        valid_rap_downlink_backhaul_choices = ["5 GHz", "2.4 GHz"]
        valid_radio_band_types_5ghz = ["auto", "802.11abg", "802.12ac", "802.11ax", "802.11n"]
        valid_radio_band_types_2_4ghz = ["auto", "802.11abg", "802.11ax", "802.11n"]

        # Validate range
        mesh_range = mesh_settings.get("range")
        self.log("Checking 'range' for AP Profile: {0} - Provided value: {1}".format(access_point_profile_name, mesh_range), "DEBUG")
        if mesh_range is not None:
            if not (150 <= mesh_range <= 132000):
                self.msg = (
                    "For Profile: {0}, the 'range' value in mesh settings is out of range. Provided value: {1}. "
                    "Valid range is 150 to 132000."
                ).format(access_point_profile_name, mesh_range)
                self.fail_and_exit(self.msg)
            else:
                self.log("The 'range' value for AP Profile: {0} is within the valid range.".format(access_point_profile_name), "INFO")

        # Validate rap_downlink_backhaul
        rap_downlink_backhaul = mesh_settings.get("rap_downlink_backhaul")
        self.log("Checking 'rap_downlink_backhaul' for AP Profile: {0} - Provided value: {1}".format(access_point_profile_name, rap_downlink_backhaul), "DEBUG")
        if rap_downlink_backhaul and rap_downlink_backhaul not in valid_rap_downlink_backhaul_choices:
            self.msg = (
                "For Profile: {0}, the 'rap_downlink_backhaul' is invalid: {1}. "
                "Valid choices are: {2}."
            ).format(access_point_profile_name, rap_downlink_backhaul, ", ".join(valid_rap_downlink_backhaul_choices))
            self.fail_and_exit(self.msg)
        else:
            self.log("The 'rap_downlink_backhaul' value for AP Profile: {0} is valid.".format(access_point_profile_name), "INFO")

        # Validate ghz_5_radio_band_type
        ghz_5_radio_band_type = mesh_settings.get("ghz_5_radio_band_type")
        self.log("Checking 'ghz_5_radio_band_type' for AP Profile: {0} - Provided value: {1}".format(access_point_profile_name, ghz_5_radio_band_type), "DEBUG")
        if ghz_5_radio_band_type and ghz_5_radio_band_type not in valid_radio_band_types_5ghz:
            self.msg = (
                "For Profile: {0}, the 'ghz_5_radio_band_type' is invalid: {1}. "
                "Valid choices are: {2}."
            ).format(access_point_profile_name, ghz_5_radio_band_type, ", ".join(valid_radio_band_types_5ghz))
            self.fail_and_exit(self.msg)
        else:
            self.log("The 'ghz_5_radio_band_type' value for AP Profile: {0} is valid.".format(access_point_profile_name), "INFO")

        # Validate ghz_2_point_4_radio_band_type
        ghz_2_point_4_radio_band_type = mesh_settings.get("ghz_2_point_4_radio_band_type")
        self.log("Checking 'ghz_2_point_4_radio_band_type' for AP Profile: {0} - Provided value: {1}"
                 .format(access_point_profile_name, ghz_2_point_4_radio_band_type), "DEBUG")
        if ghz_2_point_4_radio_band_type and ghz_2_point_4_radio_band_type not in valid_radio_band_types_2_4ghz:
            self.msg = (
                "For Profile: {0}, the 'ghz_2_point_4_radio_band_type' is invalid: {1}. "
                "Valid choices are: {2}."
            ).format(access_point_profile_name, ghz_2_point_4_radio_band_type, ", ".join(valid_radio_band_types_2_4ghz))
            self.fail_and_exit(self.msg)
        else:
            self.log("The 'ghz_2_point_4_radio_band_type' value for AP Profile: {0} is valid.".format(access_point_profile_name), "INFO")

        # Validate the bridge_group_name length
        bridge_group_name = mesh_settings.get("bridge_group_name")
        self.log("Checking 'bridge_group_name' for AP Profile: {0} - Provided value: {1}".format(access_point_profile_name, bridge_group_name), "DEBUG")
        if bridge_group_name is not None:
            if not (0 <= len(bridge_group_name) <= 10):
                self.msg = (
                    "For Profile: {0}, the 'bridge_group_name' length in mesh settings is out of range. Provided value: '{1}' "
                    "with length {2}. Valid length range is 0 to 10 characters."
                ).format(access_point_profile_name, bridge_group_name, len(bridge_group_name))
                self.fail_and_exit(self.msg)
            else:
                self.log("The 'bridge_group_name' for AP Profile: {0} is within the valid length range.".format(access_point_profile_name), "INFO")

    def validate_ap_profile_power_settings(self, power_settings, access_point_profile_name):
        """
        Validates the power settings of an access point profile.
        Args:
            power_settings (dict): Power settings of the profile.
            access_point_profile_name (str): The name of the access point profile.
        Raises:
            Exception: If any validation fails, an exception is raised with a descriptive message.
        """
        # Log the start of validation for power settings
        self.log("Validating power settings for AP Profile: {0}".format(access_point_profile_name), "INFO")

        # Check if power settings are provided
        if not power_settings:
            self.log("No power settings provided for AP Profile: {0}".format(access_point_profile_name), "INFO")
            return

        # Check if calendar power profiles are provided
        calendar_power_profiles = power_settings.get("calendar_power_profiles")
        if not calendar_power_profiles:
            self.log("No calendar power profiles provided for AP Profile: {0}".format(access_point_profile_name), "DEBUG")
            return

        # Iterate over each calendar power profile
        for profile in calendar_power_profiles:
            self.log("Validating calendar power profile for AP Profile: {0}".format(access_point_profile_name), "DEBUG")

            # Check if 'ap_power_profile_name' is provided
            if 'ap_power_profile_name' not in profile:
                self.msg = "For AP Profile: {0}, 'ap_power_profile_name' is required in calendar power profiles.".format(access_point_profile_name)
                self.fail_and_exit(self.msg)

            # Check if 'scheduler_type' is provided and valid
            scheduler_type = profile.get("scheduler_type")
            valid_scheduler_types = ["DAILY", "WEEKLY", "MONTHLY"]
            if not scheduler_type or scheduler_type not in valid_scheduler_types:
                self.msg = (
                    "For AP Profile: {0}, 'scheduler_type' is invalid or not provided. "
                    "Valid choices are: {1}."
                ).format(access_point_profile_name, ", ".join(valid_scheduler_types))
                self.fail_and_exit(self.msg)

            self.log("The 'scheduler_type' for AP Profile: {0} is valid.".format(access_point_profile_name), "INFO")

            # Validate fields based on scheduler_type
            if scheduler_type == "DAILY":
                if not profile.get("scheduler_start_time") or not profile.get("scheduler_end_time"):
                    self.msg = (
                        "For AP Profile: {0}, 'scheduler_start_time' and 'scheduler_end_time' are required for DAILY scheduler."
                    ).format(access_point_profile_name)
                    self.fail_and_exit(self.msg)

            elif scheduler_type == "WEEKLY":
                if not profile.get("scheduler_start_time") or not profile.get("scheduler_end_time") or not profile.get("scheduler_days_list"):
                    self.msg = (
                        "For AP Profile: {0}, 'scheduler_start_time', 'scheduler_end_time', and 'scheduler_days' are required for WEEKLY scheduler."
                    ).format(access_point_profile_name)
                    self.fail_and_exit(self.msg)

            elif scheduler_type == "MONTHLY":
                if not profile.get("scheduler_dates_list") or not profile.get("scheduler_start_time") or not profile.get("scheduler_end_time"):
                    self.msg = (
                        "For AP Profile: {0}, 'scheduler_start_date', 'scheduler_end_date', 'scheduler_start_time', and "
                        "'scheduler_end_time' are required for MONTHLY scheduler."
                    ).format(access_point_profile_name)
                    self.fail_and_exit(self.msg)

            # Validate the format of scheduler_start_time and scheduler_end_time
            time_pattern = re.compile(r'^(1[0-2]|0?[1-9]):([0-5][0-9])\s?(AM|PM)$')
            start_time = profile.get("scheduler_start_time")
            end_time = profile.get("scheduler_end_time")
            if start_time and not time_pattern.match(start_time):
                self.msg = (
                    "For  AP Profile: {0}, 'scheduler_start_time' is not in the correct format. "
                    "Provided value: '{1}'. Expected format: 'hh:mm AM/PM'."
                ).format(access_point_profile_name, start_time)
                self.fail_and_exit(self.msg)

            if end_time and not time_pattern.match(end_time):
                self.msg = (
                    "For AP Profile: {0}, 'scheduler_end_time' is not in the correct format. "
                    "Provided value: '{1}'. Expected format: 'hh:mm AM/PM'."
                ).format(access_point_profile_name, end_time)
                self.fail_and_exit(self.msg)

    def validate_access_point_profiles_params(self, access_point_profiles, state):
        """
        Validates the parameters for access point profiles based on the specified state.
        Args:
            access_point_profiles (list): A list of dictionaries containing access point profile parameters.
            state (str): The state of the operation, either "merged" or "deleted".
        """
        # Log the start of the validation process
        self.log("Starting validation for Access Point Profiles with state: {0}".format(state), "INFO")

        # Iterate over each access point profile
        for profile in access_point_profiles:
            self.log("Validating profile: {0}".format(profile.get('access_point_profile_name', 'Unknown')), "DEBUG")

            # Validate presence of access_point_profile_name
            if 'access_point_profile_name' not in profile:
                self.msg = "Required parameter 'access_point_profile_name' not provided for the Access Point Profile: {0}.".format(profile)
                self.fail_and_exit(self.msg)

            # Validate access_point_profile_name length
            access_point_profile_name = profile['access_point_profile_name']
            if len(access_point_profile_name) > 32:
                self.msg = (
                    "The 'access_point_profile_name' exceeds the maximum length of 32 characters. "
                    "Provided 'access_point_profile_name': {0} (length: {1})"
                ).format(access_point_profile_name, len(access_point_profile_name))
                self.fail_and_exit(self.msg)
            else:
                self.log("The 'access_point_profile_name' for profile {0} is valid.".format(access_point_profile_name), "INFO")

            # State-specific validation for "merged"
            if state == "merged":
                # Validate access_point_profile_description length if provided
                self.log("Performing 'merged' state validation for profile: {0}".format(access_point_profile_name), "INFO")

                access_point_profile_description = profile.get("access_point_profile_description")
                if access_point_profile_description:
                    self.log("Validating 'access_point_profile_description' for profile: {0}".format(access_point_profile_name), "DEBUG")
                    if len(access_point_profile_description) > 241:
                        self.msg = (
                            "For AP Profile: {0} the 'access_point_profile_description' exceeds the maximum length of 241 characters. "
                            "Provided 'access_point_profile_description': {1} (length: {2})"
                        ).format(access_point_profile_name, access_point_profile_description, len(access_point_profile_description))
                        self.fail_and_exit(self.msg)
                    else:
                        self.log("The 'access_point_profile_description' for profile {0} is valid.".format(access_point_profile_name), "INFO")

                # Validate management_settings
                management_settings = profile.get("management_settings")
                if management_settings:
                    self.log("Validating 'management_settings' for profile: {0}".format(access_point_profile_name), "DEBUG")
                    self.validate_ap_profile_management_settings(management_settings, access_point_profile_name)

                # Validate security_settings
                security_settings = profile.get("security_settings")
                if security_settings:
                    self.log("Validating 'security_settings' for profile: {0}".format(access_point_profile_name), "DEBUG")
                    self.validate_ap_profile_security_settings(security_settings, access_point_profile_name)

                # Validate mesh_settings
                mesh_settings = profile.get("mesh_settings")
                if mesh_settings:
                    self.log("Validating 'mesh_settings' for profile: {0}".format(access_point_profile_name), "DEBUG")
                    self.validate_ap_profile_mesh_settings(mesh_settings, access_point_profile_name)

                # Validate power_settings
                power_settings = profile.get("power_settings")
                if power_settings:
                    self.log("Validating 'power_settings' for profile: {0}".format(access_point_profile_name), "DEBUG")
                    self.validate_ap_profile_power_settings(power_settings, access_point_profile_name)

                # Validate country_code
                country_code = profile.get("country_code")
                valid_country_codes = [
                    "Afghanistan", "Albania", "Algeria", "Angola", "Argentina", "Australia", "Austria", "Bahamas", "Bahrain",
                    "Bangladesh", "Barbados", "Belarus", "Belgium", "Bhutan", "Bolivia", "Bosnia", "Botswana", "Brazil", "Brunei",
                    "Bulgaria", "Burundi", "Cambodia", "Cameroon", "Canada", "Chile", "China", "Colombia", "Costa Rica", "Croatia",
                    "Cuba", "Cyprus", "Czech Republic", "Democratic Republic of the Congo", "Denmark", "Dominican Republic",
                    "Ecuador", "Egypt", "El Salvador", "Estonia", "Ethiopia", "Fiji", "Finland", "France", "Gabon", "Georgia", "Germany",
                    "Ghana", "Gibraltar", "Greece", "Guatemala", "Honduras", "Hong Kong", "Hungary", "Iceland", "India", "Indonesia",
                    "Iraq", "Ireland", "Isle of Man", "Israel", "Israel (Outdoor)", "Italy", "Ivory Coast (Cote dIvoire)",
                    "Jamaica", "Japan 2(P)", "Japan 4(Q)", "Jersey", "Jordan", "Kazakhstan", "Kenya", "Korea Extended (CK)",
                    "Kosovo", "Kuwait", "Laos", "Latvia", "Lebanon", "Libya", "Liechtenstein", "Lithuania", "Luxembourg", "Macao",
                    "Macedonia", "Malaysia", "Malta", "Mauritius", "Mexico", "Moldova", "Monaco", "Mongolia", "Montenegro", "Morocco",
                    "Myanmar", "Namibia", "Nepal", "Netherlands", "New Zealand", "Nicaragua", "Nigeria", "Norway", "Oman", "Pakistan",
                    "Panama", "Paraguay", "Peru", "Philippines", "Poland", "Portugal", "Puerto Rico", "Qatar", "Romania", "Russian Federation",
                    "San Marino", "Saudi Arabia", "Serbia", "Singapore", "Slovak Republic", "Slovenia", "South Africa", "Spain", "Sri Lanka",
                    "Sudan", "Sweden", "Switzerland", "Taiwan", "Thailand", "Trinidad", "Tunisia", "Turkey", "Uganda", "Ukraine", "United Arab Emirates",
                    "United Kingdom", "United Republic of Tanzania", "United States", "Uruguay", "Uzbekistan", "Vatican City State",
                    "Venezuela", "Vietnam", "Yemen", "Zambia", "Zimbabwe"
                ]

                self.log("Validating 'country_code' for profile: {0} - Provided value: {1}".format(access_point_profile_name, country_code), "DEBUG")
                if country_code and country_code not in valid_country_codes:
                    self.msg = (
                        "For Profile: {0}, the 'country_code' is invalid: {1}. "
                        "Valid choices are: {2}."
                    ).format(access_point_profile_name, country_code, ", ".join(valid_country_codes))
                    self.fail_and_exit(self.msg)
                else:
                    self.log("The 'country_code' for profile {0} is valid.".format(access_point_profile_name), "INFO")

                # Validate time_zone
                time_zone = profile.get("time_zone")
                valid_time_zones = ["NOT CONFIGURED", "CONTROLLER", "DELTA FROM CONTROLLER"]
                self.log("Validating 'time_zone' for profile: {0} - Provided value: {1}".format(access_point_profile_name, time_zone), "DEBUG")
                if time_zone and time_zone not in valid_time_zones:
                    self.msg = (
                        "For Profile: {0}, the 'time_zone' is invalid: {1}. "
                        "Valid choices are: {2}."
                    ).format(access_point_profile_name, time_zone, ", ".join(valid_time_zones))
                    self.fail_and_exit(self.msg)
                else:
                    self.log("The 'time_zone' for profile {0} is valid.".format(access_point_profile_name), "INFO")

                # Validate time_zone_offset_hour
                time_zone_offset_hour = profile.get("time_zone_offset_hour")
                self.log("Validating 'time_zone_offset_hour' for profile: {0} - Provided value: {1}".format(
                    access_point_profile_name, time_zone_offset_hour), "DEBUG")
                if time_zone_offset_hour is not None:
                    if not (-12 <= time_zone_offset_hour <= 14):
                        self.msg = (
                            "For Profile: {0}, the 'time_zone_offset_hour' is out of range. "
                            "Provided value: {1}. Valid range is -12 to 14."
                        ).format(access_point_profile_name, time_zone_offset_hour)
                        self.fail_and_exit(self.msg)
                    else:
                        self.log("The 'time_zone_offset_hour' for profile {0} is valid.".format(access_point_profile_name), "INFO")

                # Validate time_zone_offset_minutes
                time_zone_offset_minutes = profile.get("time_zone_offset_minutes")
                self.log("Validating 'time_zone_offset_minutes' for profile: {0} - Provided value: {1}".format(
                    access_point_profile_name, time_zone_offset_minutes), "DEBUG")
                if time_zone_offset_minutes is not None:
                    if not (0 <= time_zone_offset_minutes < 60):
                        self.msg = (
                            "For Profile: {0}, the 'time_zone_offset_minutes' is out of range. "
                            "Provided value: {1}. Valid range is 0 to 59."
                        ).format(access_point_profile_name, time_zone_offset_minutes)
                        self.fail_and_exit(self.msg)
                    else:
                        self.log("The 'time_zone_offset_minutes' for profile {0} is valid.".format(access_point_profile_name), "INFO")

                # Validate maximum_client_limit
                maximum_client_limit = profile.get("maximum_client_limit")
                self.log("Validating 'maximum_client_limit' for profile: {0} - Provided value: {1}".format(
                    access_point_profile_name, maximum_client_limit), "DEBUG")
                if maximum_client_limit is not None:
                    if not (0 <= maximum_client_limit <= 1200):
                        self.msg = (
                            "For Profile: {0}, the 'maximum_client_limit' is out of range. "
                            "Provided value: {1}. Valid range is 0 to 1200."
                        ).format(access_point_profile_name, maximum_client_limit)
                        self.fail_and_exit(self.msg)
                    else:
                        self.log("The 'maximum_client_limit' for profile {0} is valid.".format(access_point_profile_name), "INFO")

    def validate_list_values(self, values, allowed_values, param_name, profile_name):
        """
        Validate that all values in a given list exist in the set of allowed values.
        Args:
            values (list): The list of values to validate.
            allowed_values (set): The set of allowed values.
            param_name (str): The parameter name being validated.
            profile_name (str): The profile name associated with the validation.
        Raises:
            Calls self.fail_and_exit with an error message if validation fails.
        """
        # Log the start of the validation process for the specified parameter
        self.log("Validating {0} in profile {1} against allowed values: {2}".format(param_name, profile_name, allowed_values), "DEBUG")

        # Check if all values are within the set of allowed values
        if not set(values).issubset(allowed_values):
            self.msg = "Invalid values in {0} for profile {1}. Allowed values: {2}".format(param_name, profile_name, allowed_values)
            self.fail_and_exit(self.msg)

        # Log the successful validation of the parameter
        self.log("Validation successful for {0} in profile {1}".format(param_name, profile_name), "INFO")

    def validate_range(self, value, min_val, max_val, param_name, profile_name):
        """
        Validate that a given value falls within the specified range.
        Args:
            value (int/float): The value to validate.
            min_val (int/float): The minimum acceptable value.
            max_val (int/float): The maximum acceptable value.
            param_name (str): The parameter name being validated.
            profile_name (str): The profile name associated with the validation.
        """
        # Log the start of the validation process for the specified parameter
        self.log("Validating {0} in profile {1}. Expected range: {2} to {3}".format(param_name, profile_name, min_val, max_val), "DEBUG")

        # Ensure the correct interpretation of the range
        if min_val > max_val:
            min_val, max_val = max_val, min_val

        # Check if the value is within the specified range
        if not (min_val <= value <= max_val):
            self.msg = "{0} in profile {1} must be between {2} and {3}".format(param_name, profile_name, min_val, max_val)
            self.fail_and_exit(self.msg)

        # Log the successful validation of the parameter
        self.log("Validation successful for {0} in profile {1}".format(param_name, profile_name), "INFO")

    def validate_mandatory_data_rates(self, mandatory_list, supported_list, param_name, profile_name):
        """
        Validate that mandatory data rates are a subset of supported data rates
        and do not exceed the maximum allowed length.
        Args:
            mandatory_list (list): The list of mandatory data rates.
            supported_list (list): The list of supported data rates.
            param_name (str): The parameter name being validated.
            profile_name (str): The profile name associated with the validation.
        Raises:
            Calls self.fail_and_exit with an error message if validation fails.
        """
        # Log the start of the validation process for mandatory data rates
        self.log("Validating {0} in profile {1}. Checking subset and max length constraints.".format(param_name, profile_name), "DEBUG")

        # Check if the number of mandatory data rates exceeds the allowed limit
        if len(mandatory_list) > 2:
            self.msg = "{0} in profile {1} should not exceed 2 values. Current count: {2}".format(param_name, profile_name, len(mandatory_list))
            self.fail_and_exit(self.msg)

        # Check if all mandatory data rates are a subset of the supported data rates
        if not set(mandatory_list).issubset(supported_list):
            self.msg = "Values in {0} must be a subset of supported data rates in profile {1}".format(param_name, profile_name)
            self.fail_and_exit(self.msg)

        # Log the successful validation of mandatory data rates
        self.log("Validation successful for {0} in profile {1}".format(param_name, profile_name), "INFO")

    def validate_radio_frequency_profiles_params(self, radio_frequency_profiles, state):
        """
        Validate the parameters for radio frequency profiles based on the specified state.
        Args:
            radio_frequency_profiles (list): A list of dictionaries containing radio frequency profile parameters.
            state (str): The state of the operation, either "merged" or "deleted".
        Raises:
            ValueError: If any validation fails.
        """
        # Log the start of the validation process
        self.log("Starting validation for Radio Frequency Profiles with state: {0}".format(state), "INFO")

        # Define validation rules for different radio frequency profile parameters
        VALIDATION_RULES = {
            "common": {
                "parent_profile": ["HIGH", "TYPICAL", "LOW", "CUSTOM"],
                "rx_sop_threshold": ["HIGH", "MEDIUM", "LOW", "AUTO", "CUSTOM"],
                "custom_rx_sop_threshold": (-85, -60),
                "tpc_power_threshold": (-80, -50),
                "minimum_power_level": (-10, 30),
                "maximum_power_level": (-10, 30),
                "client_limit": (0, 500),
                "coverage_hole_detection": {
                    "minimum_client_level": (1, 200),
                    "data_rssi_threshold": (-90, -60),
                    "voice_rssi_threshold": (-90, -60),
                    "exception_level": (0, 100),
                },
                "spatial_resuse": {
                    "non_srg_obss_pd_max_threshold": (-82, -62),
                    "srg_obss_pd_min_threshold": (-82, -62),
                    "srg_obss_pd_max_threshold": (-82, -62),
                },
            },
            "radio_bands_2_4ghz_settings": {
                "dca_channels_list": {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
                "suppported_data_rates_list": {1, 2, 5.5, 6, 9, 11, 12, 18, 24, 36, 48, 54},
                "mandatory_data_rates_list": {
                    "max_length": 2,
                    "subset_of": "suppported_data_rates_list",
                },
            },
            "radio_bands_5ghz_settings": {
                "channel_width": ["20", "40", "80", "160", "best"],
                "dca_channels_list": {
                    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
                    132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173
                },
                "suppported_data_rates_list": {6, 9, 12, 18, 24, 36, 48, 54},
                "mandatory_data_rates_list": {
                    "max_length": 2,
                    "subset_of": "suppported_data_rates_list",
                },
                "flexible_radio_assigment": {
                    "client_select": (0, 100),
                    "client_reset": (0, 100),
                },
            },
            "radio_bands_6ghz_settings": {
                "parent_profile": ["CUSTOM"],
                "minimum_dbs_channel_width": {20, 40, 80, 160, 320},
                "maximum_dbs_channel_width": {20, 40, 80, 160, 320},
                "dca_channels_list": {
                    1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93,
                    97, 101, 105, 109, 113, 117, 121, 125, 129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169,
                    173, 177, 181, 185, 189, 193, 197, 201, 205, 209, 213, 217, 221, 225, 229, 233
                },
                "suppported_data_rates_list": {6, 9, 12, 18, 24, 36, 48, 54},
                "mandatory_data_rates_list": {
                    "max_length": 2,
                    "subset_of": "suppported_data_rates_list",
                },
                "discovery_frames_6ghz": ["None", "Broadcast Probe Response", "FILS Discovery"],
                "flexible_radio_assigment": {
                    "client_reset_count": (1, 10),
                    "client_utilization_threshold": (1, 100),
                },
            },
        }

        # Iterate over each profile in the list
        for profile in radio_frequency_profiles:
            # Extract profile name, default to 'Unknown' if not present
            profile_name = profile.get('radio_frequency_profile_name', 'Unknown')
            self.log("Validating profile: {0}".format(profile_name), "DEBUG")

            # Check if the profile name exceeds the maximum allowed length
            if 'radio_frequency_profile_name' in profile and len(profile['radio_frequency_profile_name']) > 30:
                self.msg = "Profile name '{0}' exceeds max length.".format(profile['radio_frequency_profile_name'])
                self.fail_and_exit(self.msg)

            # Proceed with additional checks if the state is "merged"
            if state == "merged":
                # Ensure required parameters are present
                if 'default_rf_profile' not in profile or 'radio_bands' not in profile:
                    self.msg = "Required parameters missing for profile: {0}. Required parameters are 'default_rf_profile', 'radio_bands'.".format(profile_name)
                    self.fail_and_exit(self.msg)

                # Validate that the values in 'radio_bands' are from the acceptable ones [2.4, 5, 6]
                valid_radio_bands = {2.4, 5, 6}
                radio_bands = profile['radio_bands']

                # Validate that all radio_bands are in the set of acceptable bands
                if not set(radio_bands).issubset(valid_radio_bands):
                    self.msg = "Invalid values in 'radio_bands' for profile {0}. Allowed values: {1}".format(profile_name, valid_radio_bands)
                    self.fail_and_exit(self.msg)

                # Validate each band according to defined rules
                for band_key, band_rules in VALIDATION_RULES.items():
                    if band_key in profile:
                        band_settings = profile[band_key]

                        for param, rule in VALIDATION_RULES["common"].items():
                            # Check each parameter against its respective validation rule
                            if param in band_settings:
                                value = band_settings[param]

                                # Check if the parameter value is within the allowed list
                                if isinstance(rule, list) and value not in rule:
                                    self.msg = "Invalid {0} in profile {1}. Allowed: {2}".format(param, profile_name, rule)
                                    self.fail_and_exit(self.msg)

                                # Validate set constraints
                                elif isinstance(rule, set):
                                    # Convert value to a list if it's not a list
                                    if not isinstance(value, list):
                                        value = [value]
                                    self.validate_list_values(value, rule, param, profile_name)

                                # Validate range constraints
                                elif isinstance(rule, tuple):
                                    self.validate_range(value, *rule, param, profile_name)

                                # Validate dict constraints
                                elif isinstance(rule, dict) and isinstance(value, dict):
                                    for sub_param, sub_rule in rule.items():
                                        if sub_param in value:
                                            sub_value = value[sub_param]
                                            self.validate_range(sub_value, *sub_rule, sub_param, profile_name)

                        for param, rule in band_rules.items():
                            # Only validate if the parameter is provided
                            if param in band_settings:
                                value = band_settings[param]

                                # Check if the parameter value is within the allowed list
                                if isinstance(rule, list) and value not in rule:
                                    self.msg = "Invalid {0} in profile {1}. Allowed: {2}".format(param, profile_name, rule)
                                    self.fail_and_exit(self.msg)

                                # Validate set constraints
                                elif isinstance(rule, set):
                                    # Convert value to a list if it's not a list
                                    if not isinstance(value, list):
                                        value = [value]
                                    self.validate_list_values(value, rule, param, profile_name)

                                # Validate range constraints
                                elif isinstance(rule, tuple):
                                    self.validate_range(value, *rule, param, profile_name)

                                # Validate mandatory data rates
                                elif isinstance(rule, dict) and "subset_of" in rule:
                                    self.validate_mandatory_data_rates(value, band_settings[rule["subset_of"]], param, profile_name)

                                # Validate dict constraints
                                elif isinstance(rule, dict) and isinstance(value, dict):
                                    for sub_param, sub_rule in rule.items():
                                        if sub_param in value:
                                            sub_value = value[sub_param]
                                            self.validate_range(sub_value, *sub_rule, sub_param, profile_name)

            # Log the completion of validation for the current profile
            self.log("Completed validation for profile: {0}".format(profile_name), "INFO")

        # Log the completion of the validation process for all profiles
        self.log("Completed validation for Radio Frequency Profiles with state: {0}".format(state), "INFO")

    def validate_anchor_groups_params(self, anchor_groups, state):
        """
        Validates the parameters of anchor groups based on specified conditions and state.
        Args:
            anchor_groups (list): A list of dictionaries containing parameters for each anchor group.
            state (str): The state of the operation, either "merged" or "deleted".
        """
        # Determine required parameters based on state
        if state == "merged":
            required_params = ["anchor_group_name", "mobility_anchors"]
        elif state == "deleted":
            required_params = ["anchor_group_name"]
        else:
            self.msg = "Invalid state provided: {0}. Allowed states are 'merged' or 'deleted'.".format(state)
            self.fail_and_exit(self.msg)

        # Iterate over each anchor group dictionary
        for anchor_group in anchor_groups:
            # Check for missing required parameters
            missing_params = [param for param in required_params if param not in anchor_group]
            if missing_params:
                self.msg = ("The following required parameters for anchor group configuration are missing: {0}. "
                            "Provided parameters: {1}").format(", ".join(missing_params), anchor_group)
                self.fail_and_exit(self.msg)

            # Validate anchor_group_name
            anchor_group_name = anchor_group.get("anchor_group_name")
            if anchor_group_name:
                if not (1 <= len(anchor_group_name) <= 32):
                    self.msg = ("The 'anchor_group_name' length must be between 1 and 32 characters. "
                                "Provided 'anchor_group_name': {0} (length: {1})").format(anchor_group_name, len(anchor_group_name))
                    self.fail_and_exit(self.msg)

            # Validate mobility_anchors if state is "merged"
            if state == "merged":
                mobility_anchors = anchor_group.get("mobility_anchors")
                if mobility_anchors is not None:
                    if not isinstance(mobility_anchors, list) or len(mobility_anchors) > 3:
                        self.msg = ("The 'mobility_anchors' list must not exceed 3 entries. "
                                    "Provided 'mobility_anchors': {0}").format(mobility_anchors)
                        self.fail_and_exit(self.msg)

                    for anchor in mobility_anchors:
                        # Validate device_name or device_ip_address is required
                        if not anchor.get("device_name") and not anchor.get("device_ip_address"):
                            self.msg = ("Either 'device_name' or 'device_ip_address' is required for each mobility anchor. "
                                        "Provided anchor: {0}").format(anchor)
                            self.fail_and_exit(self.msg)

                        # Validate device_ip_address format
                        device_ip_address = anchor.get("device_ip_address")
                        if device_ip_address and not self.is_valid_ipv4(device_ip_address):
                            self.msg = ("Device IP Address '{0}' is not in a valid IPv4 format.").format(device_ip_address)
                            self.fail_and_exit(self.msg)

                        # Validate device_mac_address format
                        device_mac_address = anchor.get("device_mac_address")
                        if device_mac_address and not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', device_mac_address):
                            self.msg = ("Device MAC Address '{0}' is not in a valid format.").format(device_mac_address)
                            self.fail_and_exit(self.msg)

                        # Validate device_priority value
                        device_priority = anchor.get("device_priority")
                        if device_priority is not None and not (1 <= device_priority <= 3):
                            self.msg = ("Device priority '{0}' must be between 1 and 3.").format(device_priority)
                            self.fail_and_exit(self.msg)

                        # Validate device_nat_ip_address format
                        device_nat_ip_address = anchor.get("device_nat_ip_address")
                        if device_nat_ip_address and not self.is_valid_ipv4(device_nat_ip_address):
                            self.msg = ("Device NAT IP Address '{0}' is not in a valid IPv4 format.").format(device_nat_ip_address)
                            self.fail_and_exit(self.msg)

                        # Validate mobility_group_name
                        mobility_group_name = anchor.get("mobility_group_name")
                        if mobility_group_name and not re.match(r'^[a-zA-Z0-9_]{1,31}$', mobility_group_name):
                            self.msg = ("Mobility Group Name must be alphanumeric without {{!,<,space,?/}} and maximum of 31 characters. "
                                        "Provided: {0}").format(mobility_group_name)
                            self.fail_and_exit(self.msg)

                        # Validate device_type
                        device_type = anchor.get("device_type")
                        if device_type and device_type not in ["IOS-XE", "AIREOS"]:
                            self.msg = ("Device Type '{0}' is not valid. Must be 'IOS-XE' or 'AIREOS'.").format(device_type)
                            self.fail_and_exit(self.msg)

                        # Validate required fields within mobility_anchors
                        managed_device = anchor.get("managed_device")
                        if managed_device is None:
                            self.msg = ("The 'managed_device' is a required parameter for each mobility anchor. "
                                        "Provided anchor: {0}").format(anchor)
                            self.fail_and_exit(self.msg)
                        if device_priority is None:
                            self.msg = ("The 'device_priority' is a required parameter for each mobility anchor. "
                                        "Provided anchor: {0}").format(anchor)
                            self.fail_and_exit(self.msg)

        # Log the success of the validation process
        self.msg = "Required anchor group parameters validated successfully for all anchor groups."
        self.log(self.msg, "DEBUG")

    def validate_params(self, config, state):
        """
        Validate configuration parameters based on their type and state.
        Args:
            config (dict): The configuration dictionary containing parameters to validate.
            state (str): The state of the parameters, e.g., "merged" or "deleted".
        """
        # Log the start of the validation process
        self.log("Starting validation of the input parameters.", "INFO")

        # Define a mapping of configuration keys to their corresponding validation functions
        validation_mapping = {
            "ssids": self.validate_ssids_params,
            "interfaces": self.validate_interfaces_params,
            "power_profiles": self.validate_power_profiles_params,
            "access_point_profiles": self.validate_access_point_profiles_params,
            "radio_frequency_profiles": self.validate_radio_frequency_profiles_params,
            "anchor_groups": self.validate_anchor_groups_params
        }

        # Iterate over each configuration component and validate if present
        for config_key, validation_function in validation_mapping.items():
            config_value = config.get(config_key)
            if config_value:
                # Log details about the current validation step
                self.log("Config Key: {0}, Validation Function: {1}, Config Value: {2}".format(
                    config_key, validation_function.__name__, config_value), "DEBUG")

                # Perform validation and log the process
                self.log("Validating {0} parameters in '{1}' state.".format(
                    config_key, state), "DEBUG")
                validation_function(config_value, state)
                self.log("Completed validation of {0} parameters in '{1}' state.".format(
                    config_key, state), "DEBUG")

        # Log the completion of the validation process
        self.log("Completed validation of all input parameters.", "INFO")

    def execute_get_with_pagination(self, api_family, api_function, params):
        """
        Executes a paginated GET request using the specified API family, function, and parameters.
        Args:
            api_family (str): The API family to use for the call (e.g., 'wireless', 'network', etc.).
            api_function (str): The specific API function to call for retrieving data (e.g., 'get_ssid_by_site', 'get_interfaces').
            params (dict): Parameters for filtering the data.
        Returns:
            list: A list of dictionaries containing the retrieved data based on the filtering parameters.
        """
        try:
            # Initialize pagination variables
            offset = 1
            limit = 500
            results = []

            # Start the loop for paginated API calls
            while True:
                try:
                    # Update offset and limit in the parameters for the API call

                    # Fix for issue in API for get_ap_profiles (it needs the offset and limit to be of type string)
                    if api_function == "get_ap_profiles":
                        params.update({
                            "offset": str(offset),
                            "limit": str(limit)
                        })
                    else:
                        params.update({
                            "offset": offset,
                            "limit": limit
                        })

                    self.log(
                        "Updated parameters with offset and limit for family '{0}', function '{1}': {2}".format(api_family, api_function, params),
                        "INFO"
                    )

                    # Execute the API call
                    response = self.dnac._exec(
                        family=api_family,
                        function=api_function,
                        op_modifies=False,
                        params=params,
                    )

                    # Process the response if available
                    response = response.get("response")
                    if not response:
                        self.log(
                            "Exiting the loop because no data was returned after increasing the offset. "
                            "Current offset: {0}".format(offset),
                            "INFO"
                        )
                        break

                    # Extend the results list with the response data
                    results.extend(response)
                    # Increment the offset for the next iteration
                    offset += limit

                except Exception as e:
                    # Log an error message and fail if an exception occurs during an iteration
                    self.msg = (
                        "An error occurred during iteration while retrieving data using family '{0}', function '{1}'. "
                        "Details: '{2}' using API call: {3}".format(api_family, api_function, params, str(e))
                    )
                    self.fail_and_exit(self.msg)

            # Log the retrieved data if any
            if results:
                self.log("Data retrieved for family '{0}', function '{1}': {2}".format(api_family, api_function, results), "DEBUG")
            else:
                self.log("No data found for family '{0}', function '{1}'.".format(api_family, api_function), "DEBUG")

            # Return the list of retrieved data
            return results

        except Exception as e:
            # Log an error message and fail if an exception occurs outside the loop
            self.msg = (
                "An error occurred while retrieving data using family '{0}', function '{1}'. "
                "Details using API call. Error: {2}".format(api_family, api_function, str(e))
            )
            self.fail_and_exit(self.msg)

    def get_ssids_params(self, site_id, ssid_name=None, ssid_type=None, l2_auth_type=None, l3_auth_type=None):
        """
        Generates the parameters for retrieving SSIDs, mapping optional user parameters
        to the API's expected parameter names.
        Args:
            site_id (str): The ID of the site for which SSIDs are to be retrieved.
            ssid_name (str, optional): The name of the SSID.
            ssid_type (str, optional): The type of the SSID.
            l2_auth_type (str, optional): The Layer 2 authentication type.
            l3_auth_type (str, optional): The Layer 3 authentication type.
        Returns:
            dict: A dictionary of parameters for the API call, populated with any provided values.
        """
        # Initialize an empty dictionary to hold the parameters for the API call
        get_ssids_params = {}
        self.log("Initialized parameters dictionary for API call.", "DEBUG")

        # Map the site ID to the expected API parameter
        get_ssids_params["site_id"] = site_id
        self.log("Mapped 'site_id' to '{0}'.".format(site_id), "DEBUG")

        # Map the user-provided SSID name to the expected API parameter
        if ssid_name:
            get_ssids_params["ssid_name"] = ssid_name
            self.log("Mapped 'ssid_name' to '{0}'.".format(ssid_name), "DEBUG")

        # Map the user-provided SSID type to the expected API parameter
        if ssid_type:
            get_ssids_params["wlanType"] = ssid_type
            self.log("Mapped 'ssid_type' to '{0}'.".format(ssid_type), "DEBUG")

        # Map the user-provided Layer 2 authentication type to the expected API parameter
        if l2_auth_type:
            get_ssids_params["authType"] = l2_auth_type
            self.log("Mapped 'l2_auth_type' to '{0}'.".format(l2_auth_type), "DEBUG")

        # Map the user-provided Layer 3 authentication type to the expected API parameter
        if l3_auth_type:
            get_ssids_params["l3AuthType"] = l3_auth_type
            self.log("Mapped 'l3_auth_type' to '{0}'.".format(l3_auth_type), "DEBUG")

        # Return the constructed parameters dictionary
        self.log("Constructed get_ssids_params: {0}".format(get_ssids_params), "DEBUG")
        return get_ssids_params

    def get_ssids(self, site_id, get_ssids_params):
        """
        Retrieves SSIDs for a specified site using pagination.
        Args:
            site_id (str): The identifier of the site for which SSIDs are to be retrieved.
            get_ssids_params (dict): Parameters for filtering the SSIDs.
        Returns:
            list: A list of dictionaries containing details of SSIDs for the specified site.
        """
        # Add the site ID to the parameters
        # get_ssids_params["site_id"] = site_id
        # self.log("Added 'site_id' to parameters: {0}".format(site_id), "DEBUG")

        # Execute the paginated API call to retrieve SSIDs
        self.log("Executing paginated API call to retrieve ssids for site ID: {}.".format(site_id), "DEBUG")
        return self.execute_get_with_pagination("wireless", "get_ssid_by_site", get_ssids_params)

    def update_ssid_parameter_mappings(self, ssid_name, ssid_type, ssid_settings):
        """
        Updates SSID parameters by mapping provided settings to the required format.
        Args:
            ssid_name (str): The name of the SSID.
            ssid_type (str): The type of the SSID.
            ssid_settings (dict): A dictionary containing various SSID settings to be mapped.
        Returns:
            dict: A dictionary of the SSID parameters mapped to the required format.
        """
        # Initialize modified SSID dictionary
        modified_ssid = {}

        # Define basic mappings that don't need modifications
        basic_mappings = {
            "ssid": ssid_name,
            "profileName": ssid_settings.get("wlan_profile_name"),
            "wlanType": ssid_type,
            "isFastLaneEnabled": ssid_settings.get("fast_lane"),
            "fastTransition": ssid_settings.get("fast_transition"),
            "fastTransitionOverTheDistributedSystemEnable": ssid_settings.get("fast_transition_over_the_ds"),
            "cckmTsfTolerance": ssid_settings.get("cckm_timestamp_tolerance"),
            "managementFrameProtectionClientprotection": ssid_settings.get("mfp_client_protection"),
            "protectedManagementFrame": ssid_settings.get("protected_management_frame"),
            "neighborListEnable": ssid_settings.get("11k_neighbor_list"),
            "coverageHoleDetectionEnable": ssid_settings.get("coverage_hole_detection"),
            "nasOptions": ssid_settings.get("nas_id"),
            "clientRateLimit": ssid_settings.get("client_rate_limit"),
        }

        # Log and apply basic mappings
        self.log("Applying basic mappings.", "DEBUG")
        for ssid_key, value in basic_mappings.items():
            if value is not None:
                modified_ssid[ssid_key] = value
                self.log("Mapped '{0}' to '{1}'.".format(ssid_key, value), "DEBUG")

        # Quality of Service settings
        quality_of_service = ssid_settings.get("quality_of_service", {})
        if quality_of_service:
            self.log("Applying Quality of Service settings.", "DEBUG")
            modified_ssid["egressQos"] = quality_of_service.get("egress")
            modified_ssid["ingressQos"] = quality_of_service.get("ingress")

        # SSID State settings
        ssid_state = ssid_settings.get("ssid_state", {})
        if ssid_state:
            self.log("Applying SSID State settings.", "DEBUG")
            modified_ssid["isEnabled"] = ssid_state.get("admin_status")
            modified_ssid["isBroadcastSSID"] = ssid_state.get("broadcast_ssid")

        # L2 Security settings
        l2_security = ssid_settings.get("l2_security", {})
        l2_security_mapping = {
            "l2_auth_type": "authType",
            "ap_beacon_protection": "isApBeaconProtectionEnabled",
            "passphrase_type": "isHex",
            "passphrase": "passphrase",
            "open_ssid": "openSsid"
        }

        self.log("Applying L2 Security settings.", "DEBUG")
        for key, value in l2_security.items():
            if key in l2_security_mapping:
                if key == "passphrase_type":
                    modified_ssid[l2_security_mapping[key]] = (value == "HEX")
                else:
                    modified_ssid[l2_security_mapping[key]] = value
                self.log("Mapped '{0}' to '{1}'.".format(l2_security_mapping[key], value), "DEBUG")

            # Handle multiPSKSettings
            if key == "mpsk_settings" and value:
                updated_multi_psk_settings = [
                    {
                        "priority": setting.get("mpsk_priority"),
                        "passphraseType": setting.get("mpsk_passphrase_type"),
                        "passphrase": setting.get("mpsk_passphrase")
                    }
                    for setting in value
                ]
                self.log("MPSK Settings updated.", "DEBUG")
                modified_ssid["multiPSKSettings"] = updated_multi_psk_settings

        # Auth Key Management settings
        auth_key_management = ssid_settings.get("auth_key_management", [])
        self.log("auth_key_management content: {0}".format(auth_key_management), "DEBUG")
        if auth_key_management:
            self.log("Applying AKM settings.", "DEBUG")
            key_management_mapping = {
                "SAE": "isAuthKeySae",
                "SAE-EXT-KEY": "isAuthKeySaeExt",
                "FT+SAE": "isAuthKeySaePlusFT",
                "FT+SAE-EXT-KEY": "isAuthKeySaeExtPlusFT",
                "OWE": "isAuthKeyOWE",
                "PSK": "isAuthKeyPSK",
                "FT+PSK": "isAuthKeyPSKPlusFT",
                "Easy-PSK": "isAuthKeyEasyPSK",
                "PSK-SHA2": "isAuthKeyPSKSHA256",
                "802.1X-SHA1": "isAuthKey8021x",
                "802.1X-SHA2": "isAuthKey8021x_SHA256",
                "FT+802.1x": "isAuthKey8021xPlusFT",
                "SUITE-B-1X": "isAuthKeySuiteB1x",
                "SUITE-B-192X": "isAuthKeySuiteB1921x",
                "CCKM": "isCckmEnabled"
            }

            for key in auth_key_management:
                key_upper = key.upper()
                if key_upper in key_management_mapping:
                    modified_ssid[key_management_mapping[key_upper]] = True
                    self.log("Mapped '{0}' to True.".format(key_management_mapping[key_upper]), "DEBUG")
                else:
                    self.log("Key '{0}' not found in key_management_mapping.".format(key), "WARNING")

        # Radio Policy settings
        radio_policy = ssid_settings.get("radio_policy", {})
        if radio_policy:
            radio_policy_mapping = {
                "band_select": "wlanBandSelectEnable",
                "6_ghz_client_steering": "ghz6PolicyClientSteering"
            }

            for key, ssid_key in radio_policy_mapping.items():
                if key in radio_policy:
                    modified_ssid[ssid_key] = radio_policy[key]
                    self.log("Mapped '{0}' to '{1}'.".format(ssid_key, radio_policy[key]), "DEBUG")

            # Radio Bands Mapping
            radio_bands = set(radio_policy.get("radio_bands", [2.4, 5, 6]))
            radio_band_mapping = {
                frozenset({2.4, 5, 6}): "Triple band operation(2.4GHz, 5GHz and 6GHz)",
                frozenset({5}): "5GHz only",
                frozenset({2.4}): "2.4GHz only",
                frozenset({6}): "6GHz only",
                frozenset({2.4, 5}): "2.4 and 5 GHz",
                frozenset({2.4, 6}): "2.4 and 6 GHz",
                frozenset({5, 6}): "5 and 6 GHz"
            }

            radio_type = radio_band_mapping.get(frozenset(radio_bands))
            if radio_type:
                modified_ssid["ssidRadioType"] = radio_type
                self.log("Mapped 'ssidRadioType' to '{0}'.".format(radio_type), "DEBUG")

            # 2.4 GHz Policy Mapping
            ghz24_policy_mapping = {
                "802.11-bg": "dot11-bg-only",
                "802.11-g": "dot11-g-only"
            }
            ghz24_policy = radio_policy.get("2_dot_4_ghz_band_policy")
            if ghz24_policy in ghz24_policy_mapping:
                modified_ssid["ghz24Policy"] = ghz24_policy_mapping[ghz24_policy]
                self.log("Mapped 'ghz24Policy' to '{0}'.".format(ghz24_policy_mapping[ghz24_policy]), "DEBUG")

        # Encryption settings
        self.log("Applying Encryption settings.", "DEBUG")
        wpa_encryption = ssid_settings.get("wpa_encryption", [])
        if wpa_encryption:
            encryption_mapping = {
                "GCMP256": "rsnCipherSuiteGcmp256",
                "CCMP256": "rsnCipherSuiteCcmp256",
                "GCMP128": "rsnCipherSuiteGcmp128",
                "CCMP128": "rsnCipherSuiteCcmp128"
            }

            for enc_type in wpa_encryption:
                enc_type_upper = enc_type.upper()
                if enc_type_upper in encryption_mapping:
                    modified_ssid[encryption_mapping[enc_type_upper]] = True
                    self.log("Enabled encryption type '{0}'.".format(encryption_mapping[enc_type_upper]), "DEBUG")

        # L3 Security settings
        self.log("Applying L3 Security settings.", "DEBUG")
        l3_security = ssid_settings.get("l3_security", {})
        if l3_security:
            l3_auth_type = l3_security.get("l3_auth_type")
            if l3_auth_type:
                modified_ssid["l3AuthType"] = {
                    "WEB_AUTH": "web_auth",
                    "OPEN": "open"
                }.get(l3_auth_type, l3_auth_type)
                self.log("Mapped 'l3AuthType' to '{0}'.".format(modified_ssid["l3AuthType"]), "DEBUG")

            auth_server_mapping = {
                "Central Web Authentication": "auth_ise",
                "Web Authentication Internal": "auth_internal",
                "Web Authentication External": "auth_external",
                "Web Passthrough Internal": "auth_internal",
                "Web Passthrough External": "auth_external"
            }
            auth_server = l3_security.get("auth_server")
            if auth_server:
                modified_ssid["authServer"] = auth_server_mapping.get(auth_server)
                modified_ssid["webPassthrough"] = auth_server in ["Web Passthrough Internal", "Web Passthrough External"]
                self.log("Mapped 'authServer' to '{0}', 'webPassthrough': {1}.".format(modified_ssid["authServer"], modified_ssid["webPassthrough"]), "DEBUG")

            l3_security_mapping = {
                "web_auth_url": "externalAuthIpAddress",
                "enable_sleeping_client": "sleepingClientEnable",
                "sleeping_client_timeout": "sleepingClientTimeout"
            }

            for key, value in l3_security.items():
                if key in l3_security_mapping:
                    modified_ssid[l3_security_mapping[key]] = value
                    self.log("Mapped '{0}' to '{1}'.".format(l3_security_mapping[key], value), "DEBUG")

        # WLAN Timeouts settings
        self.log("Applying WLAN Timeouts settings.", "DEBUG")
        wlan_timeouts = ssid_settings.get("wlan_timeouts", {})
        if wlan_timeouts:
            wlan_timeouts_mapping = {
                "enable_session_timeout": "sessionTimeOutEnable",
                "session_timeout": "sessionTimeOut",
                "enable_client_execlusion_timeout": "clientExclusionEnable",
                "client_execlusion_timeout": "clientExclusionTimeout"
            }
            for key, ssid_key in wlan_timeouts_mapping.items():
                if key in wlan_timeouts:
                    modified_ssid[ssid_key] = wlan_timeouts[key]
                    self.log("Mapped '{0}' to '{1}'.".format(ssid_key, wlan_timeouts[key]), "DEBUG")

        # BSS Transition Support settings
        self.log("Applying BSS Transition Support settings.", "DEBUG")
        bss_support = ssid_settings.get("bss_transition_support", {})
        if bss_support:
            bss_mapping = {
                "bss_max_idle_service": "basicServiceSetMaxIdleEnable",
                "bss_idle_client_timeout": "basicServiceSetClientIdleTimeout",
                "directed_multicast_service": "directedMulticastServiceEnable"
            }
            for key, ssid_key in bss_mapping.items():
                if key in bss_support:
                    modified_ssid[ssid_key] = bss_support[key]
                    self.log("Mapped '{0}' to '{1}'.".format(ssid_key, bss_support[key]), "DEBUG")

        # Log the final modified SSID
        self.log("Final modified SSID: {0}".format(modified_ssid), "INFO")
        return modified_ssid

    def compare_global_ssids(self, existing_ssids, requested_ssid):
        """
        Compares global SSIDs to determine if they exist and whether updates are required.
        Args:
            existing_ssids (list): A list of dictionaries representing existing SSIDs.
            requested_ssid (dict): A dictionary containing the requested SSID parameters.
        Returns:
            tuple: A tuple containing four elements:
                - ssid_exists (bool): Whether the SSID exists in the existing list.
                - update_required (bool): Whether an update is needed for the SSID.
                - updated_ssid (dict): The updated SSID parameters, if an update is required, otherwise None.
                - ssid_id (str): The ID of the matching SSID, if it exists.
        """
        # Initialize flags and result variables
        ssid_exists = False
        update_required = False
        updated_ssid = None
        ssid_id = ""

        # Extract the name and type from the requested SSID
        requested_ssid_name = requested_ssid.get("ssid")
        requested_ssid_type = requested_ssid.get("wlanType")

        # Log the start of the comparison process
        self.log("Starting comparison for requested SSID: '{0}' of type '{1}'.".format(requested_ssid_name, requested_ssid_type), "INFO")

        # Iterate over the list of existing SSIDs
        for existing in existing_ssids:
            # Log the SSID being checked
            self.log("Checking existing SSID: '{0}' of type '{1}'.".format(existing.get("ssid"), existing.get("wlanType")), "DEBUG")

            # Check if there is an SSID with the same name and type
            if existing.get("ssid") == requested_ssid_name and existing.get("wlanType") == requested_ssid_type:
                self.log("Matching SSID found: '{0}'. Proceeding with parameter comparison.".format(requested_ssid_name), "INFO")
                ssid_exists = True
                ssid_id = existing.get("id")

                # Iterate over the parameters of the requested SSID
                for key, requested_value in requested_ssid.items():
                    # Ignore 'sites_specific_override_settings', 'site_id', and 'id'
                    if key in ["sites_specific_override_settings", "site_id", "id"]:
                        continue

                    # Check if the parameter exists and differs in the existing SSID
                    existing_value = existing.get(key)
                    self.log("Comparing parameter '{0}': existing value '{1}' vs requested value '{2}'.".format(key, existing_value, requested_value), "DEBUG")

                    if existing_value != requested_value:
                        # Log the parameter mismatch
                        self.log("Mismatch found for parameter '{0}': existing value '{1}' vs requested value '{2}'."
                                 .format(key, existing_value, requested_value), "DEBUG")

                        # Update the requested_ssid if necessary
                        if not update_required:
                            updated_ssid = requested_ssid.copy()
                            updated_ssid["id"] = ssid_id
                            updated_ssid["site_id"] = requested_ssid.get("site_id")
                        updated_ssid[key] = requested_value
                        update_required = True
                        break  # Exit immediately upon finding a mismatch

                if update_required:
                    break  # Exit the loop after handling the mismatch

        # Log the final result of the comparison
        if ssid_exists:
            if update_required:
                self.log("Update required for SSID '{0}'.".format(requested_ssid_name), "INFO")
            else:
                self.log("No update required for SSID '{0}'.".format(requested_ssid_name), "INFO")
        else:
            self.log("No matching SSID found for '{0}'.".format(requested_ssid_name), "INFO")

        # Return whether the SSID exists, if an update is required, the updated SSID parameters, and the SSID ID
        return ssid_exists, update_required, updated_ssid, ssid_id

    def compare_site_specific_ssids(self, site_id, requested_ssid_name, requested_ssid_type, existing_ssids, requested_ssid):
        """
        Compares site-specific SSIDs to determine if they exist and whether updates are required.
        Args:
            site_id (str): The site ID where the SSID is located.
            requested_ssid_name (str): The name of the SSID being requested.
            requested_ssid_type (str): The type of the SSID being requested.
            existing_ssids (list): A list of existing SSIDs to compare against.
            requested_ssid (dict): The SSID parameters being requested.
        Returns:
            tuple: A tuple containing three elements:
                - ssid_exists (bool): Whether the SSID exists in the existing list.
                - update_required (bool): Whether an update is needed for the SSID.
                - updated_ssid (dict): The updated SSID parameters, if an update is required, otherwise None.
        """
        # Initialize flags and result dictionary
        ssid_exists = False
        update_required = False
        updated_ssid = None

        # Log the start of the comparison process
        self.log("Starting comparison for SSID: '{0}' of type '{1}'.".format(requested_ssid_name, requested_ssid_type), "INFO")

        # Iterate over the list of existing SSIDs
        for existing_ssid in existing_ssids:
            self.log("Checking existing SSID: '{0}' of type '{1}'.".format(existing_ssid.get("ssid"), existing_ssid.get("wlanType")), "DEBUG")

            # Check if there is an SSID with the same name and type
            if existing_ssid.get("ssid") == requested_ssid_name and existing_ssid.get("wlanType") == requested_ssid_type:
                self.log("Matching SSID found: '{0}'.".format(requested_ssid_name), "INFO")
                ssid_exists = True

                # Compare each parameter in the requested SSID with the existing SSID
                for key, value in requested_ssid.items():
                    if existing_ssid.get(key) != value:
                        self.log("Mismatch found for parameter '{0}': existing value '{1}' vs requested value '{2}'."
                                 .format(key, existing_ssid.get(key), value), "DEBUG")
                        update_required = True
                        break  # Exit loop on first mismatch

                # If an update is required, prepare the updated SSID
                if update_required:
                    self.log("Update required for site specific SSID: '{0}'. Preparing updated SSID.".format(requested_ssid_name), "INFO")
                    updated_ssid = requested_ssid.copy()  # Copy the requested SSID
                    updated_ssid["id"] = existing_ssid.get("id")  # Copy the ID from the existing SSID
                    updated_ssid["site_id"] = site_id  # Add site_id
                else:
                    self.log("No update required for SSID: '{0}'.".format(requested_ssid_name), "INFO")

                break  # Exit the loop once the matching SSID is found

        if not ssid_exists:
            self.log("SSID: '{0}' of type '{1}' does not exist in the provided list.".format(requested_ssid_name, requested_ssid_type), "INFO")

        # Return whether the SSID exists, if an update is required, and the updated SSID parameters
        return ssid_exists, update_required, updated_ssid

    def process_ssid_entry(self, ssid_entry, ssid_params, site_id, ssid_id, operation_list):
        """
        Process the SSID entry by updating its parameters and appending it to the appropriate list.
        Args:
            ssid_entry (dict): The dictionary representing the SSID entry.
            ssid_params (dict): The parameters to be updated in the SSID entry.
            site_id (str): The site ID to be added.
            ssid_id (str): The SSID ID to be added.
            operation_list (list): The list to which the processed SSID entry should be appended.
        """
        # Log initial parameters for processing
        self.log("Processing SSID entry with initial parameters: {0}".format(ssid_entry), "DEBUG")

        # Assign parameters to ssid_entry
        ssid_entry["ssid_params"] = ssid_params
        self.log("Updated SSID parameters: {0}".format(ssid_params), "DEBUG")

        # Add site_id and ssid_id to ssid_params
        ssid_entry["ssid_params"]["site_id"] = site_id
        self.log("Added site_id '{0}' to SSID parameters.".format(site_id), "DEBUG")
        ssid_entry["ssid_params"]["id"] = ssid_id
        self.log("Added ssid_id '{0}' to SSID parameters.".format(ssid_id), "DEBUG")

        # Set the SSID name in ssid_entry
        ssid_entry["ssid_name"] = ssid_entry["ssid_params"].get("ssid")
        self.log("SSID name set to '{0}'.".format(ssid_entry["ssid_name"]), "DEBUG")

        # Set the wlanType in ssid_entry
        ssid_entry["wlanType"] = ssid_entry["ssid_params"].get("wlanType")
        self.log("SSID wlanType set to '{0}'.".format(ssid_entry["wlanType"]), "DEBUG")

        # Remove "ssid" and "wlanType" from ssid_params
        removed_ssid = ssid_entry["ssid_params"].pop("ssid", None)
        removed_wlan_type = ssid_entry["ssid_params"].pop("wlanType", None)
        if removed_ssid is not None or removed_wlan_type is not None:
            self.log("Removed 'ssid' and/or 'wlanType' from SSID parameters.", "DEBUG")

        # Append the entry to the operation list
        operation_list.append(ssid_entry)
        self.log("Appended processed SSID entry to the operation list.", "DEBUG")

    def verify_create_update_ssids_requirement(self, ssids, global_site_details):
        """
        Determines whether SSIDs need to be created, updated, or require no updates based on provided parameters.
        Args:
            ssids (list): A list of dictionaries containing the requested SSID parameters.
            global_site_details (dict): A dictionary containing details of the global site, including site name and ID.
        Returns:
            tuple: Three lists containing SSIDs to be created, updated, and not updated.
        """
        # Initialize lists to track SSIDs for creation, update, and no update
        create_ssids_list, update_ssids_list, no_update_ssids_list = [], [], []

        # Get Global Site ID and name
        global_site_name = global_site_details["site_name"]
        global_site_id = global_site_details["site_id"]
        self.log("Global site details retrieved: Name={0}, ID={1}".format(global_site_name, global_site_id), "DEBUG")

        # Retrieve all existing SSIDs in the Global site
        get_ssids_params = self.get_ssids_params(global_site_id)
        existing_ssids = self.get_ssids(global_site_id, get_ssids_params)
        self.log("Existing SSIDs retrieved: {0}".format(existing_ssids), "DEBUG")

        # Iterate over each requested SSID to determine the operation required
        for ssid in ssids:
            requested_ssid_name = ssid.get("ssid_name")
            requested_ssid_type = ssid.get("ssid_type")
            site_specific_overrides = ssid.get("sites_specific_override_settings", [])

            # Log the start of processing for this SSID
            self.log("Processing SSID: '{0}' of type '{1}'.".format(requested_ssid_name, requested_ssid_type), "INFO")

            # Prepare structures for create, update, and no-update operations
            self.log("Preparing structures for create, update, and no-update operations.", "DEBUG")
            create_ssid = {
                "global_ssid": {
                    "site_details": {"site_name": "Global", "site_id": global_site_id},
                    "ssid_params": {}
                },
                "site_specific_ssid": []
            }
            update_ssid = {
                "global_ssid": {
                    "site_details": {"site_name": "Global", "site_id": global_site_id},
                    "ssid_params": {}
                },
                "site_specific_ssid": []
            }
            no_update_ssid = {
                "global_ssid": {
                    "site_details": {"site_name": "Global", "site_id": global_site_id},
                    "ssid_params": {}
                },
                "site_specific_ssid": []
            }

            # Retrieve and log SSID parameters
            l2_security = ssid.get("l2_security")
            l3_security = ssid.get("l3_security")
            # l2_auth_type = l2_security.get("l2_auth_type") if l2_security else ""
            # l3_auth_type = l3_security.get("l3_auth_type") if l3_security else ""

            # Update request and log modified parameters
            modified_requested_ssid = self.update_ssid_parameter_mappings(requested_ssid_name, requested_ssid_type, ssid)
            modified_requested_ssid["site_id"] = global_site_id
            self.log("Modified parameters of the requested SSID: {0}".format(modified_requested_ssid), "DEBUG")

            # Verify existence and need for update
            self.log("Verifying if SSID: '{0}' exists in the Catalyst Center and if it needs an UPDATE.".format(requested_ssid_name), "INFO")
            ssid_exists, update_required, update_ssid_settings, ssid_id = self.compare_global_ssids(existing_ssids, modified_requested_ssid)

            # Determine operation based on existence and update requirement
            if ssid_exists:
                if update_required:
                    self.log("SSID '{0}' exists globally and UPDATE operation is required.".format(requested_ssid_name), "INFO")
                    update_ssid["global_ssid"]["ssid_params"] = update_ssid_settings
                else:
                    self.log("SSID '{0}' exists globally but doesn't require an UPDATE.".format(requested_ssid_name), "INFO")
                    no_update_ssid["global_ssid"]["ssid_params"] = modified_requested_ssid

                # Handle site-specific overrides
                if site_specific_overrides:
                    for site_override_settings in site_specific_overrides:
                        self.log("Processing Site Override Settings: {0}".format(site_override_settings), "DEBUG")
                        site_name_hierarchy = site_override_settings.get("site_name_hierarchy")
                        site_exists, site_id = self.get_site_id(site_name_hierarchy)
                        self.validate_site_name_hierarchy(site_exists, site_id, site_name_hierarchy)

                        site_details = {"site_name": site_name_hierarchy, "site_id": site_id}
                        modified_requested_site_specific_ssid = self.update_ssid_parameter_mappings(
                            requested_ssid_name, requested_ssid_type, site_override_settings)
                        self.log("Modified parameters of the requested SSID: {0}".format(modified_requested_site_specific_ssid), "DEBUG")

                        ssid_entry = {"site_details": site_details}

                        site_override_l2_security = site_override_settings.get("l2_security", {})
                        get_ssids_params = self.get_ssids_params(
                            site_id, requested_ssid_name, requested_ssid_type, site_override_l2_security.get("l2_auth_type"))
                        existing_site_ssids = self.get_ssids(site_id, get_ssids_params)

                        ssid_exists, update_required, update_ssid_settings = self.compare_site_specific_ssids(
                            site_id, requested_ssid_name, requested_ssid_type, existing_site_ssids, modified_requested_site_specific_ssid)

                        # Determine site-specific operation
                        if ssid_exists:
                            if update_required:
                                self.log("Site Specific SSID '{0}' exists for site '{1}' and UPDATE operation is required."
                                         .format(requested_ssid_name, site_name_hierarchy), "INFO")
                                self.process_ssid_entry(ssid_entry, update_ssid_settings, site_id, ssid_id, update_ssid["site_specific_ssid"])
                            else:
                                self.log("Site Specific SSID '{0}' exists for site '{1}' but doesn't require an UPDATE."
                                         .format(requested_ssid_name, site_name_hierarchy), "INFO")
                                ssid_entry["ssid_params"] = modified_requested_site_specific_ssid
                                no_update_ssid["site_specific_ssid"].append(ssid_entry)
                        else:
                            self.log("Site Specific SSID '{0}' does not exist for site '{1}' and CREATE operation is required."
                                     .format(requested_ssid_name, site_name_hierarchy), "INFO")
                            self.process_ssid_entry(ssid_entry, modified_requested_site_specific_ssid, site_id, ssid_id, update_ssid["site_specific_ssid"])

                        self.log("Site specific SSID entry for SSID: {0} is {1}".format(requested_ssid_name, ssid_entry), "INFO")

            else:
                self.log("SSID '{0}' does not exist globally. A create operation is required.".format(requested_ssid_name), "INFO")
                create_ssid["global_ssid"]["ssid_params"] = modified_requested_ssid

                # Handle site-specific overrides for creation
                if site_specific_overrides:
                    for site_override_settings in site_specific_overrides:
                        site_name_hierarchy = site_override_settings.get("site_name_hierarchy")

                        site_exists, site_id = self.get_site_id(site_name_hierarchy)
                        self.validate_site_name_hierarchy(site_exists, site_id, site_name_hierarchy)

                        modified_requested_site_specific_ssid = self.update_ssid_parameter_mappings(
                            requested_ssid_name, requested_ssid_type, site_override_settings)
                        self.log("Modified parameters of the requested SSID: {0}".format(modified_requested_site_specific_ssid), "DEBUG")
                        site_details = {"site_name": site_name_hierarchy, "site_id": site_id}
                        ssid_entry = {"site_details": site_details}

                        self.log("SSID '{0}' for site '{1}'. A create operation is required.".format(requested_ssid_name, site_name_hierarchy), "INFO")
                        self.process_ssid_entry(ssid_entry, modified_requested_site_specific_ssid, site_id, "", create_ssid["site_specific_ssid"])

            # Append the results to the respective lists
            if create_ssid["global_ssid"]["ssid_params"] or create_ssid["site_specific_ssid"]:
                self.log("SSID '{0}' added to the create list.".format(requested_ssid_name), "DEBUG")
                create_ssids_list.append(create_ssid)
            if update_ssid["global_ssid"]["ssid_params"] or update_ssid["site_specific_ssid"]:
                self.log("SSID '{0}' added to the update list.".format(requested_ssid_name), "DEBUG")
                update_ssids_list.append(update_ssid)
            if no_update_ssid["global_ssid"]["ssid_params"] or no_update_ssid["site_specific_ssid"]:
                self.log("SSID '{0}' added to the no-update list.".format(requested_ssid_name), "DEBUG")
                no_update_ssids_list.append(no_update_ssid)

        # Log the final lists
        self.log("Create SSIDs List: {0}".format(create_ssids_list), "INFO")
        self.log("Update SSIDs List: {0}".format(update_ssids_list), "INFO")
        self.log("No Update SSIDs List: {0}".format(no_update_ssids_list), "INFO")

        self.log("Completed processing all SSIDs.", "INFO")
        return create_ssids_list, update_ssids_list, no_update_ssids_list

    def verify_delete_ssids_requirement(self, ssids, global_site_details):
        """
        Verifies the requirement for deleting SSIDs based on global and site-specific settings.
        Args:
            ssids (list): A list of dictionaries containing SSID information for potential deletion.
            global_site_details (dict): A dictionary containing details of the global site, including site name and ID.
        Returns:
            list: A list of SSIDs marked for deletion, including their parameters.
        """
        # Initialize the list to hold SSIDs scheduled for deletion
        delete_ssids_list = []

        # Log the start of the verification process for SSID deletions
        self.log("Starting verification of SSID deletions.", "DEBUG")

        # Get Global Site ID and name
        global_site_name = global_site_details["site_name"]
        global_site_id = global_site_details["site_id"]
        self.log("Global site details retrieved: Name={0}, ID={1}".format(global_site_name, global_site_id), "DEBUG")

        # Retrieve all existing SSIDs in the Global site
        get_ssids_params = self.get_ssids_params(global_site_id)
        existing_global_ssids = self.get_ssids(global_site_id, get_ssids_params)
        self.log("Retrieved existing global SSIDs.", "DEBUG")

        # Iterate over each SSID to verify deletion requirements
        for index, ssid in enumerate(ssids):
            ssid_name = ssid.get("ssid_name")
            sites_specific_override_settings = ssid.get("sites_specific_override_settings", [])

            # Check for global SSID deletion
            if not sites_specific_override_settings:
                self.log("Checking global SSID deletion for '{0}'.".format(ssid_name), "DEBUG")

                # Find the SSID to delete from the global SSIDs
                ssid_to_delete = next((existing for existing in existing_global_ssids if existing.get("ssid") == ssid_name), None)
                if ssid_to_delete:
                    delete_entry = {
                        index: {
                            "ssid_name": ssid_name,
                            "site_name": global_site_name,
                            "delete_ssid_params": {
                                "site_id": global_site_id,
                                "id": ssid_to_delete.get("id"),
                                "remove_override_in_hierarchy": True
                            }
                        }
                    }
                    delete_ssids_list.append(delete_entry)
                    self.log("Global SSID '{0}' marked for deletion.".format(ssid_name), "INFO")
                else:
                    self.log("Global SSID '{0}' does not exist; deletion not required.".format(ssid_name), "INFO")

            # Check for site-specific SSID deletions
            for site_override in sites_specific_override_settings:
                site_name_hierarchy = site_override.get("site_name_hierarchy")
                remove_override_in_hierarchy = site_override.get("remove_override_in_hierarchy", False)

                # Validate the site existence and retrieve the site ID
                site_exists, site_id = self.get_site_id(site_name_hierarchy)
                self.validate_site_name_hierarchy(site_exists, site_id, site_name_hierarchy)

                self.log("Checking site-specific SSID deletion for '{0}' in site '{1}'.".format(ssid_name, site_name_hierarchy), "DEBUG")
                get_ssids_params = self.get_ssids_params(site_id, ssid_name)
                existing_site_ssids = self.get_ssids(site_id, get_ssids_params)

                # Find the SSID to delete from the site-specific SSIDs
                ssid_to_delete = next((existing for existing in existing_site_ssids if existing.get("ssid") == ssid_name), None)
                if ssid_to_delete:
                    delete_entry = {
                        index: {
                            "ssid_name": ssid_name,
                            "site_name": site_name_hierarchy,
                            "delete_ssid_params": {
                                "site_id": site_id,
                                "id": ssid_to_delete.get("id"),
                                "remove_override_in_hierarchy": remove_override_in_hierarchy
                            }
                        }
                    }
                    delete_ssids_list.append(delete_entry)
                    self.log("Site-specific SSID '{0}' in site '{1}' marked for deletion.".format(ssid_name, site_name_hierarchy), "INFO")
                else:
                    self.log("Site-specific SSID '{0}' does not exist in site '{1}'; deletion not required.".format(ssid_name, site_name_hierarchy), "INFO")

        # Return the list of SSIDs that need to be deleted
        return delete_ssids_list

    def create_ssid(self, create_ssid_params):
        """
        Initiates the creation of an SSID using the provided parameters.
        Args:
            create_ssid_params (dict): A dictionary containing parameters required for creating an SSID.
        Returns:
            dict: The response containing the task ID for the create operation.
        """
        # Log the initiation of the SSID creation process
        self.log("Initiating addition of SSID with parameters: {0}".format(create_ssid_params), "INFO")

        # Execute the API call to create the SSID and return the task ID
        return self.get_taskid_post_api_call("wireless", "create_ssid", create_ssid_params)

    def update_ssid(self, update_ssid_params):
        """
        Initiates the update of an SSID using the provided parameters.
        Args:
            update_ssid_params (dict): A dictionary containing parameters required for updating an SSID.
        Returns:
            dict: The response containing the task ID for the update operation.
        """
        # Log the initiation of the SSID update process
        self.log("Initiating update SSID with parameters: {0}".format(update_ssid_params), "INFO")

        # Execute the API call to update the SSID and return the task ID
        return self.get_taskid_post_api_call("wireless", "update_ssid", update_ssid_params)

    def update_or_override_ssid(self, update_or_override_ssid_params):
        """
        Initiates the update or override of a site-specific SSID using the provided parameters.
        Args:
            update_or_override_ssid_params (dict): A dictionary containing parameters for updating or overriding an SSID.
        Returns:
            dict: The response containing the task ID for the update or override operation.
        """
        # Log the initiation of the update or override process for a site-specific SSID
        self.log("Initiating update/override site-specific SSID with parameters: {0}".format(update_or_override_ssid_params), "INFO")

        # Execute the API call to update or override the SSID and return the task ID
        return self.get_taskid_post_api_call("wireless", "update_or_overridessid", update_or_override_ssid_params)

    def delete_ssid(self, delete_ssid_params):
        """
        Initiates the deletion of a site-specific SSID using the provided parameters.
        Args:
            delete_ssid_params (dict): A dictionary containing parameters required for deleting an SSID.
        Returns:
            dict: The response containing the task ID for the delete operation.
        """
        # Log the initiation of the SSID deletion process
        self.log("Initiating delete site-specific SSID with parameters: {0}".format(delete_ssid_params), "INFO")

        # Execute the API call to delete the SSID and return the task ID
        return self.get_taskid_post_api_call("wireless", "delete_ssid", delete_ssid_params)

    def get_create_ssid_task_status(self, task_id, task_name, ssid_name):
        """
        Retrieves and returns the status of the SSID creation task using the provided task ID.
        Args:
            task_id (str): The task ID for tracking the create operation.
            task_name (str): The name of the task being performed.
            ssid_name (str): The name of the SSID being created.
        Returns:
            str: The status of the task.
        """
        # Construct the message for successful task completion
        msg = "{0} operation has completed successfully for Global SSID: {1}.".format(task_name, ssid_name)

        # Retrieve and return the task status using the provided task ID
        self.get_task_status_from_tasks_by_id(task_id, task_name, msg).check_return_status()
        return self.status

    def get_update_ssid_task_status(self, task_id, task_name, ssid_name):
        """
        Retrieves and returns the status of the SSID update task using the provided task ID.
        Args:
            task_id (str): The task ID for tracking the update operation.
            task_name (str): The name of the task being performed.
            ssid_name (str): The name of the SSID being updated.
        Returns:
            str: The status of the task.
        """
        # Construct the message for successful task completion
        msg = "{0} operation has completed successfully for Global SSID: {1}.".format(task_name, ssid_name)

        # Retrieve and return the task status using the provided task ID
        self.get_task_status_from_tasks_by_id(task_id, task_name, msg).check_return_status()
        return self.status

    def get_update_or_override_ssid_task_status(self, task_id, task_name, ssid_name):
        """
        Retrieves and returns the status of the site-specific SSID update or override task using the provided task ID.
        Args:
            task_id (str): The task ID for tracking the update or override operation.
            task_name (str): The name of the task being performed.
            ssid_name (str): The name of the site-specific SSID being updated or overridden.
        Returns:
            str: The status of the task.
        """
        # Construct the message for successful task completion
        msg = "{0} operation has completed successfully for site-specific SSID: {1}.".format(task_name, ssid_name)

        # Retrieve and return the task status using the provided task ID
        self.get_task_status_from_tasks_by_id(task_id, task_name, msg).check_return_status()
        return self.status

    def get_delete_ssid_task_status(self, task_id, task_name, ssid_name):
        """
        Retrieves and returns the status of the SSID deletion task using the provided task ID.
        Args:
            task_id (str): The task ID for tracking the delete operation.
            task_name (str): The name of the task being performed.
            ssid_name (str): The name of the SSID being deleted.
        Returns:
            str: The status of the task.
        """
        # Construct the message for successful task completion
        msg = "{0} operation has completed successfully for SSID: {1}.".format(task_name, ssid_name)

        # Retrieve and return the task status using the provided task ID
        self.get_task_status_from_tasks_by_id(task_id, task_name, msg).check_return_status()
        return self.status

    def process_ssids_common(self, ssids_params, create_or_update_ssid, get_ssid_task_status, task_name):
        """
        Processes SSIDs for the specified operation (create or update).
        Args:
            ssids_params (list): A list of dictionaries containing parameters for each SSID operation.
            create_or_update_ssid (function): The function to execute for creating or updating SSIDs.
            get_ssid_task_status (function): The function to retrieve the task status for the SSID operation.
            task_name (str): The name of the task being performed, e.g., "Create SSID(s) Task".
        Returns:
            self: The current instance with the updated operation result and message.
        """
        # Initialize lists to track successful and failed SSIDs
        success_ssids = []
        failed_ssids = []
        # Initialize a dictionary to store operation messages
        msg = {}

        # Iterate over each SSID parameter set for processing
        for ssid_param in ssids_params:
            ssid_successful = True
            ssid_name = None
            ssid_id = None

            # Handle global SSID operation
            global_ssid = ssid_param.get("global_ssid", {})
            site_specific_ssids = ssid_param.get("site_specific_ssid")

            if global_ssid.get("ssid_params", {}):
                ssid_name = global_ssid["ssid_params"].get("ssid")
                self.log("Processing global SSID for '{0}'.".format(ssid_name), "INFO")
                ssid_params = global_ssid["ssid_params"]

                # Execute SSID operation (create or update) and get task status
                task_id = create_or_update_ssid(ssid_params)
                self.log("SSID Task ID for '{0}': {1}".format(ssid_name, task_id), "DEBUG")
                status = get_ssid_task_status(task_id, task_name, ssid_name)

                if status != "success":
                    ssid_successful = False

            # Handle site-specific SSID operation
            if site_specific_ssids:
                for site_specific_ssid in site_specific_ssids:
                    update_params = site_specific_ssid["ssid_params"]
                    if update_params:
                        ssid_name = site_specific_ssid["ssid_name"] or ssid_name
                        self.log("Processing site-specific SSID for '{0}'.".format(ssid_name), "INFO")

                        # Check if SSID ID needs to be retrieved
                        if not update_params["id"]:
                            site_id = global_ssid["site_details"]["site_id"]
                            get_ssids_params = self.get_ssids_params(site_id, ssid_name, ssid_params.get("wlanType"))
                            existing_ssids = self.get_ssids(site_id, get_ssids_params)
                            for existing_ssid in existing_ssids:
                                if existing_ssid.get("ssid") == ssid_name:
                                    ssid_id = existing_ssid.get("id")
                                    update_params["id"] = ssid_id
                                    break

                        # Execute SSID operation (update or override) and get task status
                        task_id = self.update_or_override_ssid(update_params)
                        self.log("Update SSID Task ID for '{0}': {1}".format(ssid_name, task_id), "DEBUG")
                        status = self.get_update_or_override_ssid_task_status(task_id, task_name, ssid_name)

                        if status != "success":
                            ssid_successful = False

            # Track success or failure for the SSID
            if ssid_successful:
                success_ssids.append(ssid_name)
            else:
                failed_ssids.append(ssid_name)

        # Log final results for successful SSIDs
        if success_ssids:
            self.log("{0} succeeded for SSID(s): {1}".format(task_name, success_ssids), "INFO")
            msg["{0} succeeded for SSID(s)".format(task_name)] = {
                "success_count": len(success_ssids),
                "successful_ssids": success_ssids
            }

        # Log final results for failed SSIDs
        if failed_ssids:
            self.log("{0} failed for SSID(s): {1}".format(task_name, failed_ssids), "ERROR")
            msg["{0} failed for SSID(s)".format(task_name)] = {
                "failed_count": len(failed_ssids),
                "failed_ssids": failed_ssids
            }

        # Store the message dictionary in the class
        self.msg = msg

        # Determine the final operation result based on success and failure lists
        if success_ssids and failed_ssids:
            self.set_operation_result("failed", True, self.msg, "ERROR")
        elif success_ssids:
            self.set_operation_result("success", True, self.msg, "INFO")
        elif failed_ssids:
            self.set_operation_result("failed", True, self.msg, "ERROR")
        else:
            self.set_operation_result("ok", False, self.msg, "INFO")

        # Return the instance for method chaining or further processing
        return self

    def process_add_ssids(self, add_ssids_params):
        """
        Initiates the process to add SSIDs based on the provided parameters.
        Args:
            add_ssids_params (list): A list of dictionaries containing parameters for adding SSIDs.
        Returns:
            self: The current instance to allow for method chaining or further processing.
        """
        # Define the task name for creating SSIDs
        task_name_create = "Create SSID(s) Task"
        self.log("Starting the creation process for SSIDs with task name: {0}".format(task_name_create), "INFO")

        # Call the common processing function to add SSIDs
        return self.process_ssids_common(
            add_ssids_params,
            self.create_ssid,
            self.get_create_ssid_task_status,
            task_name_create
        )

    def process_update_ssids(self, update_ssids_params):
        """
        Initiates the process to update SSIDs based on the provided parameters.
        Args:
            update_ssids_params (list): A list of dictionaries containing parameters for updating SSIDs.
        Returns:
            self: The current instance to allow for method chaining or further processing.
        """
        # Define the task name for updating SSIDs
        task_name_update = "Update SSID(s) Task"
        self.log("Starting the update process for SSIDs with task name: {0}".format(task_name_update), "INFO")

        # Call the common processing function to update SSIDs
        return self.process_ssids_common(
            update_ssids_params,
            self.update_ssid,
            self.get_update_ssid_task_status,
            task_name_update
        )

    def process_delete_ssids(self, delete_ssids_params):
        """
        Processes the deletion of SSIDs based on the provided parameters.
        Args:
            delete_ssids_params (list): A list of dictionaries containing parameters for deleting SSIDs.
        Returns:
            self: Returns the instance with the updated operation result and message.
        """
        # Define the task name for deletion operations
        task_name = "Delete SSID(s) Task"
        # Initialize lists to track successful and failed SSID deletions
        failed_ssids = []
        success_ssids = []
        # Initialize a dictionary to store operation messages
        msg = {}

        # Iterate over each SSID parameter set for deletion
        for delete_ssid_param in delete_ssids_params:
            # Each item in the list is a dictionary with a single key-value pair
            for index, ssid_data in delete_ssid_param.items():
                ssid_name = ssid_data.get("ssid_name")
                site_name = ssid_data.get("site_name")
                delete_params = ssid_data.get("delete_ssid_params")

                # Log the current SSID processing details
                self.log("Processing - index: {0}, SSID: {1}, site: {2}".format(index, ssid_name, site_name), "DEBUG")

                # Perform the deletion operation and retrieve the task ID
                task_id = self.delete_ssid(delete_params)
                self.log("Task ID for SSID '{0}': {1}".format(ssid_name, task_id), "DEBUG")

                # Check the status of the deletion task
                status = self.get_delete_ssid_task_status(task_id, task_name, ssid_name)

                # Categorize the SSID based on the task status
                if status == "success":
                    success_ssids.append({
                        "ssid_name": ssid_name,
                        "site_name": site_name,
                        "remove_override_in_hierarchy": delete_params.get("remove_override_in_hierarchy")
                    })
                    self.log("SSID '{0}' deletion succeeded.".format(ssid_name), "INFO")
                else:
                    failed_ssids.append(ssid_name)
                    self.log("SSID '{0}' deletion failed.".format(ssid_name), "ERROR")

        # Set the final message for successful operations
        if success_ssids:
            self.log("{0} succeeded for the following SSID(s): {1}".format(task_name, ", ".join(ssid["ssid_name"] for ssid in success_ssids)), "INFO")
            msg["{0} succeeded for the following SSID(s)".format(task_name)] = {
                "success_count": len(success_ssids),
                "successful_ssids": success_ssids
            }

        # Set the final message for failed operations
        if failed_ssids:
            self.log("{0} failed for the following SSID(s): {1}".format(task_name, ", ".join(failed_ssids)), "ERROR")
            msg["{0} failed for the following SSID(s)".format(task_name)] = {
                "failed_count": len(failed_ssids),
                "failed_ssids": failed_ssids
            }

        # Store the message dictionary in the class
        self.msg = msg

        # Determine the final operation result based on success and failure lists
        if success_ssids and failed_ssids:
            self.set_operation_result("failed", True, self.msg, "ERROR")
        elif success_ssids:
            self.set_operation_result("success", True, self.msg, "INFO")
        elif failed_ssids:
            self.set_operation_result("failed", True, self.msg, "ERROR")
        else:
            self.set_operation_result("ok", False, self.msg, "INFO")

        # Return the instance for method chaining or further processing
        return self

    def verify_add_ssids_operation(self, add_ssids_params):
        """
        Verifies the success of the ADD SSIDs operation.
        Args:
            add_ssids_params (list): A list of dictionaries containing parameters for adding SSIDs.
        Returns:
            tuple: A tuple containing two lists - successfully created SSIDs and failed SSIDs.
        """
        # Extract global site details
        global_site_details = self.have.get("global_site_details")
        global_site_id = global_site_details.get("site_id")
        self.log("Retrieved global site ID: {0}".format(global_site_id), "DEBUG")

        # Retrieve all existing SSIDs in the Global site
        get_ssids_params = self.get_ssids_params(global_site_id)
        existing_ssids = self.get_ssids(global_site_id, get_ssids_params)
        self.log("Existing SSIDs in the Global site: {0}".format(existing_ssids), "INFO")

        # Extract existing SSID names for comparison
        existing_ssid_names = {ssid.get("ssid") for ssid in existing_ssids}
        self.log("Extracted existing SSID names for comparison.", "DEBUG")

        # Initialize lists to track created and failed SSIDs
        created_ssids = []
        failed_ssids = []

        # Iterate over the global SSIDs in add_ssids_params to verify creation
        for ssid_param in add_ssids_params:
            ssid_name = ssid_param["global_ssid"]["ssid_params"].get("ssid")
            self.log("Verifying creation of SSID '{0}'.".format(ssid_name), "DEBUG")

            # Check if the SSID was successfully created
            if ssid_name in existing_ssid_names:
                self.log("SSID '{0}' was successfully created.".format(ssid_name), "INFO")
                created_ssids.append(ssid_name)
            else:
                self.log("SSID '{0}' was not found in the Global site; creation may have failed.".format(ssid_name), "WARNING")
                failed_ssids.append(ssid_name)

        # Log final verification result
        if failed_ssids:
            self.log("The ADD SSID(s) operation may not have been successful since some SSIDs were not successfully created: {0}"
                     .format(", ".join(failed_ssids)), "ERROR")
        else:
            self.log("Verified the success of ADD SSID(s) operation for parameters: {0}.".format(add_ssids_params), "INFO")

        # Return lists of created and failed SSIDs
        return created_ssids, failed_ssids

    def verify_update_ssids_operation(self, update_ssids_params):
        """
        Verifies the update operation for SSIDs based on the provided update parameters.
        Args:
            update_ssids_params (list): A list of dictionaries containing parameters for updating SSIDs.
        """
        # Retrieve global site details
        global_site_details = self.have.get("global_site_details")
        global_site_id = global_site_details.get("site_id")
        self.log("Retrieved global site ID: {0}".format(global_site_id), "DEBUG")

        # Retrieve all existing SSIDs in the global site
        existing_global_ssids = self.get_ssids(global_site_id, self.get_ssids_params(global_site_id))
        self.log("Existing SSIDs in the Global site: {0}".format(existing_global_ssids), "INFO")

        # Function to compare SSID parameters
        def compare_ssid_params(existing_params, requested_params):
            ignored_keys = {"site_id", "id", "passphrase", "active_validation"}
            for key, requested_value in requested_params.items():
                if key in ignored_keys:
                    continue

                existing_value = existing_params.get(key)

                if key == "multiPSKSettings":
                    # Compare each setting in multiPSKSettings while ignoring the passphrase
                    if not compare_multipsk_settings(existing_value, requested_value):
                        return False
                elif existing_value != requested_value:
                    self.log("Mismatch for key '{0}': existing value '{1}' vs requested value '{2}'.".format(key, existing_value, requested_value), "WARNING")
                    return False

            return True

        def compare_multipsk_settings(existing_settings, requested_settings):
            if not isinstance(existing_settings, list) or not isinstance(requested_settings, list):
                return False

            for req_setting in requested_settings:
                # Find matching setting by keys other than passphrase
                match = next((ex_setting for ex_setting in existing_settings if all(
                    k in ex_setting and ex_setting[k] == v for k, v in req_setting.items() if k != "passphrase"
                )), None)

                if not match:
                    self.log("Mismatch in multiPSKSettings: no matching entry found for '{0}'.".format(req_setting), "WARNING")
                    return False

            return True

        # Lists to track failed verifications
        failed_verifications = []

        # Iterate over the SSIDs in the update parameters
        all_updates_verified = True
        for ssid_param in update_ssids_params:
            if "global_ssid" in ssid_param:
                global_ssid_params = ssid_param["global_ssid"].get("ssid_params", {})
                ssid_name = global_ssid_params.get("ssid")
                wlan_type = global_ssid_params.get("wlanType")
                self.log("Verifying global SSID: {0}, Type: {1}".format(ssid_name, wlan_type), "DEBUG")

                if global_ssid_params:
                    # Check if SSID is in the existing global SSIDs
                    existing_global_ssid = next(
                        (ssid for ssid in existing_global_ssids if ssid.get("ssid") == ssid_name and ssid.get("wlanType") == wlan_type), None)
                    if existing_global_ssid:
                        if not compare_ssid_params(existing_global_ssid, global_ssid_params):
                            all_updates_verified = False
                            failed_verifications.append({"ssid_name": ssid_name, "site": "Global"})
                            continue

            # Verify site-specific SSID updates
            for site_specific in ssid_param.get("site_specific_ssid", []):
                site_specific_params = site_specific.get("ssid_params", {})
                ssid_name = site_specific.get("ssid_name")
                wlan_type = site_specific.get("wlanType")
                site_details = site_specific.get("site_details", {})
                site_id = site_details.get("site_id")
                site_name = site_details.get("site_name")
                self.log("Verifying site-specific SSID: {0}, Type: {1} for site: {2}".format(ssid_name, wlan_type, site_name), "DEBUG")

                if site_specific_params and site_id:
                    # Retrieve existing SSIDs for the site
                    existing_site_ssids = self.get_ssids(site_id, self.get_ssids_params(site_id))
                    existing_site_ssid = next(
                        (ssid for ssid in existing_site_ssids if ssid.get("ssid") == ssid_name and ssid.get("wlanType") == wlan_type), None)

                    if existing_site_ssid:
                        if not compare_ssid_params(existing_site_ssid, site_specific_params):
                            all_updates_verified = False
                            failed_verifications.append({"ssid_name": ssid_name, "site": site_name})

        # Log final verification result
        if all_updates_verified:
            self.log("Successfully verified the update SSID(s) operation for the following SSID(s): {0}.".format(update_ssids_params), "INFO")
        else:
            self.log("The UPDATE SSID(s) operation may not have been successful. The following SSIDs failed verification: {0}.".format(
                ", ".join("{0} at {1}".format(failure["ssid_name"], failure["site"]) for failure in failed_verifications)), "ERROR")

    def verify_delete_ssids_operation(self, delete_ssids_params):
        """
        Verifies the delete operation for SSIDs based on the provided delete parameters.
        Args:
            delete_ssids_params (list): A list of dictionaries containing parameters for deleting SSIDs.
        """
        # Retrieve global site details
        global_site_details = self.have.get("global_site_details")
        global_site_id = global_site_details.get("site_id")
        self.log("Retrieved global site ID: {0}".format(global_site_id), "DEBUG")

        # Retrieve all existing SSIDs in the global site
        existing_global_ssids = self.get_ssids(global_site_id, self.get_ssids_params(global_site_id))
        existing_global_ssid_names = {ssid.get("ssid") for ssid in existing_global_ssids}
        self.log("Existing SSIDs in global site: {0}".format(existing_global_ssid_names), "DEBUG")

        # Initialize lists to track results of deletions
        successful_deletions = []
        failed_deletions = []

        # Iterate over the delete SSIDs parameters
        for ssid_param in delete_ssids_params:
            for key, details in ssid_param.items():
                ssid_name = details.get("ssid_name")
                site_name = details.get("site_name")
                self.log("Verifying deletion for SSID: {0} in site: {1}".format(ssid_name, site_name), "DEBUG")

                # Only verify deletion for global site SSIDs
                if site_name == "Global":
                    if ssid_name not in existing_global_ssid_names:
                        self.log("SSID '{0}' successfully deleted from global site.".format(ssid_name), "INFO")
                        successful_deletions.append(ssid_name)
                    else:
                        self.log("SSID '{0}' still exists in global site; deletion failed.".format(ssid_name), "WARNING")
                        failed_deletions.append(ssid_name)

        # Log final verification result
        if not failed_deletions:
            self.log("Verified the success of DELETE SSID(s) operation for parameters: {0}.".format(delete_ssids_params), "INFO")
        else:
            self.log("The DELETE SSID(s) operation may not have been successful since some SSIDs failed to be deleted from the global site: {0}"
                     .format(", ".join(failed_deletions)), "ERROR")

    def get_interfaces_params(self, interface_name=None, vlan_id=None):
        """
        Generates the parameters for retrieving interfaces, mapping optional user parameters
        to the API's expected parameter names.
        Args:
            interface_name (str, optional): The name of the interface to filter the retrieval.
            vlan_id (int, optional): The VLAN ID to filter the retrieval.
        Returns:
            dict: A dictionary of parameters for the API call, or an empty dictionary if no parameters are provided.
        """
        # Initialize an empty dictionary to hold the parameters for the API call
        get_interfaces_params = {}
        self.log("Initialized parameters dictionary for API call.", "DEBUG")

        # Map the user-provided interface name to the expected API parameter
        if interface_name:
            get_interfaces_params["interfaceName"] = interface_name
            self.log("Mapped 'interface_name' to 'interfaceName' with value: {0}".format(interface_name), "DEBUG")

        # Map the user-provided VLAN ID to the expected API parameter
        if vlan_id:
            get_interfaces_params["vlanId"] = vlan_id
            self.log("Mapped 'vlan_id' to 'vlanId' with value: {0}".format(vlan_id), "DEBUG")

        # Return the constructed parameters dictionary
        self.log("Constructed get_interfaces_params: {0}".format(get_interfaces_params), "DEBUG")
        return get_interfaces_params

    def get_interfaces(self, get_interfaces_params):
        """
        Retrieves interface details using pagination.
        Args:
            get_interfaces_params (dict, optional): Parameters for filtering the interfaces. Defaults to an empty dictionary.
        Returns:
            list: A list of dictionaries containing details of interfaces based on the filtering parameters.
        """
        self.log("Retrieving interfaces with parameters: {0}".format(get_interfaces_params), "INFO")

        # Execute the paginated API call to retrieve interfaces
        return self.execute_get_with_pagination("wireless", "get_interfaces", get_interfaces_params)

    def create_interface(self, create_interface_params):
        """
        Initiates the creation of an interface using the provided parameters.
        Args:
            create_interface_params (dict): A dictionary containing parameters required for creating an interface.
        Returns:
            dict: The response containing the task ID for the create operation.
        """
        # Log the initiation of the creation process
        self.log("Initiating addition of interface with parameters: {0}".format(create_interface_params), "INFO")

        # Execute the API call to create the interface and return the task ID
        return self.get_taskid_post_api_call("wireless", "create_interface", create_interface_params)

    def update_interface(self, update_interface_params):
        """
        Initiates the update of an interface using the provided parameters.
        Args:
            update_interface_params (dict): A dictionary containing parameters required for updating an interface.
        Returns:
            dict: The response containing the task ID for the update operation.
        """
        # Log the initiation of the update process
        self.log("Initiating updation of interface with parameters: {0}".format(update_interface_params), "INFO")

        # Execute the API call to update the interface and return the task ID
        return self.get_taskid_post_api_call("wireless", "update_interface", update_interface_params)

    def delete_interface(self, delete_interface_params):
        """
        Initiates the deletion of an interface using the provided parameters.
        Args:
            delete_interface_params (dict): A dictionary containing parameters required for deleting an interface.
        Returns:
            dict: The response containing the task ID for the delete operation.
        """
        # Log the initiation of the deletion process
        self.log("Initiating deletion of interface with parameters: {0}".format(delete_interface_params), "INFO")

        # Execute the API call to delete the interface and return the task ID
        return self.get_taskid_post_api_call("wireless", "delete_interface", delete_interface_params)

    def verify_create_update_interfaces_requirement(self, interfaces):
        """
        Determines whether interfaces need to be created, updated, or require no updates.
        Args:
            interfaces (list): A list of dictionaries containing the requested interface parameters.
        Returns:
            tuple: Three lists containing interfaces to be created, updated, and not updated.
        """
        # Retrieve all existing interfaces
        existing_interfaces = self.get_interfaces(get_interfaces_params={})
        self.log("Retrieved existing interfaces.", "DEBUG")

        # Log the existing and requested interfaces for debugging
        self.log("Existing Interfaces: {0}".format(existing_interfaces), "DEBUG")
        self.log("Requested Interfaces: {0}".format(interfaces), "DEBUG")

        # Initialize lists to store interfaces that need to be created, updated, or not changed
        create_interfaces = []
        update_interfaces = []
        no_update_interfaces = []

        # Convert the requested interfaces to a dictionary for quick lookup by interface name
        requested_interfaces_dict = {interface["interface_name"]: interface for interface in interfaces}
        self.log("Converted requested interfaces to a dictionary for quick lookup.", "DEBUG")

        # Iterate over existing interfaces to find matches and differences
        for existing_interface in existing_interfaces:
            interface_name = existing_interface["interfaceName"]
            vlan_id = existing_interface["vlanId"]
            self.log("Evaluating existing interface: {0}, VLAN ID: {1}".format(interface_name, vlan_id), "DEBUG")

            # If the interface exists in both, compare fields
            if interface_name in requested_interfaces_dict:
                requested_interface = requested_interfaces_dict[interface_name]
                requested_vlan_id = requested_interface.get("vlan_id")
                self.log("Comparing requested interface '{0}' with existing interface.".format(interface_name), "DEBUG")

                # Check for differences
                if vlan_id != requested_vlan_id:
                    # Add the requested interface with the ID from the existing interface
                    updated_interface = requested_interface.copy()
                    updated_interface["id"] = existing_interface.get("id")
                    update_interfaces.append(updated_interface)
                    self.log("Interface '{0}' marked for update.".format(interface_name), "DEBUG")
                else:
                    # If there's no difference, add to no_update_interfaces
                    no_update_interfaces.append(existing_interface)
                    self.log("Interface '{0}' requires no updates.".format(interface_name), "DEBUG")

                # Remove the processed interface from the dictionary
                del requested_interfaces_dict[interface_name]

        # Remaining items in requested_interfaces_dict are new interfaces to be created
        create_interfaces.extend(requested_interfaces_dict.values())
        self.log("Identified new interfaces to be created.", "DEBUG")

        # Log details of interfaces to be created, updated, not updated
        self.log("Interfaces that need to be CREATED: {0} - {1}".format(len(create_interfaces), create_interfaces), "DEBUG")
        self.log("Interfaces that need to be UPDATED: {0} - {1}".format(len(update_interfaces), update_interfaces), "DEBUG")
        self.log("Interfaces that DON'T NEED UPDATES: {0} - {1}".format(len(no_update_interfaces), no_update_interfaces), "DEBUG")

        # Calculate total interfaces processed and check against requested interfaces
        total_interfaces_processed = len(create_interfaces) + len(update_interfaces) + len(no_update_interfaces)

        if total_interfaces_processed == len(interfaces):
            self.log("Match in total counts: Processed={0}, Requested={1}.".format(total_interfaces_processed, len(interfaces)), "DEBUG")
        else:
            self.log("Mismatch in total counts: Processed={0}, Requested={1}.".format(total_interfaces_processed, len(interfaces)), "ERROR")

        # Return the categorized interfaces
        return create_interfaces, update_interfaces, no_update_interfaces

    def verify_delete_interfaces_requirement(self, interfaces):
        """
        Determines whether interfaces need to be deleted based on the requested parameters.
        Args:
            interfaces (list): A list of dictionaries containing the requested interface parameters for deletion.
        Returns:
            list: A list of interfaces that need to be deleted, including their IDs.
        """
        # Initialize the list to hold interfaces scheduled for deletion
        delete_interfaces_list = []

        # Log the start of the verification process for deletions
        self.log("Starting verification of interfaces for deletion.", "INFO")

        # Retrieve all existing interfaces
        existing_interfaces = self.get_interfaces(get_interfaces_params={})
        self.log("Existing Interfaces: {0}".format(existing_interfaces), "DEBUG")

        # Convert existing interfaces to a dictionary for quick lookup by interface name
        existing_interfaces_dict = {interface["interfaceName"]: interface for interface in existing_interfaces}
        self.log("Converted existing interfaces to a dictionary for quick lookup.", "DEBUG")

        # Iterate over the requested interfaces
        for requested_interface in interfaces:
            interface_name = requested_interface.get("interface_name")
            self.log("Checking deletion requirement for interface: {0}".format(interface_name), "DEBUG")

            # Check if the interface exists in the existing interfaces
            if interface_name in existing_interfaces_dict:
                # Add the requested interface with the ID from the existing interface
                existing_interface = existing_interfaces_dict[interface_name]
                interface_to_delete = requested_interface.copy()
                interface_to_delete["id"] = existing_interface.get("id")
                delete_interfaces_list.append(interface_to_delete)
                self.log("Interface '{0}' scheduled for deletion.".format(interface_name), "INFO")
            else:
                self.log("Deletion not required for interface '{0}'. It does not exist.".format(interface_name), "INFO")

        # Log the list of interfaces scheduled for deletion
        self.log("Interfaces scheduled for deletion: {0} - {1}".format(len(delete_interfaces_list), delete_interfaces_list), "DEBUG")

        # Return the list of interfaces that need to be deleted
        return delete_interfaces_list

    def map_interface_params(self, interfaces):
        """
        Maps the parameters of each interface to the required format for API calls.
        Args:
            interfaces (list): A list of dictionaries containing interface parameters.
        Returns:
            list: A list of dictionaries with the parameters mapped to the required format.
        """
        # Initialize an empty list to store the mapped interfaces
        mapped_interfaces = []

        # Check if the interfaces list is empty and return the empty mapped list
        if not interfaces:
            self.log("No interfaces provided for mapping.", "DEBUG")
            return mapped_interfaces

        # Iterate over each interface to perform mappings
        for interface in interfaces:
            mapped_interface = {}
            self.log("Mapping interface: {0}".format(interface), "DEBUG")

            # Map each parameter to the required format
            if "interface_name" in interface:
                mapped_interface["interfaceName"] = interface["interface_name"]
                self.log("Mapped 'interface_name' to 'interfaceName': {0}".format(interface["interface_name"]), "DEBUG")

            if "vlan_id" in interface:
                mapped_interface["vlanId"] = interface["vlan_id"]
                self.log("Mapped 'vlan_id' to 'vlanId': {0}".format(interface["vlan_id"]), "DEBUG")

            # Retain the id if it exists in the interface
            if "id" in interface:
                mapped_interface["id"] = interface["id"]
                self.log("Retained 'id': {0}".format(interface["id"]), "DEBUG")

            # Add the mapped interface to the list of mapped interfaces
            mapped_interfaces.append(mapped_interface)
            self.log("Added mapped interface: {0}".format(mapped_interface), "DEBUG")

        # Log all mapped interfaces
        self.log("Mapped Interfaces: {0}".format(mapped_interfaces), "DEBUG")

        # Return the list of mapped interfaces
        return mapped_interfaces

    def process_interfaces_common(self, interfaces_params, create_or_update_or_delete_interface, task_name):
        """
        Processes the interfaces for the specified operation (create, update, delete).
        Args:
            interfaces_params (list): A list of dictionaries containing parameters for each interface operation.
            create_or_update_or_delete_interface (function): The function to execute for each interface operation.
            task_name (str): The name of the task being performed, e.g., "Create Interface(s) Task".
        Returns:
            self: The current instance to allow for method chaining or further processing.
        """
        # Initialize lists to track successful and failed interface operations
        failed_interfaces = []
        success_interfaces = []
        msg = {}

        # Iterate over each interface parameter set for processing
        for interface in interfaces_params:
            interface_name = interface.get("interfaceName")
            self.log("Processing interface: {0}".format(interface_name), "DEBUG")

            # Prepare parameters for the operation
            if create_or_update_or_delete_interface == self.delete_interface:
                # For delete operation, extract only the id
                operation_params = {"id": interface.get("id")}
                self.log("Prepared parameters for delete operation.", "DEBUG")
            else:
                # For create or update operations, use the entire interface data
                operation_params = interface
                self.log("Prepared parameters for create/update operation.", "DEBUG")

            # Execute the operation and retrieve the task ID
            task_id = create_or_update_or_delete_interface(operation_params)
            self.log("Task ID for interface '{0}': {1}".format(interface_name, task_id), "DEBUG")

            # Check the status of the operation
            operation_msg = "{0} operation has completed successfully for interface_name: {1}.".format(task_name, interface_name)
            self.get_task_status_from_tasks_by_id(task_id, task_name, operation_msg).check_return_status()

            # Determine if the operation was successful and categorize accordingly
            if self.status == "success":
                success_interfaces.append(interface_name)
                self.log("Interface '{0}' processed successfully.".format(interface_name), "INFO")
            else:
                failed_interfaces.append(interface_name)
                self.log("Interface '{0}' failed to process.".format(interface_name), "ERROR")

        # Log and prepare final messages for successful operations
        if success_interfaces:
            self.log("{0} succeeded for the following interface(s): {1}".format(task_name, ", ".join(success_interfaces)), "INFO")
            msg["{0} succeeded for the following interface(s)".format(task_name)] = {
                "success_count": len(success_interfaces),
                "successful_interfaces": success_interfaces
            }

        # Log and prepare final messages for failed operations
        if failed_interfaces:
            self.log("{0} failed for the following interface(s): {1}".format(task_name, ", ".join(failed_interfaces)), "ERROR")
            msg["{0} failed for the following interface(s)".format(task_name)] = {
                "failed_count": len(failed_interfaces),
                "failed_interfaces": failed_interfaces
            }

        # Store the message dictionary in the class
        self.msg = msg

        # Determine the final operation result based on success and failure lists
        if success_interfaces and failed_interfaces:
            self.set_operation_result("failed", True, self.msg, "ERROR")
        elif success_interfaces:
            self.set_operation_result("success", True, self.msg, "INFO")
        elif failed_interfaces:
            self.set_operation_result("failed", True, self.msg, "ERROR")
        else:
            self.set_operation_result("ok", False, self.msg, "INFO")

        # Return the instance for method chaining or further processing
        return self

    def process_add_interfaces(self, add_interfaces_params):
        """
        Initiates the process to add interfaces.
        Args:
            add_interfaces_params (list): A list of dictionaries containing parameters for each interface to be added.
        Returns:
            self: The current instance to allow for method chaining or further processing.
        """
        # Define the task name for creating interfaces
        task_name_create = "Create Interface(s) Task"
        self.log("Starting the creation process for interfaces with task name: {0}".format(task_name_create), "INFO")

        # Call the common processing function to add interfaces
        return self.process_interfaces_common(
            add_interfaces_params,
            self.create_interface,
            task_name_create
        )

    def process_update_interfaces(self, update_interfaces_params):
        """
        Initiates the process to update interfaces.
        Args:
            update_interfaces_params (list): A list of dictionaries containing parameters for each interface to be updated.
        Returns:
            self: The current instance to allow for method chaining or further processing.
        """
        # Define the task name for updating interfaces
        task_name_update = "Update Interface(s) Task"
        self.log("Starting the update process for interfaces with task name: {0}".format(task_name_update), "INFO")

        # Call the common processing function to update interfaces
        return self.process_interfaces_common(
            update_interfaces_params,
            self.update_interface,
            task_name_update
        )

    def process_delete_interfaces(self, delete_interfaces_params):
        """
        Initiates the process to delete interfaces.
        Args:
            delete_interfaces_params (list): A list of dictionaries containing parameters for each interface to be deleted.
        Returns:
            self: The current instance to allow for method chaining or further processing.
        """
        # Define the task name for deleting interfaces
        task_name_delete = "Delete Interface(s) Task"
        self.log("Starting the deletion process for interfaces with task name: {0}".format(task_name_delete), "INFO")

        # Call the common processing function to delete interfaces
        return self.process_interfaces_common(
            delete_interfaces_params,
            self.delete_interface,
            task_name_delete
        )

    def verify_add_interfaces_operation(self, add_interfaces_params):
        """
        Verifies whether the specified interfaces have been successfully added.
        Args:
            add_interfaces_params (list): A list of dictionaries containing parameters for each interface to be added.
        """
        # Retrieve all existing interfaces
        existing_interfaces = self.get_interfaces(get_interfaces_params={})
        # Create a set of existing interface names for quick lookup
        existing_interface_names = {interface["interfaceName"] for interface in existing_interfaces}
        self.log("Retrieved existing interfaces.", "DEBUG")

        # Log the state of interfaces after the add operation and the requested additions
        self.log("State after performing ADD Interface operation: {0}".format(existing_interface_names), "INFO")
        self.log("Interfaces requested to be added: {0}".format(add_interfaces_params), "INFO")

        # Initialize a list to track interfaces that failed to add
        failed_interfaces = []

        # Iterate over the requested interfaces to verify addition
        for interface in add_interfaces_params:
            interface_name = interface.get("interfaceName")
            self.log("Verifying addition for interface: {0}".format(interface_name), "DEBUG")

            # Check if the interface exists in the current state
            if interface_name not in existing_interface_names:
                failed_interfaces.append(interface_name)
                self.log("Add operation failed for interface '{0}'. It does not exist in the current state.".format(interface_name), "WARNING")

        # Log the summary of the addition verification
        if failed_interfaces:
            self.log("The ADD operation may not have been successful since some interfaces were not successfully created: {0}".format(
                failed_interfaces), "ERROR")
        else:
            self.log("Verified the success of ADD interface(s) operation for parameters: {0}.".format(add_interfaces_params), "INFO")

    def verify_update_interfaces_operation(self, update_interfaces_params):
        """
        Verifies whether the specified interfaces have been successfully updated.
        Args:
            update_interfaces_params (list): A list of dictionaries containing parameters for each interface to be updated.
        """
        # Retrieve all existing interfaces
        existing_interfaces = self.get_interfaces(get_interfaces_params={})
        # Create a dictionary of existing interfaces for quick lookup by interface name and VLAN ID
        existing_interfaces_dict = {(interface["interfaceName"], interface["vlanId"]): interface for interface in existing_interfaces}
        self.log("Retrieved existing interfaces and created lookup dictionary.", "DEBUG")

        # Log the current state of interfaces and the requested updates
        self.log("State after performing UPDATE Interface operation: {0}".format(existing_interfaces_dict), "INFO")
        self.log("Interfaces requested to be updated: {0}".format(update_interfaces_params), "INFO")

        # Initialize a list to track interfaces that failed to update
        failed_interfaces = []

        # Iterate over the requested interfaces to verify updates
        for interface in update_interfaces_params:
            interface_name = interface.get("interfaceName")
            vlan_id = interface.get("vlanId")
            self.log("Verifying update for interface: {0}, VLAN ID: {1}".format(interface_name, vlan_id), "DEBUG")

            # Check if the interface with the specified VLAN ID exists in the current state
            if (interface_name, vlan_id) not in existing_interfaces_dict:
                failed_interfaces.append(interface_name)
                self.log("Update operation failed for interface '{0}'. It was not found with the specified VLAN ID.".format(interface_name), "WARNING")

        # Log the summary of the update verification
        if failed_interfaces:
            self.log("The UPDATE operation may not have been successful for the following interfaces: {0}. They were not found with the specified parameters."
                     .format(failed_interfaces), "ERROR")
        else:
            self.log("Verified the success of UPDATE interfaces operation for parameters: {0}.".format(update_interfaces_params), "INFO")

    def verify_delete_interfaces_operation(self, delete_interfaces_params):
        """
        Verifies whether the specified interfaces have been successfully deleted.
        Args:
            delete_interfaces_params (list): A list of dictionaries containing parameters for each interface to be deleted.
        """
        # Retrieve all existing interfaces
        existing_interfaces = self.get_interfaces(get_interfaces_params={})
        # Create a set of existing interface names for quick lookup
        existing_interface_names = {interface["interfaceName"] for interface in existing_interfaces}
        self.log("Retrieved existing interfaces.", "DEBUG")

        # Log the current state of interfaces and the requested deletions
        self.log("State after performing DELETE Interface operation: {0}".format(existing_interface_names), "INFO")
        self.log("Interfaces requested to be deleted: {0}".format(delete_interfaces_params), "INFO")

        # Initialize a list to track interfaces that failed deletion
        failed_interfaces = []

        # Iterate over the requested interfaces to verify deletion
        for interface in delete_interfaces_params:
            interface_name = interface.get("interfaceName")
            self.log("Verifying deletion for interface: {0}".format(interface_name), "DEBUG")

            # Check if the interface still exists in the current state
            if interface_name in existing_interface_names:
                failed_interfaces.append(interface_name)
                self.log("Delete operation failed for interface '{0}'. It still exists in the current state.".format(interface_name), "WARNING")

        # Log the summary of the deletion verification
        if failed_interfaces:
            self.log("The DELETE Interface(s) operation may not have been successful since some interfaces still exist: {0}."
                     .format(failed_interfaces), "ERROR")
        else:
            self.log("Verified the success of DELETE Interface(s) operation for all requested parameters: {0}.".format(delete_interfaces_params), "INFO")

    def get_power_profiles_params(self, power_profile_name=None):
        """
        Generates the parameters for retrieving power profiles, mapping optional user parameters
        to the API's expected parameter names.
        Args:
            power_profile_name (str, optional): The name of the power profile to filter the retrieval.
        Returns:
            dict: A dictionary of parameters for the API call, or an empty dictionary if no parameters are provided.
        """
        # Initialize an empty dictionary to hold the parameters for the API call
        get_power_profiles_params = {}
        self.log("Initialized parameters dictionary for API call.", "DEBUG")

        # Map the user-provided power profile name to the expected API parameter
        if power_profile_name:
            get_power_profiles_params["profile_name"] = power_profile_name
            self.log("Mapped 'power_profile_name' to 'profile_name' with value: {0}".format(power_profile_name), "DEBUG")
        else:
            self.log("No specific power profile name provided. Returning empty parameters.", "DEBUG")

        # Return the constructed parameters dictionary
        self.log("Constructed get_power_profiles_params: {0}".format(get_power_profiles_params), "DEBUG")
        return get_power_profiles_params

    def get_power_profiles(self, get_power_profiles_params):
        """
        Retrieves power profile details using pagination.
        Args:
            get_power_profiles_params (dict): Parameters for filtering the power profiles.
        Returns:
            list: A list of dictionaries containing details of power profiles based on the filtering parameters.
        """
        # Execute the paginated API call to retrieve power profiles
        self.log("Executing paginated API call to retrieve power profiles.", "DEBUG")
        return self.execute_get_with_pagination("wireless", "get_power_profiles", get_power_profiles_params)

    def update_power_profiles_with_defaults(self, power_profiles):
        """
        Updates each power profile's rules with default values based on the interface type.
        Args:
            power_profiles (list): A list of dictionaries containing power profile parameters.
        Returns:
            list: A list of power profiles with rules updated with default values.
        """
        # Iterate over each power profile to update rules with defaults
        for profile in power_profiles:
            rules = profile.get("rules", [])
            self.log("Processing power profile: {0}".format(profile.get("profileName", "Unnamed")), "DEBUG")

            # Iterate over each rule in the power profile
            for rule in rules:
                interface_type = rule.get("interface_type")
                self.log("Processing rule for interface type: {0}".format(interface_type), "DEBUG")

                # Assign default values based on the interface type if only one parameter is present
                if interface_type == "USB" and len(rule) == 1:
                    rule["interface_id"] = "USB0"
                    rule["parameter_type"] = "STATE"
                    rule["parameter_value"] = "DISABLE"
                    self.log("Assigned defaults for USB interface: interface_id=USB0, parameter_type=STATE, parameter_value=DISABLE", "DEBUG")
                elif interface_type == "RADIO" and len(rule) == 1:
                    rule["interface_id"] = "6GHZ"
                    rule["parameter_type"] = "SPATIALSTREAM"
                    rule["parameter_value"] = "FOUR_BY_FOUR"
                    self.log("Assigned defaults for RADIO interface: interface_id=6GHZ, parameter_type=SPATIALSTREAM, parameter_value=FOUR_BY_FOUR", "DEBUG")
                elif interface_type == "ETHERNET" and len(rule) == 1:
                    rule["interface_id"] = "GIGABITETHERNET0"
                    rule["parameter_type"] = "SPEED"
                    rule["parameter_value"] = "5000MBPS"
                    self.log("Assigned defaults for ETHERNET interface: interface_id=GIGABITETHERNET0, parameter_type=SPEED, parameter_value=5000MBPS", "DEBUG")

        # Return the updated power profiles with default values applied
        self.log("Completed updating power profiles with default values.", "DEBUG")
        return power_profiles

    def verify_create_update_power_profiles_requirement(self, power_profiles):
        """
        Determines whether power profiles need to be created, updated, or require no updates.
        Args:
            power_profiles (list): A list of dictionaries containing the requested power profile parameters.
        Returns:
            tuple: Three lists containing power profiles to be created, updated, and not updated.
        """
        # Update requested profiles with default values where needed
        updated_power_profiles = self.update_power_profiles_with_defaults(power_profiles)
        self.log("Updated requested power profiles with defaults.", "DEBUG")

        # Retrieve all existing power profiles from the system
        existing_power_profiles = self.get_power_profiles(get_power_profiles_params={})
        self.log("Retrieved existing power profiles.", "DEBUG")

        # Log the existing and requested power profiles for debugging
        self.log("Existing Power Profiles: {0}".format(existing_power_profiles), "DEBUG")
        self.log("Requested Power Profiles: {0}".format(updated_power_profiles), "DEBUG")

        # Initialize lists to store profiles that need to be created, updated, or not changed
        create_profiles = []
        update_profiles = []
        no_update_profiles = []

        # Create a dictionary of existing profiles for quick lookup using the profile name
        existing_profiles_dict = {profile["profileName"]: profile for profile in existing_power_profiles}
        self.log("Converted existing profiles to a dictionary for quick lookup.", "DEBUG")

        # Iterate over the updated requested power profiles
        for requested_profile in updated_power_profiles:
            profile_name = requested_profile["power_profile_name"]
            requested_description = requested_profile.get("power_profile_description", "")
            requested_rules = requested_profile.get("rules", [])
            self.log("Evaluating profile: {0}".format(profile_name), "DEBUG")

            # Check if the profile already exists
            if profile_name in existing_profiles_dict:
                existing_profile = existing_profiles_dict[profile_name]
                existing_description = existing_profile.get("description", "")
                existing_rules = existing_profile.get("rules", [])

                # Flag to determine if an update is needed
                update_needed = False

                # Compare description
                if requested_description != existing_description:
                    update_needed = True
                    self.log("Description differs for profile '{0}'.".format(profile_name), "DEBUG")

                # Compare rules, considering both parameter changes and order changes
                if len(requested_rules) != len(existing_rules):
                    update_needed = True
                    self.log("Number of rules differs for profile '{0}'.".format(profile_name), "DEBUG")
                else:
                    for req_rule, exist_rule in zip(requested_rules, existing_rules):
                        if (
                            req_rule.get("interface_type") != exist_rule.get("interfaceType") or
                            req_rule.get("interface_id") != exist_rule.get("interfaceId") or
                            req_rule.get("parameter_type") != exist_rule.get("parameterType") or
                            req_rule.get("parameter_value") != exist_rule.get("parameterValue")
                        ):
                            update_needed = True
                            self.log("Rule differs for profile '{0}'.".format(profile_name), "DEBUG")
                            break

                if update_needed:
                    # Add the requested profile with the ID from the existing profile
                    updated_profile = requested_profile.copy()
                    updated_profile["id"] = existing_profile.get("id")
                    update_profiles.append(updated_profile)
                    self.log("Profile '{0}' marked for update.".format(profile_name), "DEBUG")
                else:
                    # If there's no difference, add to no_update_profiles
                    no_update_profiles.append(existing_profile)
                    self.log("Profile '{0}' requires no updates.".format(profile_name), "DEBUG")
            else:
                # If the profile does not exist, mark it for creation
                create_profiles.append(requested_profile)
                self.log("Profile '{0}' marked for creation.".format(profile_name), "DEBUG")

        # Log details of power profiles to be created, updated, not updated
        self.log("Power Profiles that need to be CREATED: {0} - {1}".format(len(create_profiles), create_profiles), "DEBUG")
        self.log("Power Profiles that need to be UPDATED: {0} - {1}".format(len(update_profiles), update_profiles), "DEBUG")
        self.log("Power Profiles that DON'T NEED UPDATES: {0} - {1}".format(len(no_update_profiles), no_update_profiles), "DEBUG")

        # Calculate total profiles processed and check against requested profiles
        total_profiles_processed = len(create_profiles) + len(update_profiles) + len(no_update_profiles)

        if total_profiles_processed == len(updated_power_profiles):
            self.log("Match in total counts: Processed={0}, Requested={1}.".format(total_profiles_processed, len(updated_power_profiles)), "DEBUG")
        else:
            self.log("Mismatch in total counts: Processed={0}, Requested={1}.".format(total_profiles_processed, len(updated_power_profiles)), "ERROR")

        # Return the categorized profiles
        return create_profiles, update_profiles, no_update_profiles

    def verify_delete_power_profiles_requirement(self, power_profiles):
        """
        Determines whether power profiles need to be deleted based on the requested parameters.
        Args:
            power_profiles (list): A list of dictionaries containing the requested power profile parameters for deletion.
        Returns:
            list: A list of power profiles that need to be deleted, including their IDs.
        """
        # Initialize the list to hold profiles scheduled for deletion
        delete_power_profiles_list = []

        # Log the start of the verification process for deletions
        self.log("Starting verification of power profiles for deletion.", "INFO")

        # Retrieve all existing power profiles
        existing_power_profiles = self.get_power_profiles(get_power_profiles_params={})
        self.log("Existing Power Profiles: {0}".format(existing_power_profiles), "DEBUG")

        # Convert existing power profiles to a dictionary for quick lookup by power profile name
        existing_power_profiles_dict = {profile["profileName"]: profile for profile in existing_power_profiles}
        self.log("Converted existing profiles to a dictionary for quick lookup.", "DEBUG")

        # Iterate over the requested power profiles
        for requested_profile in power_profiles:
            profile_name = requested_profile.get("power_profile_name")
            self.log("Checking deletion requirement for profile: {0}".format(profile_name), "DEBUG")

            # Check if the power profile exists in the existing power profiles
            if profile_name in existing_power_profiles_dict:
                # Add the requested power profile with the ID from the existing power profile
                existing_profile = existing_power_profiles_dict[profile_name]
                profile_to_delete = requested_profile.copy()
                profile_to_delete["id"] = existing_profile.get("id")
                delete_power_profiles_list.append(profile_to_delete)
                self.log("Power Profile '{0}' scheduled for deletion.".format(profile_name), "INFO")
            else:
                self.log("Deletion not required for power profile '{0}'. It does not exist.".format(profile_name), "INFO")

        # Log the list of profiles scheduled for deletion
        self.log("Power Profiles scheduled for deletion: {0} - {1}".format(len(delete_power_profiles_list), delete_power_profiles_list), "DEBUG")

        # Return the list of profiles that need to be deleted
        return delete_power_profiles_list

    def map_power_profiles_params(self, power_profiles):
        """
        Maps the parameters of each power profile to the required format for API calls.
        Args:
            power_profiles (list): A list of dictionaries containing power profile parameters.
        Returns:
            list: A list of dictionaries with the parameters mapped to the required format.
        """
        # Initialize an empty list to hold the mapped power profiles
        mapped_power_profiles = []

        # Check if the power profiles list is empty and return the empty mapped list
        if not power_profiles:
            self.log("No power profiles provided for mapping.", "DEBUG")
            return mapped_power_profiles

        # Iterate over each power profile to perform mappings
        for profile in power_profiles:
            mapped_profile = {}
            self.log("Mapping power profile: {0}".format(profile), "DEBUG")

            # Map each parameter to the required format
            if "power_profile_name" in profile:
                mapped_profile["profileName"] = profile["power_profile_name"]
                self.log("Mapped 'power_profile_name' to 'profileName': {0}".format(profile["power_profile_name"]), "DEBUG")

            if "power_profile_description" in profile:
                mapped_profile["description"] = profile["power_profile_description"]
                self.log("Mapped 'power_profile_description' to 'description': {0}".format(profile["power_profile_description"]), "DEBUG")

            if "id" in profile:
                mapped_profile["id"] = profile["id"]
                self.log("Mapped 'id': {0}".format(profile["id"]), "DEBUG")

            # Map the rules if they exist in the profile
            if "rules" in profile:
                mapped_rules = []
                self.log("Mapping rules for profile: {0}".format(profile.get("power_profile_name", "Unnamed")), "DEBUG")

                for rule in profile["rules"]:
                    mapped_rule = {}
                    if "interface_type" in rule:
                        mapped_rule["interfaceType"] = rule["interface_type"]
                        self.log("Mapped 'interface_type' to 'interfaceType': {0}".format(rule["interface_type"]), "DEBUG")
                    if "interface_id" in rule:
                        mapped_rule["interfaceId"] = rule["interface_id"]
                        self.log("Mapped 'interface_id' to 'interfaceId': {0}".format(rule["interface_id"]), "DEBUG")
                    if "parameter_type" in rule:
                        mapped_rule["parameterType"] = rule["parameter_type"]
                        self.log("Mapped 'parameter_type' to 'parameterType': {0}".format(rule["parameter_type"]), "DEBUG")
                    if "parameter_value" in rule:
                        mapped_rule["parameterValue"] = rule["parameter_value"]
                        self.log("Mapped 'parameter_value' to 'parameterValue': {0}".format(rule["parameter_value"]), "DEBUG")

                    # Add the mapped rule to the list of mapped rules
                    mapped_rules.append(mapped_rule)

                # Assign the mapped rules to the profile
                mapped_profile["rules"] = mapped_rules

            # Add the mapped profile to the list of mapped power profiles
            mapped_power_profiles.append(mapped_profile)
            self.log("Added mapped power profile: {0}".format(mapped_profile), "DEBUG")

        # Log all mapped power profiles
        self.log("Mapped Power Profiles: {0}".format(mapped_power_profiles), "DEBUG")

        # Return the list of mapped power profiles
        return mapped_power_profiles

    def create_power_profile(self, create_power_profile_params):
        """
        Initiates the creation of a power profile using the provided parameters.
        Args:
            create_power_profile_params (dict): A dictionary containing parameters required for creating a power profile.
        Returns:
            dict: The response containing the task ID for the create operation.
        """
        # Log the initiation of the creation process
        self.log("Initiating addition of power profile with parameters: {0}".format(create_power_profile_params), "INFO")

        # Execute the API call to create the power profile and return the task ID
        return self.get_taskid_post_api_call("wireless", "create_power_profile", create_power_profile_params)

    def update_power_profile(self, update_power_profile_params):
        """
        Initiates the update of a power profile using the provided parameters.
        Args:
            update_power_profile_params (dict): A dictionary containing parameters required for updating a power profile.
        Returns:
            dict: The response containing the task ID for the update operation.
        """
        # Log the initiation of the update process
        self.log("Initiating update power profile parameters: {0}".format(update_power_profile_params), "INFO")

        # Execute the API call to update the power profile and return the task ID
        return self.get_taskid_post_api_call("wireless", "update_power_profile_by_id", update_power_profile_params)

    def delete_power_profile(self, delete_power_profile_params):
        """
        Initiates the deletion of a power profile using the provided parameters.
        Args:
            delete_power_profile_params (dict): A dictionary containing parameters required for deleting a power profile.
        Returns:
            dict: The response containing the task ID for the delete operation.
        """
        # Log the initiation of the deletion process
        self.log("Initiating deletion power profile parameters: {0}".format(delete_power_profile_params), "INFO")

        # Execute the API call to delete the power profile and return the task ID
        return self.get_taskid_post_api_call("wireless", "delete_power_profile_by_id", delete_power_profile_params)

    def process_power_profiles_common(self, profiles_params, operation_function, task_name):
        """
        Processes the power profiles for the specified operation (create, update, delete).
        Args:
            profiles_params (list): A list of dictionaries containing parameters for each power profile operation.
            operation_function (function): The function to execute for each power profile operation.
            task_name (str): The name of the task being performed, e.g., "Create Power Profile(s) Task".
        Returns:
            self: The current instance to allow for method chaining or further processing.
        """
        # Initialize lists to track successful and failed profile operations
        failed_profiles = []
        success_profiles = []
        msg = {}

        # Iterate over each profile parameter set for processing
        for profile in profiles_params:
            profile_name = profile.get("profileName")
            self.log("Processing power profile: {0}".format(profile_name), "DEBUG")

            # Prepare parameters for the operation
            if operation_function == self.delete_power_profile:
                # For delete operation, extract only the id
                operation_params = {"id": profile.get("id")}
            else:
                # For create or update operations, use the entire profile
                operation_params = profile

            # Execute the operation and retrieve the task ID
            task_id = operation_function(operation_params)
            self.log("Task ID for power profile '{0}': {1}".format(profile_name, task_id), "DEBUG")

            # Check the status of the operation
            operation_msg = "{0} operation has completed successfully for power profile: {1}.".format(task_name, profile_name)
            self.get_task_status_from_tasks_by_id(task_id, task_name, operation_msg).check_return_status()

            # Determine if the operation was successful
            if self.status == "success":
                success_profiles.append(profile_name)
                self.log("Power Profile '{0}' processed successfully.".format(profile_name), "INFO")
            else:
                failed_profiles.append(profile_name)
                self.log("Power Profile '{0}' failed to process.".format(profile_name), "ERROR")

        # Set the final message for successful operations
        if success_profiles:
            self.log("{0} succeeded for the following power profile(s): {1}".format(task_name, ", ".join(success_profiles)), "INFO")
            msg["{0} succeeded for the following power profile(s)".format(task_name)] = {
                "success_count": len(success_profiles),
                "successful_power_profiles": success_profiles
            }

        # Set the final message for failed operations
        if failed_profiles:
            self.log("{0} failed for the following power profile(s): {1}".format(task_name, ", ".join(failed_profiles)), "ERROR")
            msg["{0} failed for the following power profile(s)".format(task_name)] = {
                "failed_count": len(failed_profiles),
                "failed_power_profiles": failed_profiles
            }

        # Store the message dictionary in the class
        self.msg = msg

        # Determine the final operation result based on success and failure lists
        if success_profiles and failed_profiles:
            self.set_operation_result("failed", True, self.msg, "ERROR")
        elif success_profiles:
            self.set_operation_result("success", True, self.msg, "INFO")
        elif failed_profiles:
            self.set_operation_result("failed", True, self.msg, "ERROR")
        else:
            self.set_operation_result("ok", False, self.msg, "INFO")

        # Return the instance for method chaining or further processing
        return self

    def process_add_power_profiles(self, add_power_profiles_params):
        """
        Initiates the process to add power profiles.
        Args:
            add_power_profiles_params (list): A list of dictionaries containing parameters for each power profile to be added.
        Returns:
            self: The current instance to allow for method chaining or further processing.
        """
        # Define the task name for creating power profiles
        task_name_create = "Create Power Profile(s) Task"
        self.log("Starting the creation process for power profiles with task name: {0}".format(task_name_create), "INFO")

        # Call the common processing function to add power profiles
        return self.process_power_profiles_common(
            add_power_profiles_params,
            self.create_power_profile,
            task_name_create
        )

    def process_update_power_profiles(self, update_power_profiles_params):
        """
        Initiates the process to update power profiles.
        Args:
            update_power_profiles_params (list): A list of dictionaries containing parameters for each power profile to be updated.
        Returns:
            self: The current instance to allow for method chaining or further processing.
        """
        # Define the task name for updating power profiles
        task_name_update = "Update Power Profile(s) Task"
        self.log("Starting the update process for power profiles with task name: {0}".format(task_name_update), "INFO")

        # Call the common processing function to update power profiles
        return self.process_power_profiles_common(
            update_power_profiles_params,
            self.update_power_profile,
            task_name_update
        )

    def process_delete_power_profiles(self, delete_power_profiles_params):
        """
        Initiates the process to delete power profiles.
        Args:
            delete_power_profiles_params (list): A list of dictionaries containing parameters for each power profile to be deleted.
        Returns:
            self: The current instance to allow for method chaining or further processing.
        """
        # Define the task name for deleting power profiles
        task_name_delete = "Delete Power Profile(s) Task"
        self.log("Starting the deletion process for power profiles with task name: {0}".format(task_name_delete), "INFO")

        # Call the common processing function to delete power profiles
        return self.process_power_profiles_common(
            delete_power_profiles_params,
            self.delete_power_profile,
            task_name_delete
        )

    def verify_add_power_profiles_operation(self, add_power_profiles_params):
        """
        Verifies whether the power profiles specified in add_power_profiles_params have been successfully created.
        Args:
            add_power_profiles_params (list): A list of dictionaries containing the requested power profile parameters to be added.
        Returns:
            tuple: Two lists containing successfully created power profiles and failed profiles.
        """
        # Retrieve all existing power profiles
        existing_power_profiles = self.get_power_profiles(get_power_profiles_params={})
        self.log("Retrieved existing power profiles.", "DEBUG")

        # Log existing and requested power profiles for debugging
        self.log("Existing Power Profiles: {0}".format(existing_power_profiles), "DEBUG")
        self.log("Requested Power Profiles to Add: {0}".format(add_power_profiles_params), "DEBUG")

        # Initialize lists to track successful and failed profile additions
        successful_profiles = []
        failed_profiles = []

        # Convert existing power profiles to a set for quick lookup by profile name
        existing_profiles_set = {profile["profileName"] for profile in existing_power_profiles}
        self.log("Converted existing profiles to a set for quick lookup.", "DEBUG")

        # Iterate over the requested power profiles to verify creation
        for requested_profile in add_power_profiles_params:
            profile_name = requested_profile["profileName"]
            self.log("Verifying creation for profile: {0}".format(profile_name), "DEBUG")

            # Check if the profile exists in the existing profiles
            if profile_name in existing_profiles_set:
                successful_profiles.append(profile_name)
                self.log("Power Profile '{0}' has been successfully created.".format(profile_name), "INFO")
            else:
                failed_profiles.append(profile_name)
                self.log("Power Profile '{0}' failed to create.".format(profile_name), "ERROR")

        # Log the summary of the operation
        if failed_profiles:
            self.log("The ADD Power Profile(s) operation may not have been successful since some power profiles were not successfully created: {0}"
                     .format(failed_profiles), "WARNING")
        else:
            self.log("Verified the success of ADD Power Profile(s) operation for the following profiles: {0}.".format(successful_profiles), "INFO")

    def verify_update_power_profiles_operation(self, update_power_profiles_params):
        """
        Verifies whether the power profiles specified in update_power_profiles_params have been successfully updated.
        Args:
            update_power_profiles_params (list): A list of dictionaries containing the requested power profile parameters to be updated.
        Returns:
            tuple: Two lists containing successfully updated power profiles and failed profiles.
        """
        # Retrieve all existing power profiles
        existing_power_profiles = self.get_power_profiles(get_power_profiles_params={})
        self.log("Retrieved existing power profiles.", "DEBUG")

        # Log existing and requested power profiles for debugging
        self.log("Existing Power Profiles: {0}".format(existing_power_profiles), "DEBUG")
        self.log("Requested Power Profiles to Update: {0}".format(update_power_profiles_params), "DEBUG")

        # Initialize lists to track successful and failed profile updates
        successful_updates = []
        failed_updates = []

        # Convert existing power profiles to a dictionary for quick lookup by profile name
        existing_profiles_dict = {profile["profileName"]: profile for profile in existing_power_profiles}
        self.log("Converted existing profiles to a dictionary for quick lookup.", "DEBUG")

        # Iterate over the requested power profiles to verify updates
        for requested_profile in update_power_profiles_params:
            profile_name = requested_profile["profileName"]
            requested_description = requested_profile.get("description", "")
            requested_rules = requested_profile.get("rules", [])
            self.log("Verifying update for profile: {0}".format(profile_name), "DEBUG")

            # Check if the profile exists in the existing profiles
            if profile_name in existing_profiles_dict:
                existing_profile = existing_profiles_dict[profile_name]
                existing_description = existing_profile.get("description", "")
                existing_rules = existing_profile.get("rules", [])

                # Flag to determine if an update is needed
                update_successful = True

                # Compare description
                if requested_description != existing_description:
                    update_successful = False
                    self.log("Description mismatch for profile '{0}'. Requested: {1}, Existing: {2}".format(
                        profile_name, requested_description, existing_description), "DEBUG")

                # Compare rules, ignoring the sequence parameter
                if len(requested_rules) != len(existing_rules):
                    update_successful = False
                    self.log("Rule count mismatch for profile '{0}'. Requested: {1}, Existing: {2}".format(
                        profile_name, len(requested_rules), len(existing_rules)), "DEBUG")
                else:
                    for req_rule, exist_rule in zip(requested_rules, existing_rules):
                        if (
                            req_rule.get("interfaceType") != exist_rule.get("interfaceType") or
                            req_rule.get("interfaceId") != exist_rule.get("interfaceId") or
                            req_rule.get("parameterType") != exist_rule.get("parameterType")
                        ):
                            update_successful = False
                            self.log("Rule mismatch in profile '{0}'. Requested rule: {1}, Existing rule: {2}".format(
                                profile_name, req_rule, exist_rule), "DEBUG")
                            break

                if update_successful:
                    successful_updates.append(profile_name)
                    self.log("Power Profile '{0}' has been successfully updated.".format(profile_name), "INFO")
                else:
                    failed_updates.append(profile_name)
                    self.log("Power Profile '{0}' failed to update.".format(profile_name), "ERROR")
            else:
                failed_updates.append(profile_name)
                self.log("Power Profile '{0}' does not exist and cannot be updated.".format(profile_name), "ERROR")

        # Log the summary of the operation
        if failed_updates:
            self.log("The UPDATE Power Profiles operation may not have been successful. The following power profiles failed verification: {0}.".format(
                failed_updates), "ERROR")
        else:
            self.log("Successfully verified the UPDATE Power Profiles operation for the following profiles: {0}.".format(successful_updates), "INFO")

    def verify_delete_power_profiles_operation(self, delete_power_profiles_params):
        """
        Verifies whether the power profiles specified in delete_power_profiles_params have been successfully deleted.
        Args:
            delete_power_profiles_params (list): A list of dictionaries containing the requested power profile names to be deleted.
        Returns:
            bool: True if all requested power profiles were successfully deleted, False otherwise.
        """
        # Retrieve all existing power profiles
        existing_power_profiles = self.get_power_profiles(get_power_profiles_params={})
        # Convert existing profiles to a set for quick lookup
        existing_profiles_set = {profile["profileName"] for profile in existing_power_profiles}
        self.log("Retrieved current power profiles.", "DEBUG")

        # Log the current state of profiles and requested deletions
        self.log("Current Power Profiles after DELETE operation: {0}".format(existing_profiles_set), "INFO")
        self.log("Requested Power Profiles to Delete: {0}".format(delete_power_profiles_params), "INFO")

        # Initialize a list to track profiles that failed deletion
        failed_deletions = []

        # Iterate over the requested power profiles to verify deletion
        for requested_profile in delete_power_profiles_params:
            profile_name = requested_profile["profileName"]
            self.log("Verifying deletion for profile: {0}".format(profile_name), "DEBUG")

            # Check if the profile still exists in the existing profiles
            if profile_name in existing_profiles_set:
                # If it exists, the deletion failed
                failed_deletions.append(profile_name)
                self.log("Delete operation failed for Power Profile '{0}'. It still exists.".format(profile_name), "ERROR")

        # Log the summary of the operation
        if failed_deletions:
            self.log("The DELETE Power Profile(s) operation may not have been successful since some Power Profiles still exist: {0}."
                     .format(failed_deletions), "ERROR")
        else:
            self.log("Verified the success of DELETE Power Profile(s) operation for following parameters: {0}.".format(delete_power_profiles_params), "INFO")

    def get_access_point_profiles_params(self, access_point_profile_name=None):
        """
        Constructs and returns a dictionary of parameters for retrieving access point profiles.
        Args:
            access_point_profile_name (str, optional): The name of the access point profile to filter the retrieval.
        Returns:
            dict: A dictionary containing parameters to be used for API calls to retrieve access point profiles.
        """
        # Initialize an empty dictionary to hold the parameters for the API call
        get_access_point_profiles_params = {}

        # Map the user-provided access point profile name to the expected API parameter
        if access_point_profile_name:
            get_access_point_profiles_params["ap_profile_name"] = access_point_profile_name
            self.log("Added 'ap_profile_name' to parameters: {0}".format(access_point_profile_name), "DEBUG")
        else:
            self.log("No specific access point profile name provided.", "DEBUG")

        # Return the constructed parameters dictionary
        self.log("Constructed get_access_point_profiles_params: {0}".format(get_access_point_profiles_params), "DEBUG")
        return get_access_point_profiles_params

    def get_access_point_profiles(self, get_access_point_profiles_params):
        """
        Retrieves access point profile details using pagination.
        Args:
            get_access_point_profiles_params (dict): Parameters for filtering the access point profiles.
        Returns:
            list: A list of dictionaries containing details of access point profiles based on the filtering parameters.
        """
        # Execute the paginated API call to retrieve access point profiles
        self.log("Executing paginated API call to retrieve access point profiles.", "DEBUG")
        return self.execute_get_with_pagination("wireless", "get_ap_profiles", get_access_point_profiles_params)

    def map_access_point_profiles_params(self, access_point_profiles):
        """
        Maps the provided access point profiles parameters to the parameters required for API calls.
        Args:
            access_point_profiles (list): A list of dictionaries containing access point profile parameters.
        Returns:
            list: A list of dictionaries with mapped parameters suitable for API calls.
        """
        # Initialize an empty list to store the mapped access point profiles
        mapped_access_point_profiles = []

        # Check if the access point profiles list is empty and return the empty mapped list
        if not access_point_profiles:
            self.log("No access point profiles provided for mapping.", "DEBUG")
            return mapped_access_point_profiles

        # Define a mapping from country names to country codes
        country_code_map = {
            # Country name to code mappings
            "Afghanistan": "AF", "Albania": "AL", "Algeria": "DZ", "Angola": "AO", "Argentina": "AR", "Australia": "AU",
            "Austria": "AT", "Bahamas": "BS", "Bahrain": "BH", "Bangladesh": "BD", "Barbados": "BB", "Belarus": "BY",
            "Belgium": "BE", "Bhutan": "BT", "Bolivia": "BO", "Bosnia": "BA", "Botswana": "BW", "Brazil": "BR",
            "Brunei": "BN", "Bulgaria": "BG", "Burundi": "BI", "Cambodia": "KH", "Cameroon": "CM", "Canada": "CA",
            "Chile": "CL", "China": "CN", "Colombia": "CO", "Costa Rica": "CR", "Croatia": "HR", "Cuba": "CU",
            "Cyprus": "CY", "Czech Republic": "CZ", "Democratic Republic of the Congo": "CD", "Denmark": "DK", "Dominican Republic": "DO",
            "Ecuador": "EC", "Egypt": "EG", "El Salvador": "SV", "Estonia": "EE", "Ethiopia": "ET", "Fiji": "FJ",
            "Finland": "FI", "France": "FR", "Gabon": "GA", "Georgia": "GE", "Germany": "DE", "Ghana": "GH",
            "Gibraltar": "GI", "Greece": "GR", "Guatemala": "GT", "Honduras": "HN", "Hong Kong": "HK", "Hungary": "HU",
            "Iceland": "IS", "India": "IN", "Indonesia": "ID", "Iraq": "IQ", "Ireland": "IE", "Isle of Man": "IM",
            "Israel": "IL", "Italy": "IT", "Ivory Coast (Cote dIvoire)": "CI", "Jamaica": "JM", "Japan 2(P)": "J2", "Japan 4(Q)": "J4",
            "Jersey": "JE", "Jordan": "JO", "Kazakhstan": "KZ", "Kenya": "KE", "Korea Extended (CK)": "KR", "Kosovo": "XK",
            "Kuwait": "KW", "Laos": "LA", "Latvia": "LV", "Lebanon": "LB", "Libya": "LY", "Liechtenstein": "LI",
            "Lithuania": "LT", "Luxembourg": "LU", "Macao": "MO", "Macedonia": "MK", "Malaysia": "MY", "Malta": "MT",
            "Mauritius": "MU", "Mexico": "MX", "Moldova": "MD", "Monaco": "MC", "Mongolia": "MN", "Montenegro": "ME",
            "Morocco": "MA", "Myanmar": "MM", "Namibia": "NA", "Nepal": "NP", "Netherlands": "NL", "New Zealand": "NZ",
            "Nicaragua": "NI", "Nigeria": "NG", "Norway": "NO", "Oman": "OM", "Pakistan": "PK", "Panama": "PA",
            "Paraguay": "PY", "Peru": "PE", "Philippines": "PH", "Poland": "PL", "Portugal": "PT", "Puerto Rico": "PR",
            "Qatar": "QA", "Romania": "RO", "Russian Federation": "RU", "San Marino": "SM", "Saudi Arabia": "SA",
            "Serbia": "RS", "Singapore": "SG", "Slovak Republic": "SK", "Slovenia": "SI", "South Africa": "ZA", "Spain": "ES",
            "Sri Lanka": "LK", "Sudan": "SD", "Sweden": "SE", "Switzerland": "CH", "Taiwan": "TW", "Thailand": "TH",
            "Trinidad": "TT", "Tunisia": "TN", "Turkey": "TR", "Uganda": "UG", "Ukraine": "UA", "United Arab Emirates": "AE",
            "United Kingdom": "GB", "United Republic of Tanzania": "TZ", "United States": "US", "Uruguay": "UY", "Uzbekistan": "UZ",
            "Vatican City State": "VA", "Venezuela": "VE", "Vietnam": "VN", "Yemen": "YE", "Zambia": "ZM", "Zimbabwe": "ZW"
        }

        # Iterate over each access point profile
        for profile in access_point_profiles:
            mapped_profile = {}

            # Map the ID if it exists
            if "id" in profile:
                mapped_profile["id"] = profile["id"]
                self.log("Mapped 'id' to '{0}'.".format(profile["id"]), "DEBUG")

            # Define mappings for basic profile attributes
            mappings = {
                "apProfileName": profile.get("access_point_profile_name"),
                "description": profile.get("access_point_profile_description"),
                "remoteWorkerEnabled": profile.get("remote_teleworker"),
                "awipsEnabled": profile.get("security_settings", {}).get("awips"),
                "awipsForensicEnabled": profile.get("security_settings", {}).get("awips_forensic"),
                "pmfDenialEnabled": profile.get("security_settings", {}).get("pmf_denial"),
                "meshEnabled": profile.get("mesh_enabled"),
                "apPowerProfileName": profile.get("power_settings", {}).get("ap_power_profile_name"),
                "countryCode": profile.get("country_code"),
                "timeZone": profile.get("time_zone"),
                "timeZoneOffsetHour": profile.get("time_zone_offset_hour"),
                "timeZoneOffsetMinutes": profile.get("time_zone_offset_minutes"),
                "clientLimit": profile.get("maximum_client_limit"),
            }

            # Apply basic mappings
            self.log("Applying basic mappings.", "DEBUG")
            for key, value in mappings.items():
                if value is not None:
                    mapped_profile[key] = value
                    self.log("Mapped '{0}' to '{1}'.".format(key, value), "DEBUG")

            # Map the country code if provided
            if "country_code" in profile:
                mapped_profile["countryCode"] = country_code_map.get(profile["country_code"])
                self.log("Mapped 'country_code' to '{0}'.".format(mapped_profile["countryCode"]), "DEBUG")

            # Define mappings for management settings
            management_mapping = {
                "access_point_authentication": "authType",
                "dot1x_username": "dot1xUsername",
                "dot1x_password": "dot1xPassword",
                "ssh_enabled": "sshEnabled",
                "telnet_enabled": "telnetEnabled",
                "management_username": "managementUserName",
                "management_password": "managementPassword",
                "management_enable_password": "managementEnablePassword",
                "cdp_state": "cdpState"
            }

            # Map the management settings if they exist
            if "management_settings" in profile:
                management_settings = profile["management_settings"]
                mapped_profile["managementSetting"] = {}

                for key, original_key in management_mapping.items():
                    if key in management_settings:
                        mapped_profile["managementSetting"][original_key] = management_settings[key]
                        self.log("Mapped '{0}' to '{1}'.".format(key, original_key), "DEBUG")
                    else:
                        self.log("Key '{0}' not found in management_settings.".format(key), "WARNING")

            # Define mappings for rogue detection settings
            rogue_detection_mapping = {
                "rogue_detection_enabled": "rogueDetection",
                "minimum_rssi": "rogueDetectionMinRssi",
                "transient_interval": "rogueDetectionTransientInterval",
                "report_interval": "rogueDetectionReportInterval"
            }

            # Map the rogue detection settings if they exist
            if "security_settings" in profile:
                security_settings = profile["security_settings"]
                if security_settings.get("rogue_detection_enabled", False):
                    mapped_profile["rogueDetectionSetting"] = {}

                    for key, original_key in rogue_detection_mapping.items():
                        if key in security_settings:
                            mapped_profile["rogueDetectionSetting"][original_key] = security_settings[key]
                            self.log("Mapped '{0}' to '{1}'.".format(key, original_key), "DEBUG")
                        else:
                            self.log("Key '{0}' not found in security_settings.".format(key), "WARNING")

            # Define mappings for mesh settings
            mesh_mapping = {
                "bridge_group_name": "bridgeGroupName",
                "backhaul_client_access": "backhaulClientAccess",
                "range": "range",
                "ghz_5_radio_band_type": "ghz5BackhaulDataRates",
                "ghz_2_point_4_radio_band_type": "ghz24BackhaulDataRates",
                "rap_downlink_backhaul": "rapDownlinkBackhaul"
            }

            # Map the mesh settings if they exist
            if "mesh_settings" in profile:
                mesh_settings = profile["mesh_settings"]
                mapped_profile["meshSetting"] = {}

                for key, original_key in mesh_mapping.items():
                    if key in mesh_settings:
                        mapped_profile["meshSetting"][original_key] = mesh_settings[key]
                        self.log("Mapped '{0}' to '{1}'.".format(key, original_key), "DEBUG")
                    else:
                        self.log("Key '{0}' not found in mesh_settings.".format(key), "WARNING")

            # Map calendar power profiles if they exist
            if "power_settings" in profile:
                power_settings = profile["power_settings"]

                calendar_power_profiles_mapping = {
                    "ap_power_profile_name": "powerProfileName",
                    "scheduler_type": "schedulerType"
                }

                scheduler_mapping = {
                    "scheduler_start_time": "schedulerStartTime",
                    "scheduler_end_time": "schedulerEndTime",
                    "scheduler_days_list": "schedulerDay",
                    "scheduler_dates_list": "schedulerDate"
                }

                # Initialize the API-compatible structure for calendar power profiles
                api_calendar_profiles = []

                # Iterate over each calendar power profile in the provided settings
                for calendar_profile in power_settings.get("calendar_power_profiles", []):
                    # Map the main calendar power profile fields
                    api_calendar_profile = {}
                    for provided_key, api_key in calendar_power_profiles_mapping.items():
                        if provided_key in calendar_profile:
                            api_calendar_profile[api_key] = calendar_profile[provided_key]
                            self.log("Mapped '{0}' to '{1}'.".format(provided_key, api_key), "DEBUG")

                    # Map the scheduler fields
                    api_calendar_profile["duration"] = {}
                    for provided_key, api_key in scheduler_mapping.items():
                        if provided_key in calendar_profile:
                            api_calendar_profile["duration"][api_key] = calendar_profile[provided_key]
                            self.log("Mapped '{0}' to '{1}'.".format(provided_key, api_key), "DEBUG")

                    # Add the mapped calendar profile to the list
                    api_calendar_profiles.append(api_calendar_profile)
                    self.log("Added mapped calendar power profile: {0}".format(api_calendar_profile), "DEBUG")

                mapped_profile["calendarPowerProfiles"] = api_calendar_profiles

            # Add the mapped profile to the list
            mapped_access_point_profiles.append(mapped_profile)
            self.log("Added mapped access point profile: {0}".format(mapped_profile), "DEBUG")

        # Log all mapped access point profiles
        self.log("Mapped Access Point Profiles: {0}".format(mapped_access_point_profiles), "DEBUG")

        # Return the list of mapped access point profiles
        return mapped_access_point_profiles

    def normalize_time(self, time_str):
        """
        Normalize the time string to a standard format (HH:MM AM/PM).
        Args:
            time_str (str): The time string to be normalized.
        Returns:
            str: The normalized time string in the format HH:MM AM/PM.
        """
        # Use regex to match the time string pattern
        self.log("Attempting to normalize time string: {0}".format(time_str), "DEBUG")
        match = re.match(r"(\d{1,2}):(\d{2})\s?(AM|PM)", time_str, re.IGNORECASE)

        if match:
            # Extract hour, minute, and period from the matched groups
            hour, minute, period = match.groups()
            self.log("Matched time components - Hour: {0}, Minute: {1}, Period: {2}".format(hour, minute, period), "DEBUG")

            # Ensure two digits for the hour
            hour = hour.zfill(2)
            normalized_time = "{0}:{1} {2}".format(hour, minute, period.upper())
            self.log("Normalized time string: {0}".format(normalized_time), "DEBUG")
            return normalized_time

        # Return the original time string if no match is found
        self.log("No match found for time string. Returning original: {0}".format(time_str), "DEBUG")
        return time_str

    def compare_values(self, requested_value, existing_value):
        """
        Compare requested and existing values, handling different types.
        Args:
            requested_value: The value requested for comparison.
            existing_value: The existing value to compare against.
        Returns:
            bool: True if values match, False otherwise.
        """
        # Compare dictionaries key by key
        if isinstance(requested_value, dict) and isinstance(existing_value, dict):
            self.log("Comparing dictionaries.", "DEBUG")
            for sub_key in requested_value:
                if not self.compare_values(requested_value[sub_key], existing_value.get(sub_key)):
                    self.log("Mismatch found in dictionary comparison for key: {0}".format(sub_key), "DEBUG")
                    return False

        # Compare lists by sorting and comparing elements
        elif isinstance(requested_value, list) and isinstance(existing_value, list):
            self.log("Comparing lists.", "DEBUG")
            requested_sorted = sorted(requested_value, key=str)
            existing_sorted = sorted(existing_value, key=str)
            # requested_sorted = sorted(requested_value, key=lambda x: str(x))
            # existing_sorted = sorted(existing_value, key=lambda x: str(x))
            comparison_result = all(self.compare_values(r, e) for r, e in zip(requested_sorted, existing_sorted))
            self.log("List comparison result: {0}".format(comparison_result), "DEBUG")
            return comparison_result

        # Normalize and compare time strings
        elif isinstance(requested_value, str) and isinstance(existing_value, str):
            self.log("Comparing string values.", "DEBUG")
            requested_value = self.normalize_time(requested_value)
            existing_value = self.normalize_time(existing_value)
            comparison_result = requested_value == existing_value
            self.log("String comparison result: {0}".format(comparison_result), "DEBUG")
            return comparison_result

        # Direct comparison for other types
        else:
            self.log("Directly comparing values: {0} and {1}".format(requested_value, existing_value), "DEBUG")
            return requested_value == existing_value

        return True

    def recursive_update(self, existing, updates):
        """
        Recursively update a dictionary with values from another dictionary.
        This function handles nested dictionaries and lists of dictionaries, updating
        entries in `existing` with corresponding entries in `updates`.
        Args:
            existing (dict): The dictionary to be updated.
            updates (dict): The dictionary containing updates.
        """
        # Iterate over each key-value pair in the updates dictionary
        for key, value in updates.items():
            if isinstance(value, dict) and key in existing and isinstance(existing[key], dict):
                # If the value is a dictionary and exists in the existing dictionary, recursively update it
                self.log("Recursively updating dictionary for key: {0}".format(key), "DEBUG")
                self.recursive_update(existing[key], value)
            elif isinstance(value, list) and key in existing and isinstance(existing[key], list):
                # If the value is a list, handle lists of dictionaries
                self.log("Handling list of dictionaries for key: {0}".format(key), "DEBUG")
                existing_list = existing[key]
                updates_list = value

                # Iterate over each dictionary in the updates list
                for update_dict in updates_list:
                    if isinstance(update_dict, dict):
                        # Assume each dictionary has a unique identifier key to match
                        identifier_keys = ["powerProfileName"]
                        matched = False

                        # Check for matches in the existing list
                        for existing_dict in existing_list:
                            if any(existing_dict.get(id_key) == update_dict.get(id_key) for id_key in identifier_keys if id_key in update_dict):
                                # If a match is found, recursively update the existing dictionary
                                self.log("Match found for update. Recursively updating existing dictionary.", "DEBUG")
                                self.recursive_update(existing_dict, update_dict)
                                matched = True
                                break

                        if not matched:
                            # If no match is found, append the update_dict as a new entry
                            self.log("No match found. Appending new dictionary to existing list.", "DEBUG")
                            existing_list.append(update_dict)
            else:
                # For non-dictionary or non-list values, directly update the existing value
                self.log("Updating value for key: {0}".format(key), "DEBUG")
                existing[key] = value

    def verify_create_update_access_point_profiles_requirement(self, access_point_profiles):
        """
        Determines whether access point profiles need to be created, updated, or require no updates.
        Args:
            access_point_profiles (list): A list of dictionaries containing the requested access point profile parameters.
        Returns:
            tuple: Three lists containing access point profiles to be created, updated, and not updated.
        """
        # Update requested profiles with default values where needed
        updated_access_point_profiles = self.map_access_point_profiles_params(access_point_profiles)
        self.log("Mapped requested profiles to include default values.", "DEBUG")

        # Retrieve all existing access point profiles from the system
        existing_access_point_profiles = self.get_access_point_profiles(get_access_point_profiles_params={})
        self.log("Retrieved existing access point profiles from the system.", "DEBUG")

        # Log the existing and requested access point profiles for debugging
        self.log("Existing Access Point Profiles: {0}".format(existing_access_point_profiles), "DEBUG")
        self.log("Requested Access Point Profiles: {0}".format(updated_access_point_profiles), "DEBUG")

        # Initialize lists to store profiles that need to be created, updated, or not changed
        create_profiles = []
        update_profiles = []
        no_update_profiles = []

        # Create a dictionary of existing profiles for quick lookup using the profile name
        existing_profiles_dict = {profile["apProfileName"]: profile for profile in existing_access_point_profiles}
        self.log("Converted existing profiles to a dictionary for quick lookup.", "DEBUG")

        # Iterate over the updated requested access point profiles
        for requested_profile in updated_access_point_profiles:
            profile_name = requested_profile["apProfileName"]
            self.log("Checking profile: {0}".format(profile_name), "DEBUG")
            update_needed = False

            # Check if the profile already exists
            if profile_name in existing_profiles_dict:
                existing_profile = existing_profiles_dict[profile_name]
                self.log("Profile '{0}' exists in the system.".format(profile_name), "DEBUG")

                # Iterate over each parameter in the requested profile
                for key, requested_value in requested_profile.items():
                    if key in existing_profile:
                        existing_value = existing_profile[key]

                        # Compare requested and existing values
                        if not self.compare_values(requested_value, existing_value):
                            update_needed = True
                            self.log(
                                "Mismatch found in parameter '{0}' for profile '{1}'. "
                                "Requested value: {2}, Existing value: {3}".format(
                                    key, profile_name, requested_value, existing_value
                                ),
                                "DEBUG"
                            )
                            break

                if update_needed:
                    # Copy the existing profile and update it with the requested values
                    updated_profile = existing_profile.copy()
                    self.recursive_update(updated_profile, requested_profile)
                    update_profiles.append(updated_profile)
                    self.log("Profile '{0}' marked for update.".format(profile_name), "DEBUG")
                else:
                    # No changes needed for this profile
                    no_update_profiles.append(existing_profile)
                    self.log("Profile '{0}' requires no updates.".format(profile_name), "DEBUG")

            else:
                # The profile does not exist and needs to be created
                create_profiles.append(requested_profile)
                self.log("Profile '{0}' marked for creation.".format(profile_name), "DEBUG")

        # Log the results of the categorization
        self.log("Access Point Profiles that need to be CREATED: {0} - {1}".format(len(create_profiles), create_profiles), "DEBUG")
        self.log("Access Point Profiles that need to be UPDATED: {0} - {1}".format(len(update_profiles), update_profiles), "DEBUG")
        self.log("Access Point Profiles that DON'T NEED UPDATES: {0} - {1}".format(len(no_update_profiles), no_update_profiles), "DEBUG")

        # Validate that the total number of processed profiles matches the number of requested profiles
        total_profiles_processed = len(create_profiles) + len(update_profiles) + len(no_update_profiles)
        if total_profiles_processed == len(updated_access_point_profiles):
            self.log("Match in total counts: Processed={0}, Requested={1}.".format(total_profiles_processed, len(updated_access_point_profiles)), "DEBUG")
        else:
            self.log("Mismatch in total counts: Processed={0}, Requested={1}.".format(total_profiles_processed, len(updated_access_point_profiles)), "ERROR")

        # Return the categorized profiles
        return create_profiles, update_profiles, no_update_profiles

    def verify_delete_access_point_profiles_requirement(self, access_point_profiles):
        """
        Determines whether access point profiles need to be deleted based on the requested parameters.
        Args:
            access_point_profiles (list): A list of dictionaries containing the requested access point profile parameters for deletion.
        Returns:
            list: A list of access point profiles that need to be deleted, including their IDs.
        """
        # Initialize the list to hold profiles scheduled for deletion
        delete_access_point_profiles_list = []

        # Log the start of the verification process for deletions
        self.log("Starting verification of access point profiles for deletion.", "INFO")

        # Retrieve all existing access point profiles
        existing_access_point_profiles = self.get_access_point_profiles(get_access_point_profiles_params={})
        self.log("Existing Access Point Profiles: {0}".format(existing_access_point_profiles), "DEBUG")

        # Convert existing access point profiles to a dictionary for quick lookup by profile name
        existing_profiles_dict = {profile["apProfileName"]: profile for profile in existing_access_point_profiles}
        self.log("Converted existing profiles to a dictionary for quick lookup.", "DEBUG")

        # Iterate over the requested access point profiles
        for requested_profile in access_point_profiles:
            profile_name = requested_profile.get("access_point_profile_name")
            self.log("Checking deletion requirement for profile: {0}".format(profile_name), "DEBUG")

            # Check if the access point profile exists in the existing access point profiles
            if profile_name in existing_profiles_dict:
                # Add the requested access point profile with the ID from the existing profile
                existing_profile = existing_profiles_dict[profile_name]
                profile_to_delete = requested_profile.copy()
                profile_to_delete["id"] = existing_profile.get("id")
                delete_access_point_profiles_list.append(profile_to_delete)
                self.log("Access Point Profile '{0}' scheduled for deletion.".format(profile_name), "INFO")
            else:
                # Log that deletion is not required for profiles that don't exist
                self.log("Deletion not required for access point profile '{0}'. It does not exist.".format(profile_name), "INFO")

        # Log the list of profiles scheduled for deletion
        self.log("Access Point Profiles scheduled for deletion: {0} - {1}".format(
            len(delete_access_point_profiles_list), delete_access_point_profiles_list), "DEBUG")

        # Return the list of profiles that need to be deleted
        return delete_access_point_profiles_list

    def create_access_point_profile(self, create_access_point_profile_params):
        """
        Initiates the creation of an access point profile using the provided parameters.
        Args:
            create_access_point_profile_params (dict): A dictionary containing parameters required for creating an access point profile.
        Returns:
            dict: The response containing the task ID for the create operation.
        """
        # Log the initiation of the creation process
        self.log("Initiating addition of Access Point profiles with parameters: {0}".format(create_access_point_profile_params), "INFO")

        # Execute the API call to create the access point profile and return the task ID
        return self.get_taskid_post_api_call("wireless", "create_ap_profile", create_access_point_profile_params)

    def update_access_point_profile(self, update_access_point_profile_params):
        """
        Initiates the update of an access point profile using the provided parameters.
        Args:
            update_access_point_profile_params (dict): A dictionary containing parameters required for updating an access point profile.
        Returns:
            dict: The response containing the task ID for the update operation.
        """
        # Log the initiation of the update process
        self.log("Initiating update Access Point profiles with parameters: {0}".format(update_access_point_profile_params), "INFO")

        # Execute the API call to update the access point profile and return the task ID
        return self.get_taskid_post_api_call("wireless", "update_ap_profile_by_id", update_access_point_profile_params)

    def delete_access_point_profile(self, delete_access_point_profile_params):
        """
        Initiates the deletion of an access point profile using the provided parameters.
        Args:
            delete_access_point_profile_params (dict): A dictionary containing parameters required for deleting an access point profile.
        Returns:
            dict: The response containing the task ID for the delete operation.
        """
        # Log the initiation of the deletion process
        self.log("Initiating deletion of Access Point profiles with parameters: {0}".format(delete_access_point_profile_params), "INFO")

        # Execute the API call to delete the access point profile and return the task ID
        return self.get_taskid_post_api_call("wireless", "delete_ap_profile_by_id", delete_access_point_profile_params)

    def process_access_point_profiles_common(self, access_point_profiles_params, create_or_update_or_delete_access_point_profiles, task_name):
        """
        Processes the access point profiles for the specified operation (create, update, delete).
        Args:
            access_point_profiles_params (list): A list of dictionaries containing parameters for each access point profile operation.
            create_or_update_or_delete_access_point_profiles (function): The function to execute for each access point profile operation.
            task_name (str): The name of the task being performed, e.g., "Create Access Point Profile(s) Task".
        Returns:
            self: The current instance to allow for method chaining or further processing.
        """
        # Initialize lists to track successful and failed profile operations
        failed_profiles = []
        success_profiles = []
        msg = {}

        # Iterate over each profile parameter set for processing
        for profile in access_point_profiles_params:
            profile_name = profile.get("apProfileName")
            self.log("Processing access point profile: {0}".format(profile_name), "DEBUG")

            # Prepare parameters for the operation
            if create_or_update_or_delete_access_point_profiles == self.delete_access_point_profile:
                # For delete operations, only the ID is needed
                operation_params = {"id": profile.get("id")}
            else:
                # For create or update operations, use the entire profile
                operation_params = profile

            # Execute the operation and retrieve the task ID
            task_id = create_or_update_or_delete_access_point_profiles(operation_params)
            self.log("Task ID for access point profile '{0}': {1}".format(profile_name, task_id), "DEBUG")

            # Construct operation message
            operation_msg = "{0} operation has completed successfully for access point profile: {1}.".format(task_name, profile_name)

            # Check the status of the operation using the task ID
            self.get_task_status_from_tasks_by_id(task_id, task_name, operation_msg).check_return_status()

            # Determine if the operation was successful and categorize accordingly
            if self.status == "success":
                success_profiles.append(profile_name)
                self.log("Access Point Profile '{0}' processed successfully.".format(profile_name), "INFO")
            else:
                failed_profiles.append(profile_name)
                self.log("Access Point Profile '{0}' failed to process.".format(profile_name), "ERROR")

        # Log and prepare final messages for successful operations
        if success_profiles:
            self.log("{0} succeeded for the following access point profile(s): {1}".format(task_name, ", ".join(success_profiles)), "INFO")
            msg["{0} succeeded for the following access point profile(s)".format(task_name)] = {
                "success_count": len(success_profiles),
                "successful_access_point_profiles": success_profiles
            }

        # Log and prepare final messages for failed operations
        if failed_profiles:
            self.log("{0} failed for the following access point profile(s): {1}".format(task_name, ", ".join(failed_profiles)), "ERROR")
            msg["{0} failed for the following access point profile(s)".format(task_name)] = {
                "failed_count": len(failed_profiles),
                "failed_access_point_profiles": failed_profiles
            }

        # Store the message dictionary in the class
        self.msg = msg

        # Determine the final operation result based on success and failure lists
        if success_profiles and failed_profiles:
            self.set_operation_result("failed", True, self.msg, "ERROR")
        elif success_profiles:
            self.set_operation_result("success", True, self.msg, "INFO")
        elif failed_profiles:
            self.set_operation_result("failed", True, self.msg, "ERROR")
        else:
            self.set_operation_result("ok", False, self.msg, "INFO")

        # Return the instance for method chaining or further processing
        return self

    def process_add_access_point_profiles(self, add_access_point_profiles_params):
        """
        Initiates the process to add access point profiles.
        This function sets up the task name for creating access point profiles and invokes the common processing function
        to handle the actual operation of adding profiles.
        Args:
            add_access_point_profiles_params (list): A list of dictionaries containing parameters for each access point profile to be added.
        Returns:
            The result of the process_access_point_profiles_common function call.
        """
        # Define the task name for logging and operation tracking
        task_name_create = "Create Access Point Profile(s) Task"

        # Log the initiation of the add process
        self.log("Starting the {0} with parameters: {1}".format(task_name_create, add_access_point_profiles_params), "INFO")

        # Call the common processing function with the create operation function
        return self.process_access_point_profiles_common(
            add_access_point_profiles_params,
            self.create_access_point_profile,
            task_name_create
        )

    def process_update_access_point_profiles(self, update_access_point_profiles_params):
        """
        Initiates the process to update access point profiles.
        This function sets up the task name for updating access point profiles and invokes the common processing function
        to handle the actual operation of updating profiles.
        Args:
            update_access_point_profiles_params (list): A list of dictionaries containing parameters for each access point profile to be updated.
        Returns:
            The result of the process_access_point_profiles_common function call.
        """
        # Define the task name for logging and operation tracking
        task_name_update = "Update Access Point Profile(s) Task"

        # Log the initiation of the update process
        self.log("Starting the {0} with parameters: {1}".format(task_name_update, update_access_point_profiles_params), "INFO")

        # Call the common processing function with the update operation function
        return self.process_access_point_profiles_common(
            update_access_point_profiles_params,
            self.update_access_point_profile,
            task_name_update
        )

    def process_delete_access_point_profiles(self, delete_access_point_profiles_params):
        """
        Initiates the process to delete access point profiles.
        This function sets up the task name for deleting access point profiles and invokes the common processing function
        to handle the actual operation of deleting profiles.
        Args:
            delete_access_point_profiles_params (list): A list of dictionaries containing parameters for each access point profile to be deleted.
        Returns:
            The result of the process_access_point_profiles_common function call.
        """
        # Define the task name for logging and operation tracking
        task_name_delete = "Delete Access Point Profile(s) Task"

        # Log the initiation of the delete process
        self.log("Starting the {0} with parameters: {1}".format(task_name_delete, delete_access_point_profiles_params), "INFO")

        # Call the common processing function with the delete operation function
        return self.process_access_point_profiles_common(
            delete_access_point_profiles_params,
            self.delete_access_point_profile,
            task_name_delete
        )

    def verify_add_access_point_profiles_operation(self, add_access_point_profiles_params):
        """
        Verifies whether the access point profiles specified in add_access_point_profiles_params have been successfully created.
        Args:
            add_access_point_profiles_params (list): A list of dictionaries containing the requested access point profile parameters to be added.
        Returns:
            tuple: Two lists containing successfully created access point profiles and failed profiles.
        """
        # Retrieve all existing access point profiles to verify against
        existing_access_point_profiles = self.get_access_point_profiles(get_access_point_profiles_params={})
        self.log("Retrieved existing access point profiles.", "DEBUG")

        # Log existing and requested access point profiles for debugging
        self.log("Existing Access Point Profiles: {0}".format(existing_access_point_profiles), "DEBUG")
        self.log("Requested Access Point Profiles to Add: {0}".format(add_access_point_profiles_params), "DEBUG")

        # Initialize lists to track successful and failed profile additions
        successful_profiles = []
        failed_profiles = []

        # Convert existing access point profiles to a set for quick lookup by profile name
        existing_profiles_set = {profile["apProfileName"] for profile in existing_access_point_profiles}
        self.log("Converted existing profiles to a set for quick lookup.", "DEBUG")

        # Iterate over the requested access point profiles to verify their creation
        for requested_profile in add_access_point_profiles_params:
            profile_name = requested_profile["apProfileName"]
            self.log("Verifying creation for profile: {0}".format(profile_name), "DEBUG")

            # Check if the profile now exists in the existing profiles
            if profile_name in existing_profiles_set:
                # Profile exists, add to successful list
                successful_profiles.append(profile_name)
                self.log("Access Point Profile '{0}' has been successfully created.".format(profile_name), "INFO")
            else:
                # Profile does not exist, add to failed list
                failed_profiles.append(profile_name)
                self.log("Access Point Profile '{0}' failed to create.".format(profile_name), "ERROR")

        # Log the summary of the creation verification
        if failed_profiles:
            self.log("The ADD Access Point Profile(s) operation may not have been successful since some profiles were not successfully created: {0}"
                     .format(failed_profiles), "WARNING")
        else:
            self.log("Verified the success of ADD Access Point Profile(s) operation for parameters: {0}".format(add_access_point_profiles_params), "INFO")

    def verify_update_access_point_profiles_operation(self, update_access_point_profiles_params):
        """
        Verifies whether the access point profiles specified in update_access_point_profiles_params have been successfully updated.
        Args:
            update_access_point_profiles_params (list): A list of dictionaries containing the requested access point profile parameters to be updated.
        Returns:
            tuple: Two lists containing successfully updated access point profiles and failed profiles.
        """
        # Retrieve all existing access point profiles
        existing_access_point_profiles = self.get_access_point_profiles(get_access_point_profiles_params={})
        self.log("Retrieved existing access point profiles.", "DEBUG")

        # Log existing and requested access point profiles for debugging purposes
        self.log("Existing Access Point Profiles: {0}".format(existing_access_point_profiles), "DEBUG")
        self.log("Requested Access Point Profiles to Update: {0}".format(update_access_point_profiles_params), "DEBUG")

        # Initialize lists to track successful and failed profile updates
        successful_updates = []
        failed_updates = []

        # Convert existing access point profiles to a dictionary for quick lookup by profile name
        existing_profiles_dict = {profile["apProfileName"]: profile for profile in existing_access_point_profiles}
        self.log("Converted existing profiles to a dictionary for quick lookup.", "DEBUG")

        # Iterate over the requested access point profiles to verify updates
        for requested_profile in update_access_point_profiles_params:
            profile_name = requested_profile["apProfileName"]
            self.log("Verifying update for profile: {0}".format(profile_name), "DEBUG")

            # Check if the profile exists in the existing profiles
            if profile_name in existing_profiles_dict:
                existing_profile = existing_profiles_dict[profile_name]

                # Flag to determine if the update was successful
                update_successful = True

                # Iterate over each requested parameter to verify if the update was applied
                for key, requested_value in requested_profile.items():
                    if key in existing_profile:
                        existing_value = existing_profile[key]

                        # Special handling for management_settings
                        if key == "managementSetting":
                            # Skip verification for sensitive keys within management_settings
                            sensitive_keys = ["dot1xPassword", "managementPassword", "managementEnablePassword"]
                            for sub_key, sub_value in requested_value.items():
                                if sub_key in sensitive_keys:
                                    continue
                                if not self.compare_values(sub_value, existing_value.get(sub_key)):
                                    update_successful = False
                                    self.log("Mismatch in management setting '{0}' for profile '{1}'. Requested value: {2}, Existing value: {3}".format(
                                        sub_key, profile_name, sub_value, existing_value.get(sub_key)), "ERROR")
                                    break

                        # Use the compare_values method to compare the requested and existing values for other keys
                        elif not self.compare_values(requested_value, existing_value):
                            update_successful = False
                            self.log("Mismatch in parameter '{0}' for profile '{1}'. Requested value: {2}, Existing value: {3}".format(
                                key, profile_name, requested_value, existing_value), "ERROR")
                            break

                if update_successful:
                    successful_updates.append(profile_name)
                    self.log("Access Point Profile '{0}' has been successfully updated.".format(profile_name), "INFO")
                else:
                    failed_updates.append(profile_name)
                    self.log("Access Point Profile '{0}' failed to update.".format(profile_name), "ERROR")
            else:
                failed_updates.append(profile_name)
                self.log("Access Point Profile '{0}' does not exist and cannot be updated.".format(profile_name), "ERROR")

        # Log the summary of the operation
        if failed_updates:
            self.log("The UPDATE Access Point Profiles operation may not have been successful. The following access point profiles failed verification: {0}."
                     .format(failed_updates), "ERROR")
        else:
            self.log("Successfully verified the UPDATE Access Point Profiles operation for the following profiles: {0}.".format(successful_updates), "INFO")

    def verify_delete_access_point_profiles_operation(self, delete_access_point_profiles_params):
        """
        Verifies whether the access point profiles specified in delete_access_point_profiles_params have been successfully deleted.
        Args:
            delete_access_point_profiles_params (list): A list of dictionaries containing the requested access point profile names to be deleted.
        Returns:
            bool: True if all requested access point profiles were successfully deleted, False otherwise.
        """
        # Retrieve all existing access point profiles
        existing_access_point_profiles = self.get_access_point_profiles(get_access_point_profiles_params={})
        existing_profiles_set = {profile["apProfileName"] for profile in existing_access_point_profiles}
        self.log("Retrieved existing access point profiles.", "DEBUG")

        # Log the current state of profiles after the deletion attempt and the requested deletions
        self.log("Current Access Point Profiles after DELETE operation: {0}".format(existing_profiles_set), "INFO")
        self.log("Requested Access Point Profiles to Delete: {0}".format(delete_access_point_profiles_params), "INFO")

        # Initialize a list to track profiles that failed deletion
        failed_deletions = []

        # Iterate over the requested access point profiles to verify deletion
        for requested_profile in delete_access_point_profiles_params:
            profile_name = requested_profile["apProfileName"]
            self.log("Verifying deletion for profile: {0}".format(profile_name), "DEBUG")

            # Check if the profile still exists in the existing profiles
            if profile_name in existing_profiles_set:
                # If it exists, the deletion failed
                failed_deletions.append(profile_name)
                self.log("Delete operation failed for Access Point Profile '{0}'. It still exists.".format(profile_name), "ERROR")

        # Log the summary of the deletion verification operation
        if failed_deletions:
            self.log("The DELETE Access Point Profile(s) operation may not have been successful since some Access Point Profiles still exist: {0}."
                     .format(failed_deletions), "ERROR")
        else:
            self.log("Verified the success of DELETE Access Point Profile(s) operation for the following parameters: {0}."
                     .format(delete_access_point_profiles_params), "INFO")

    def get_radio_frequency_profiles_params(self, radio_frequency_profile_name=None):
        """
        Constructs and returns a dictionary of parameters for retrieving radio frequency profiles.
        Args:
            radio_frequency_profile_name (str, optional): The name of the radio frequency profile to filter the retrieval.
        Returns:
            dict: A dictionary containing parameters to be used for API calls to retrieve radio frequency profiles.
        """
        # Initialize an empty dictionary to hold the parameters for the API call
        get_radio_frequency_profiles_params = {}

        # Map the user-provided radio frequency profile name to the expected API parameter
        if radio_frequency_profile_name:
            get_radio_frequency_profiles_params["rf_profile_name"] = radio_frequency_profile_name
            self.log("Added 'rf_profile_name' to parameters: {0}".format(radio_frequency_profile_name), "DEBUG")
        else:
            self.log("No specific radio frequency profile name provided.", "DEBUG")

        # Return the constructed parameters dictionary
        self.log("Constructed get_radio_frequency_profiles_params: {0}".format(get_radio_frequency_profiles_params), "DEBUG")
        return get_radio_frequency_profiles_params

    def get_radio_frequency_profiles(self, get_radio_frequency_profiles_params):
        """
        Retrieves radio frequency profile details using pagination.
        Args:
            get_radio_frequency_profiles_params (dict): Parameters for filtering the radio frequency profiles.
        Returns:
            list: A list of dictionaries containing details of radio frequency profiles based on the filtering parameters.
        """
        # Execute the paginated API call to retrieve radio frequency profiles
        self.log("Executing paginated API call to retrieve radio frequency profiles.", "DEBUG")
        return self.execute_get_with_pagination("wireless", "get_rf_profiles", get_radio_frequency_profiles_params)

    def verify_create_update_radio_frequency_profiles_requirement(self, radio_frequency_profiles):
        """
        Determines whether radio frequency profiles need to be created, updated, or require no updates.
        Args:
            radio_frequency_profiles (list): A list of dictionaries containing the requested radio frequency profile parameters.
        Returns:
            tuple: Three lists containing radio frequency profiles to be created, updated, and not updated.
        """
        # Update requested profiles with API-compatible values
        updated_radio_frequency_profiles = self.map_radio_frequency_profiles_params(radio_frequency_profiles)
        self.log("Updated radio frequency profiles: {0}".format(updated_radio_frequency_profiles), "DEBUG")

        # Retrieve all existing radio frequency profiles from the system
        existing_rf_profiles = self.get_radio_frequency_profiles(get_radio_frequency_profiles_params={})

        # Log the existing and requested radio frequency profiles for debugging
        self.log("Existing Radio Frequency Profiles: {0}".format(existing_rf_profiles), "DEBUG")
        self.log("Requested Radio Frequency Profiles: {0}".format(updated_radio_frequency_profiles), "DEBUG")

        # Initialize lists to store profiles that need to be created, updated, or not changed
        create_profiles = []
        update_profiles = []
        no_update_profiles = []

        # Create a dictionary of existing profiles for quick lookup using the profile name
        existing_profiles_dict = {profile["rfProfileName"]: profile for profile in existing_rf_profiles}

        # Iterate over the updated requested radio frequency profiles
        self.log("Starting to iterate over updated requested radio frequency profiles.", "DEBUG")
        for requested_profile in updated_radio_frequency_profiles:
            profile_name = requested_profile["rfProfileName"]
            self.log("Processing profile: {0}".format(profile_name), "DEBUG")
            update_needed = False

            # Check if the profile already exists
            if profile_name in existing_profiles_dict:
                self.log("Profile '{0}' exists in the existing profiles.".format(profile_name), "DEBUG")
                existing_profile = existing_profiles_dict[profile_name]

                # Iterate over each top-level parameter in the requested profile
                for key, requested_value in requested_profile.items():
                    self.log("Checking parameter '{0}' for profile '{1}'.".format(key, profile_name), "DEBUG")
                    if key in existing_profile:
                        existing_value = existing_profile[key]
                        self.log("Found existing value for parameter '{0}' in profile '{1}': {2}".format(key, profile_name, existing_value), "DEBUG")

                        # Check if the value is a dictionary containing specific properties
                        if isinstance(requested_value, dict) and isinstance(existing_value, dict):
                            self.log("Parameter '{0}' is a dictionary. Checking all sub-keys.".format(key), "DEBUG")
                            for sub_key, sub_requested_value in requested_value.items():
                                if sub_key in existing_value:
                                    sub_existing_value = existing_value[sub_key]
                                    self.log("Checking sub-key '{0}' in parameter '{1}'.".format(sub_key, key), "DEBUG")

                                    # Special handling for comma-separated string of numbers
                                    if sub_key in ["radioChannels", "dataRates", "mandatoryDataRates"]:
                                        requested_sorted = sorted(map(float, sub_requested_value.split(",")))
                                        existing_sorted = sorted(map(float, sub_existing_value.split(",")))
                                        self.log("Sorted requested values for '{0}.{1}': {2}".format(key, sub_key, requested_sorted), "DEBUG")
                                        self.log("Sorted existing values for '{0}.{1}': {2}".format(key, sub_key, existing_sorted), "DEBUG")
                                        if requested_sorted != existing_sorted:
                                            update_needed = True
                                            self.log(
                                                "Mismatch found in parameter '{0}.{1}' for profile '{2}'. "
                                                "Requested value: {3}, Existing value: {4}".format(
                                                    key, sub_key, profile_name, requested_sorted, existing_sorted
                                                ),
                                                "DEBUG"
                                            )
                                            break
                                    else:
                                        # Standard comparison for other sub-keys
                                        if not self.compare_values(sub_requested_value, sub_existing_value):
                                            update_needed = True
                                            self.log(
                                                "Mismatch found in parameter '{0}.{1}' for profile '{2}'. "
                                                "Requested value: {3}, Existing value: {4}".format(
                                                    key, sub_key, profile_name, sub_requested_value, sub_existing_value
                                                ),
                                                "DEBUG"
                                            )
                                            break
                        else:
                            # Compare requested and existing values using compare_values
                            if not self.compare_values(requested_value, existing_value):
                                update_needed = True
                                self.log(
                                    "Mismatch found in parameter '{0}' for profile '{1}'. "
                                    "Requested value: {2}, Existing value: {3}".format(
                                        key, profile_name, requested_value, existing_value
                                    ),
                                    "DEBUG"
                                )
                                break

                if update_needed:
                    # Copy the existing profile and update it with the requested values
                    updated_profile = existing_profile.copy()
                    self.recursive_update(updated_profile, requested_profile)
                    update_profiles.append(updated_profile)
                    self.log("Profile '{0}' marked for update.".format(profile_name), "DEBUG")
                else:
                    # No changes needed for this profile
                    no_update_profiles.append(existing_profile)
                    self.log("Profile '{0}' requires no updates.".format(profile_name), "DEBUG")
            else:
                # The profile does not exist and needs to be created
                create_profiles.append(requested_profile)
                self.log("Profile '{0}' marked for creation.".format(profile_name), "DEBUG")

        # Log the results of the categorization
        self.log("Radio Frequency Profiles that need to be CREATED: {0} - {1}".format(len(create_profiles), create_profiles), "DEBUG")
        self.log("Radio Frequency Profiles that need to be UPDATED: {0} - {1}".format(len(update_profiles), update_profiles), "DEBUG")
        self.log("Radio Frequency Profiles that DON'T NEED UPDATES: {0} - {1}".format(len(no_update_profiles), no_update_profiles), "DEBUG")

        # Validate that the total number of processed profiles matches the number of requested profiles
        total_profiles_processed = len(create_profiles) + len(update_profiles) + len(no_update_profiles)
        if total_profiles_processed == len(updated_radio_frequency_profiles):
            self.log("Match in total counts: Processed={0}, Requested={1}.".format(total_profiles_processed, len(updated_radio_frequency_profiles)), "DEBUG")
        else:
            self.log("Mismatch in total counts: Processed={0}, Requested={1}.".format(total_profiles_processed, len(updated_radio_frequency_profiles)), "ERROR")

        # Return the categorized profiles
        return create_profiles, update_profiles, no_update_profiles

    def verify_delete_radio_frequency_profiles_requirement(self, access_point_profiles):
        """
        Determines which radio frequency profiles need to be deleted based on the requested parameters.
        Args:
            access_point_profiles (list): A list of dictionaries containing the requested radio frequency profile parameters for deletion.
        Returns:
            list: A list of radio frequency profiles that need to be deleted, including their IDs.
        """
        # Initialize an empty list to store the profiles that need to be deleted
        delete_rf_profiles_list = []

        # Log the start of the verification process for deletions
        self.log("Starting verification of radio frequency profiles for deletion.", "INFO")

        # Retrieve all existing radio frequency profiles
        existing_rf_profiles = self.get_radio_frequency_profiles(get_radio_frequency_profiles_params={})
        self.log("Retrieved existing radio frequency profiles.", "DEBUG")
        self.log("Existing Radio Frequency Profiles: {0}".format(existing_rf_profiles), "DEBUG")

        # Convert existing radio frequency profiles to a dictionary for quick lookup by profile name
        existing_profiles_dict = {profile["rfProfileName"]: profile for profile in existing_rf_profiles}
        self.log("Converted existing profiles to a dictionary for quick lookup.", "DEBUG")

        # Iterate over the requested radio frequency profiles
        self.log("Iterating over requested radio frequency profiles for deletion.", "DEBUG")
        for requested_profile in access_point_profiles:
            profile_name = requested_profile.get("radio_frequency_profile_name")
            self.log("Processing requested profile: {0}".format(profile_name), "DEBUG")

            # Check if the radio frequency profile exists in the existing radio frequency profiles
            if profile_name in existing_profiles_dict:
                self.log("Profile '{0}' found in existing profiles, scheduling for deletion.".format(profile_name), "DEBUG")
                # Add the requested radio frequency profile with the ID from the existing profile
                existing_profile = existing_profiles_dict[profile_name]
                profile_to_delete = requested_profile.copy()
                profile_to_delete["id"] = existing_profile.get("id")
                delete_rf_profiles_list.append(profile_to_delete)
                self.log("Radio Frequency Profile '{0}' scheduled for deletion.".format(profile_name), "INFO")
            else:
                # Log that deletion is not required for profiles that don't exist
                self.log("Deletion not required for radio frequency profile '{0}'. It does not exist.".format(profile_name), "INFO")

        # Log the list of profiles scheduled for deletion
        self.log("Radio Frequency Profiles scheduled for deletion: {0} - {1}".format(len(delete_rf_profiles_list), delete_rf_profiles_list), "DEBUG")

        # Log completion of the verification process
        self.log("Completed verification of radio frequency profiles for deletion.", "INFO")

        # Return the list of profiles that need to be deleted
        return delete_rf_profiles_list

    def create_radio_frequency_profile(self, create_radio_frequency_profile_params):
        """
        Initiates the creation of a new Radio Frequency profile using the provided parameters.
        Args:
            create_radio_frequency_profile_params (dict): A dictionary containing parameters required
                for creating a new Radio Frequency profile.
        Returns:
            dict: Response from the API call, including task ID for the create operation.
        """
        # Log the initiation of the create RF profile process
        self.log("Initiating addition of Radio Frequency profile with parameters: {0}".format(create_radio_frequency_profile_params), "INFO")

        # Call the API to create an RF profile and return the task ID
        return self.get_taskid_post_api_call("wireless", "create_rf_profile", create_radio_frequency_profile_params)

    def update_radio_frequency_profile(self, update_radio_frequency_profile_params):
        """
        Initiates the update of an existing Radio Frequency profile using the provided parameters.
        Args:
            update_radio_frequency_profile_params (dict): A dictionary containing parameters required
                for updating an existing Radio Frequency profile.
        Returns:
            dict: Response from the API call, including task ID for the update operation.
        """
        # Log the initiation of the update RF profile process
        self.log("Initiating update Radio Frequency profile with parameters: {0}".format(update_radio_frequency_profile_params), "INFO")

        # Call the API to update the RF profile and return the task ID
        return self.get_taskid_post_api_call("wireless", "update_rf_profile", update_radio_frequency_profile_params)

    def delete_radio_frequency_profile(self, delete_radio_frequency_profile_params):
        """
        Initiates the deletion of a Radio Frequency profile using the provided parameters.
        Args:
            delete_radio_frequency_profile_params (dict): A dictionary containing parameters required
                for deleting a Radio Frequency profile.
        Returns:
            dict: Response from the API call, including task ID for the delete operation.
        """
        # Log the initiation of the delete RF profile process
        self.log("Initiating deletion of Radio Frequency profile with parameters: {0}".format(delete_radio_frequency_profile_params), "INFO")

        # Call the API to delete the RF profile and return the task ID
        return self.get_taskid_post_api_call("wireless", "delete_rf_profile", delete_radio_frequency_profile_params)

    def map_radio_frequency_profiles_params(self, radio_frequency_profiles):
        """
        Maps radio frequency profile parameters from the input list of profiles to a new format.
        Args:
            radio_frequency_profiles (list): A list of dictionaries, where each dictionary contains
                radio frequency profile settings including radio bands and other configurations.
        Returns:
            list: A list of mapped radio frequency profiles with translated parameter names and structures.
        """
        # Initialize an empty list to store the mapped profiles
        mapped_profiles = []

        # Iterate over each radio frequency profile in the input list
        for profile in radio_frequency_profiles:
            # Extract radio bands from the current profile
            radio_bands = profile.get("radio_bands", [])

            # Create a new dictionary with mapped profile parameters
            mapped_profile = {
                "rfProfileName": profile.get("radio_frequency_profile_name"),
                "defaultRfProfile": profile.get("default_rf_profile"),
                "enableRadioTypeA": 5 in radio_bands,
                "enableRadioTypeB": 2.4 in radio_bands,
                "enableRadioType6GHz": 6 in radio_bands,
            }

            def map_band_settings(band_settings):
                """Maps individual band settings to their corresponding new format."""
                # If band settings are not provided, return None
                mapped = {}

                if not band_settings:
                    return mapped

                # Define the mapping from band settings keys to target keys
                band_mapping = {
                    "parent_profile": "parentProfile",
                    "dca_channels_list": "radioChannels",
                    "suppported_data_rates_list": "dataRates",
                    "mandatory_data_rates_list": "mandatoryDataRates",
                    "minimum_power_level": "minPowerLevel",
                    "maximum_power_level": "maxPowerLevel",
                    "rx_sop_threshold": "rxSopThreshold",
                    "custom_rx_sop_threshold": "customRxSopThreshold",
                    "tpc_power_threshold": "powerThresholdV1",
                    "client_limit": "maxRadioClients",
                    "channel_width": "channelWidth",
                    "minimum_dbs_channel_width": "minDbsWidth",
                    "maximum_dbs_channel_width": "maxDbsWidth",
                    "preamble_puncturing": "preamblePuncture",
                    "psc_enforcing_enabled": "pscEnforcingEnabled",
                    "zero_wait_dfs": "zeroWaitDfsEnable",
                    "discovery_frames_6ghz": "discoveryFrames6GHz",
                    "standard_power_service": "enableStandardPowerService",
                    "broadcast_probe_response_interval": "broadcastProbeResponseInterval",
                }

                # Initialize the mapped dictionary
                self.log("Initializing the mapped dictionary.", "DEBUG")

                # Iterate over each band setting and map them if present
                self.log("Starting to map band settings.", "DEBUG")
                for key, target_key in band_mapping.items():
                    if key in band_settings:
                        # Special handling for lists that need to be joined into strings
                        if key in ["dca_channels_list", "suppported_data_rates_list", "mandatory_data_rates_list"]:
                            mapped[target_key] = ",".join(map(str, band_settings[key]))
                            self.log("Joined list for '{0}' and mapped to '{1}' with value: {2}.".format(key, target_key, mapped[target_key]), "DEBUG")
                        else:
                            mapped[target_key] = band_settings[key]
                            self.log("Mapped '{0}' to '{1}' with value: {2}.".format(key, target_key, mapped[target_key]), "DEBUG")
                    else:
                        self.log("Key '{0}' not found in band_settings.".format(key), "WARNING")

                # Define mappings for nested structures
                self.log("Defining mappings for nested structures.", "DEBUG")

                spatial_reuse_mapping = {
                    "non_srg_obss_pd": "dot11axNonSrgObssPacketDetect",
                    "non_srg_obss_pd_max_threshold": "dot11axNonSrgObssPacketDetectMaxThreshold",
                    "srg_obss_pd": "dot11axSrgObssPacketDetect",
                    "srg_obss_pd_min_threshold": "dot11axSrgObssPacketDetectMinThreshold",
                    "srg_obss_pd_max_threshold": "dot11axSrgObssPacketDetectMaxThreshold"
                }
                self.log("Spatial reuse mapping defined.", "DEBUG")

                coverage_hole_detection_mapping = {
                    "minimum_client_level": "chdClientLevel",
                    "data_rssi_threshold": "chdDataRssiThreshold",
                    "voice_rssi_threshold": "chdVoiceRssiThreshold",
                    "exception_level": "chdExceptionLevel"
                }
                self.log("Coverage hole detection mapping defined.", "DEBUG")

                dot_11ax_parameters_mapping = {
                    "mu_mimo_downlink": "muMimoDownLink",
                    "mu_mimo_uplink": "muMimoUpLink",
                    "ofdma_downlink": "ofdmaDownLink",
                    "ofdma_uplink": "ofdmaUpLink"
                }
                self.log("Dot 11ax parameters mapping defined.", "DEBUG")

                dot_11be_parameters_mapping = {
                    "mu_mimo_downlink": "muMimoDownLink",
                    "mu_mimo_uplink": "muMimoUpLink",
                    "ofdma_downlink": "ofdmaDownLink",
                    "ofdma_uplink": "ofdmaUpLink",
                    "ofdma_multi_ru": "ofdmaMultiRu"
                }
                self.log("Dot 11be parameters mapping defined.", "DEBUG")

                # Process spatial reuse settings
                if "spatial_resuse" in band_settings:
                    self.log("Processing spatial reuse settings.", "DEBUG")
                    mapped["spatialReuseProperties"] = {}
                    for key, target_key in spatial_reuse_mapping.items():
                        if key in band_settings["spatial_resuse"]:
                            mapped["spatialReuseProperties"][target_key] = band_settings["spatial_resuse"][key]
                            self.log("Mapped spatial reuse '{0}' to '{1}' with value: {2}.".format(
                                key, target_key, mapped["spatialReuseProperties"][target_key]), "DEBUG")

                # Process coverage hole detection settings
                if "coverage_hole_detection" in band_settings:
                    self.log("Processing coverage hole detection settings.", "DEBUG")
                    mapped["coverageHoleDetectionProperties"] = {}
                    for key, target_key in coverage_hole_detection_mapping.items():
                        if key in band_settings["coverage_hole_detection"]:
                            mapped["coverageHoleDetectionProperties"][target_key] = band_settings["coverage_hole_detection"][key]
                            self.log("Mapped coverage hole detection '{0}' to '{1}' with value: {2}.".format(
                                key, target_key, mapped["coverageHoleDetectionProperties"][target_key]), "DEBUG")

                # Process multi-bssid settings
                if "multi_bssid" in band_settings:
                    self.log("Processing multi-bssid settings.", "DEBUG")
                    mapped["multiBssidProperties"] = {}

                    if "dot_11ax_parameters" in band_settings["multi_bssid"]:
                        self.log("Processing dot 11ax parameters.", "DEBUG")
                        mapped["multiBssidProperties"]["dot11axParameters"] = {}
                        for key, target_key in dot_11ax_parameters_mapping.items():
                            if key in band_settings["multi_bssid"]["dot_11ax_parameters"]:
                                mapped["multiBssidProperties"]["dot11axParameters"][target_key] = band_settings["multi_bssid"]["dot_11ax_parameters"][key]
                                self.log("Mapped dot_11ax '{0}' to '{1}' with value: {2}.".format(
                                    key, target_key, mapped["multiBssidProperties"]["dot11axParameters"][target_key]), "DEBUG")

                    if "dot_11be_parameters" in band_settings["multi_bssid"]:
                        self.log("Processing dot 11be parameters.", "DEBUG")
                        mapped["multiBssidProperties"]["dot11beParameters"] = {}
                        for key, target_key in dot_11be_parameters_mapping.items():
                            if key in band_settings["multi_bssid"]["dot_11be_parameters"]:
                                mapped["multiBssidProperties"]["dot11beParameters"][target_key] = band_settings["multi_bssid"]["dot_11be_parameters"][key]
                                self.log("Mapped dot_11be '{0}' to '{1}' with value: {2}.".format(
                                    key, target_key, mapped["multiBssidProperties"]["dot11beParameters"][target_key]), "DEBUG")

                    # Additional mappings directly under multi_bssid
                    self.log("Processing additional multi-bssid settings.", "DEBUG")
                    additional_keys = ["twt_broadcast_support", "target_waketime"]
                    for key in additional_keys:
                        if key in band_settings["multi_bssid"]:
                            target_key = key.replace("twt_broadcast_support", "twtBroadcastSupport").replace("target_waketime", "targetWakeTime")
                            mapped["multiBssidProperties"][target_key] = band_settings["multi_bssid"][key]
                            self.log("Mapped multi_bssid '{0}' to '{1}' with value: {2}.".format(
                                key, target_key, mapped["multiBssidProperties"][target_key]), "DEBUG")

                self.log("Completed mapping of band settings.", "DEBUG")
                return mapped

            # Check and map flexible radio assignment settings for 6GHz band
            if "flexible_radio_assigment" in profile.get("radio_bands_6ghz_settings", {}):
                mapped_profile["fraPropertiesC"] = profile["radio_bands_6ghz_settings"]["flexible_radio_assigment"]

            # Check and map flexible radio assignment settings for 5GHz band
            if "flexible_radio_assigment" in profile.get("radio_bands_5ghz_settings", {}):
                mapped_profile["fraPropertiesA"] = profile["radio_bands_5ghz_settings"]["flexible_radio_assigment"]

            # Map settings for 5GHz band if present
            if profile.get("radio_bands_5ghz_settings"):
                mapped_profile["radioTypeAProperties"] = map_band_settings(profile.get("radio_bands_5ghz_settings"))

            # Map settings for 2.4GHz band if present
            if profile.get("radio_bands_2_4ghz_settings"):
                mapped_profile["radioTypeBProperties"] = map_band_settings(profile.get("radio_bands_2_4ghz_settings"))

            # Map settings for 6GHz band if present
            if profile.get("radio_bands_6ghz_settings"):
                mapped_profile["radioType6GHzProperties"] = map_band_settings(profile.get("radio_bands_6ghz_settings"))

            # Append the mapped profile to the list of mapped profiles
            mapped_profiles.append(mapped_profile)

        # Return the final list of mapped profiles
        return mapped_profiles

    def process_radio_frequency_profiles_common(self, radio_frequency_profiles_params, create_or_update_or_delete_radio_frequency_profiles, task_name):
        """
        Processes the radio frequency profiles for the specified operation (create, update, delete).
        Args:
            radio_frequency_profiles_params (list): A list of dictionaries containing parameters for each radio frequency profile operation.
            create_or_update_or_delete_radio_frequency_profiles (function): The function to execute for each radio frequency profile operation.
            task_name (str): The name of the task being performed, e.g., "Create Radio Frequency Profile(s) Task".
        Returns:
            self: The current instance to allow for method chaining or further processing.
        """
        # Initialize lists to track successful and failed profile operations
        failed_profiles = []
        success_profiles = []
        msg = {}

        # Iterate over each profile parameter set for processing
        for index, profile in enumerate(radio_frequency_profiles_params, start=1):
            # Determine the profile name based on the operation type
            profile_name = profile.get("radio_frequency_profile_name") if (
                create_or_update_or_delete_radio_frequency_profiles == self.delete_radio_frequency_profile
            ) else profile.get("rfProfileName")
            self.log("Processing radio frequency profile {0}: {1}".format(index, profile_name), "DEBUG")

            # Prepare parameters for the operation
            if create_or_update_or_delete_radio_frequency_profiles == self.delete_radio_frequency_profile:
                # For delete operations, only the ID is needed
                operation_params = {"id": profile.get("id")}
            else:
                # For create or update operations, use the entire profile
                operation_params = profile

            # Execute the operation and retrieve the task ID
            task_id = create_or_update_or_delete_radio_frequency_profiles(operation_params)
            self.log("Task ID for radio frequency profile '{0}': {1}".format(profile_name, task_id), "DEBUG")

            # Construct operation message
            operation_msg = "{0} operation has completed successfully for radio frequency profile: {1}.".format(task_name, profile_name)

            # Check the status of the operation using the task ID
            self.get_task_status_from_tasks_by_id(task_id, task_name, operation_msg).check_return_status()

            # Determine if the operation was successful and categorize accordingly
            if self.status == "success":
                success_profiles.append(profile_name)
                self.log("Radio Frequency Profile '{0}' processed successfully.".format(profile_name), "INFO")
            else:
                failed_profiles.append(profile_name)
                self.log("Radio Frequency Profile '{0}' failed to process.".format(profile_name), "ERROR")

        # Log and prepare final messages for successful operations
        if success_profiles:
            self.log("{0} succeeded for the following radio frequency profile(s): {1}".format(task_name, ", ".join(success_profiles)), "INFO")
            msg["{0} succeeded for the following radio frequency profile(s)".format(task_name)] = {
                "success_count": len(success_profiles),
                "successful_radio_frequency_profiles": success_profiles
            }

        # Log and prepare final messages for failed operations
        if failed_profiles:
            self.log("{0} failed for the following radio frequency profile(s): {1}".format(task_name, ", ".join(failed_profiles)), "ERROR")
            msg["{0} failed for the following radio frequency profile(s)".format(task_name)] = {
                "failed_count": len(failed_profiles),
                "failed_radio_frequency_profiles": failed_profiles
            }

        # Store the message dictionary in the class
        self.msg = msg

        # Determine the final operation result based on success and failure lists
        if success_profiles and failed_profiles:
            self.set_operation_result("failed", True, self.msg, "ERROR")
        elif success_profiles:
            self.set_operation_result("success", True, self.msg, "INFO")
        elif failed_profiles:
            self.set_operation_result("failed", True, self.msg, "ERROR")
        else:
            self.set_operation_result("ok", False, self.msg, "INFO")

        # Return the instance for method chaining or further processing
        return self

    def process_add_radio_frequency_profiles(self, add_radio_frequency_profiles_params):
        """
        Initiates the creation of radio frequency profiles.
        Args:
            add_radio_frequency_profiles_params (list): A list of dictionaries containing the parameters for the radio frequency profiles to be added.
        Returns:
            tuple: A tuple containing the results of the add operation, typically indicating success or failure for each profile.
        """
        # Define the task name for creating radio frequency profiles
        task_name_create = "Create Radio Frequency Profile(s) Task"
        self.log("Starting '{0}' with parameters: {1}".format(task_name_create, add_radio_frequency_profiles_params), "INFO")

        # Call the common processing function with the appropriate creation function and task name
        result = self.process_radio_frequency_profiles_common(
            add_radio_frequency_profiles_params,
            self.create_radio_frequency_profile,
            task_name_create
        )

        # Log the completion of the task
        self.log("Completed '{0}'.".format(task_name_create), "INFO")
        return result

    def process_update_radio_frequency_profiles(self, update_radio_frequency_profiles_params):
        """
        Initiates the update of radio frequency profiles.
        Args:
            update_radio_frequency_profiles_params (list): A list of dictionaries containing the parameters for the radio frequency profiles to be updated.
        Returns:
            tuple: A tuple containing the results of the update operation, typically indicating success or failure for each profile.
        """
        # Define the task name for updating radio frequency profiles
        task_name_update = "Update Radio Frequency Profile(s) Task"
        self.log("Starting '{0}' with parameters: {1}".format(task_name_update, update_radio_frequency_profiles_params), "INFO")

        # Call the common processing function with the appropriate update function and task name
        result = self.process_radio_frequency_profiles_common(
            update_radio_frequency_profiles_params,
            self.update_radio_frequency_profile,
            task_name_update
        )

        # Log the completion of the task
        self.log("Completed '{0}'.".format(task_name_update), "INFO")
        return result

    def process_delete_radio_frequency_profiles(self, delete_radio_frequency_profiles_params):
        """
        Initiates the deletion of radio frequency profiles.
        Args:
            delete_radio_frequency_profiles_params (list): A list of dictionaries containing the parameters for the radio frequency profiles to be deleted.
        Returns:
            tuple: A tuple containing the results of the delete operation, typically indicating success or failure for each profile.
        """
        # Define the task name for deleting radio frequency profiles
        task_name_delete = "Delete Radio Frequency Profile(s) Task"
        self.log("Starting '{0}' with parameters: {1}".format(task_name_delete, delete_radio_frequency_profiles_params), "INFO")

        # Call the common processing function with the appropriate deletion function and task name
        result = self.process_radio_frequency_profiles_common(
            delete_radio_frequency_profiles_params,
            self.delete_radio_frequency_profile,
            task_name_delete
        )

        # Log the completion of the task
        self.log("Completed '{0}'.".format(task_name_delete), "INFO")
        return result

    def verify_add_radio_frequency_profiles_operation(self, add_radio_frequency_profiles_params):
        """
        Verifies whether the radio frequency profiles specified in add_radio_frequency_profiles_params have been successfully created.
        Args:
            add_radio_frequency_profiles_params (list): A list of dictionaries containing the requested radio frequency profile parameters to be added.
        Returns:
            tuple: Two lists containing successfully created radio frequency profiles and failed profiles.
        """
        # Log the initiation of the creation verification process
        self.log("Starting verification of radio frequency profile creation.", "INFO")

        # Retrieve all existing radio frequency profiles to verify against
        existing_radio_frequency_profiles = self.get_radio_frequency_profiles(get_radio_frequency_profiles_params={})
        self.log("Existing Radio Frequency Profiles: {0}".format(existing_radio_frequency_profiles), "DEBUG")
        self.log("Requested Radio Frequency Profiles to Add: {0}".format(add_radio_frequency_profiles_params), "DEBUG")

        # Initialize lists to track successful and failed profile additions
        successful_profiles = []
        failed_profiles = []

        # Convert existing radio frequency profiles to a set for quick lookup by profile name
        existing_profiles_set = {profile['rfProfileName'] for profile in existing_radio_frequency_profiles}
        self.log("Converted existing profiles to a set for quick lookup.", "DEBUG")

        # Iterate over the requested radio frequency profiles to verify their creation
        for index, requested_profile in enumerate(add_radio_frequency_profiles_params, start=1):
            profile_name = requested_profile['rfProfileName']
            self.log("Iteration {0}: Verifying creation for Radio Frequency Profile '{1}'.".format(index, profile_name), "DEBUG")

            # Check if the profile now exists in the existing profiles
            if profile_name in existing_profiles_set:
                # Profile exists, add to successful list
                successful_profiles.append(profile_name)
                self.log("Iteration {0}: Radio Frequency Profile '{1}' has been successfully created.".format(index, profile_name), "INFO")
            else:
                # Profile does not exist, add to failed list
                failed_profiles.append(profile_name)
                self.log("Iteration {0}: Radio Frequency Profile '{1}' failed to create.".format(index, profile_name), "ERROR")

        # Log the summary of the creation verification
        if failed_profiles:
            self.log("The ADD Radio Frequency Profile(s) operation may not have been successful since some profiles were not successfully created: {0}"
                     .format(failed_profiles), "WARNING")
        else:
            self.log("Successfully verified the ADD Radio Frequency Profile(s) operation for parameters: {0}"
                     .format(add_radio_frequency_profiles_params), "INFO")

    def verify_update_radio_frequency_profiles_operation(self, update_radio_frequency_profiles_params):
        """
        Verifies whether the radio frequency profiles specified in update_radio_frequency_profiles_params have been successfully updated.
        Args:
            update_radio_frequency_profiles_params (list): A list of dictionaries containing the requested radio frequency profile parameters to be updated.
        Returns:
            tuple: Two lists containing successfully updated radio frequency profiles and failed profiles.
        """
        # Log the initiation of the update verification process
        self.log("Starting verification of radio frequency profile updates.", "INFO")

        # Retrieve all existing radio frequency profiles from the system
        existing_radio_frequency_profiles = self.get_radio_frequency_profiles(get_radio_frequency_profiles_params={})
        self.log("Existing Radio Frequency Profiles: {0}".format(existing_radio_frequency_profiles), "DEBUG")
        self.log("Requested Radio Frequency Profiles to Update: {0}".format(update_radio_frequency_profiles_params), "DEBUG")

        # Initialize lists to track successful and failed profile updates
        successful_updates = []
        failed_updates = []

        # Convert existing profiles to a dictionary for quick lookup by profile name
        existing_profiles_dict = {profile['rfProfileName']: profile for profile in existing_radio_frequency_profiles}
        self.log("Converted existing profiles to a dictionary for quick lookup.", "DEBUG")

        # Iterate over the requested radio frequency profiles to verify updates
        for index, requested_profile in enumerate(update_radio_frequency_profiles_params, start=1):
            profile_name = requested_profile['rfProfileName']
            self.log("Iteration {0}: Verifying update for Radio Frequency Profile '{1}'.".format(index, profile_name), "DEBUG")

            # Check if the profile exists in the existing profiles
            if profile_name in existing_profiles_dict:
                existing_profile = existing_profiles_dict[profile_name]

                # Flag to determine if the update was successful
                update_successful = True

                # Iterate over each requested parameter to verify if the update was applied
                for key, requested_value in requested_profile.items():
                    if key in existing_profile:
                        existing_value = existing_profile[key]

                        # Compare the requested and existing values
                        if not self.compare_values(requested_value, existing_value):
                            update_successful = False
                            self.log("Mismatch in parameter '{0}' for profile '{1}'. Requested value: {2}, Existing value: {3}".format(
                                key, profile_name, requested_value, existing_value), "ERROR")
                            break

                if update_successful:
                    successful_updates.append(profile_name)
                    self.log("Iteration {0}: Radio Frequency Profile '{1}' has been successfully updated.".format(index, profile_name), "INFO")
                else:
                    failed_updates.append(profile_name)
                    self.log("Iteration {0}: Radio Frequency Profile '{1}' failed to update.".format(index, profile_name), "ERROR")
            else:
                failed_updates.append(profile_name)
                self.log("Iteration {0}: Radio Frequency Profile '{1}' does not exist and cannot be updated.".format(index, profile_name), "ERROR")

        # Log the summary of the operation
        if failed_updates:
            self.log(
                "The UPDATE Radio Frequency Profiles operation may not have been successful. "
                "The following radio frequency profiles failed verification: {0}.".format(failed_updates),
                "ERROR"
            )
        else:
            self.log("Successfully verified the UPDATE Radio Frequency Profiles operation for the following profiles: {0}.".format(successful_updates), "INFO")

    def verify_delete_radio_frequency_profiles_operation(self, delete_radio_frequency_profiles_params):
        """
        Verifies whether the radio frequency profiles specified in delete_radio_frequency_profiles_params have been successfully deleted.
        Args:
            delete_radio_frequency_profiles_params (list): A list of dictionaries containing the requested radio frequency profile names to be deleted.
        Returns:
            bool: True if all requested radio frequency profiles were successfully deleted, False otherwise.
        """
        # Log the initiation of the verification process
        self.log("Starting verification of radio frequency profiles for deletion.", "INFO")

        # Retrieve all existing radio frequency profiles from the system
        existing_radio_frequency_profiles = self.get_radio_frequency_profiles(get_radio_frequency_profiles_params={})
        # Create a set of existing profile names for quick lookup
        existing_profiles_set = {profile['rfProfileName'] for profile in existing_radio_frequency_profiles}
        self.log("Current Radio Frequency Profiles after DELETE operation: {0}".format(existing_profiles_set), "DEBUG")

        # Log the requested profiles for deletion
        self.log("Requested Radio Frequency Profiles to Delete: {0}".format(delete_radio_frequency_profiles_params), "DEBUG")

        # Initialize a list to track profiles that failed deletion
        failed_deletions = []

        # Iterate over the requested radio frequency profiles to verify their deletion
        for index, requested_profile in enumerate(delete_radio_frequency_profiles_params, start=1):
            profile_name = requested_profile['radio_frequency_profile_name']
            self.log("Iteration {0}: Verifying deletion for Radio Frequency Profile '{1}'.".format(index, profile_name), "DEBUG")

            # Check if the profile still exists in the existing profiles
            if profile_name in existing_profiles_set:
                # If it exists, the deletion failed
                failed_deletions.append(profile_name)
                self.log("Iteration {0}: Delete operation failed for Radio Frequency Profile '{1}'. It still exists.".format(index, profile_name), "ERROR")

        # Log the summary of the deletion verification operation
        if failed_deletions:
            self.log("The DELETE Radio Frequency Profile(s) operation may not have been successful since some Radio Frequency Profiles still exist: {0}."
                     .format(failed_deletions), "ERROR")
        else:
            self.log("Verified the success of DELETE Radio Frequency Profile(s) operation for the following parameters: {0}."
                     .format(delete_radio_frequency_profiles_params), "INFO")

    def get_anchor_groups(self, get_anchor_groups_params):
        """
        Retrieves the anchor groups using the specified parameters and handles the API response.
        Args:
            get_anchor_groups_params (dict): Optional parameters for the GET request.
        Returns:
            list: A list of anchor group dictionaries if the request is successful.
        """
        # Log the initiation of the GET request for anchor groups
        self.log("Initiating GET request for anchor groups with parameters: {0}".format(get_anchor_groups_params), "INFO")

        # Execute the GET request to retrieve anchor groups
        api_response = self.execute_get_request("wireless", "get_anchor_groups", get_anchor_groups_params)
        self.log("API response received: {0}".format(api_response), "DEBUG")

        # Extract the 'response' part of the API response
        if not api_response or not api_response.get("response"):
            # Log an error if the API response is empty and return an empty list
            self.log("No response received from API call 'get_anchor_groups'. Returning an empty list.", "ERROR")
            return []

        # Attempt to extract anchor groups from the response
        anchor_groups = api_response.get("response")
        self.log("Anchor groups extracted from response: {0}".format(anchor_groups), "DEBUG")

        # Return the list of anchor groups if successfully retrieved
        self.log("Successfully retrieved anchor groups: {0}".format(anchor_groups), "INFO")
        return anchor_groups

    def verify_create_update_anchor_groups_requirement(self, anchor_groups):
        """
        Determines whether anchor groups need to be created, updated, or require no updates.
        Args:
            anchor_groups (list): A list of dictionaries containing the requested anchor group parameters.
        Returns:
            tuple: Three lists containing anchor groups to be created, updated, and not updated.
        """
        # Log the start of the verification process for creating or updating anchor groups
        self.log("Starting verification for creating/updating anchor groups with requested parameters: {0}".format(anchor_groups), "INFO")

        # Map the parameters to the API-supported format
        updated_anchor_groups = self.map_anchor_groups_params(anchor_groups)
        self.log("Mapped Requested Anchor Groups: {0}".format(updated_anchor_groups), "DEBUG")

        # Retrieve all existing anchor groups
        existing_anchor_groups = self.get_anchor_groups(get_anchor_groups_params={})
        self.log("Existing Anchor Groups: {0}".format(existing_anchor_groups), "DEBUG")

        # Initialize lists to track anchor groups for creation, update, and no update needed
        create_groups = []
        update_groups = []
        no_update_groups = []

        # Convert existing anchor groups to a dictionary for quick lookup by group name
        existing_groups_dict = {group['anchorGroupName']: group for group in existing_anchor_groups}
        self.log("Converted existing anchor groups to a dictionary for quick lookup.", "DEBUG")

        # Iterate over the mapped requested anchor groups
        for index, requested_group in enumerate(updated_anchor_groups, start=1):
            group_name = requested_group['anchorGroupName']
            requested_mobility_anchors = requested_group.get('mobilityAnchors', [])
            self.log("Iteration {0}: Evaluating anchor group '{1}'.".format(index, group_name), "DEBUG")

            # Check if the group exists in the existing groups
            if group_name in existing_groups_dict:
                existing_group = existing_groups_dict[group_name]
                existing_mobility_anchors = existing_group.get('mobilityAnchors', [])
                self.log("Iteration {0}: Anchor Group '{1}' exists. Checking for updates.".format(index, group_name), "DEBUG")

                # Function to normalize and sort anchors for comparison
                def normalize_anchors(anchors):
                    return sorted([
                        (
                            anchor.get('deviceName'),
                            anchor.get('ipAddress'),
                            anchor.get('macAddress'),
                            anchor.get('peerDeviceType'),
                            anchor.get('anchorPriority'),
                            anchor.get('privateIp'),
                            anchor.get('mobilityGroupName'),
                            anchor.get('managedAnchorWlc'),
                        )
                        for anchor in anchors
                    ])

                # Determine if an update is needed by comparing mobility anchors
                update_needed = normalize_anchors(requested_mobility_anchors) != normalize_anchors(existing_mobility_anchors)

                if update_needed:
                    # Add the requested group with the ID from the existing group for update
                    updated_group = requested_group.copy()
                    updated_group["id"] = existing_group.get("id")
                    update_groups.append(updated_group)
                    self.log("Iteration {0}: Anchor Group '{1}' scheduled for update.".format(index, group_name), "INFO")
                else:
                    # If there's no difference, add to no_update_groups
                    no_update_groups.append(existing_group)
                    self.log("Iteration {0}: Anchor Group '{1}' requires no update.".format(index, group_name), "INFO")
            else:
                # If the group does not exist, mark it for creation
                create_groups.append(requested_group)
                self.log("Iteration {0}: Anchor Group '{1}' scheduled for creation.".format(index, group_name), "INFO")

        # Log details of anchor groups to be created, updated, and not updated
        self.log("Anchor Groups that need to be CREATED: {0} - {1}".format(len(create_groups), create_groups), "DEBUG")
        self.log("Anchor Groups that need to be UPDATED: {0} - {1}".format(len(update_groups), update_groups), "DEBUG")
        self.log("Anchor Groups that DON'T NEED UPDATES: {0} - {1}".format(len(no_update_groups), no_update_groups), "DEBUG")

        # Calculate total groups processed and check against requested groups
        total_groups_processed = len(create_groups) + len(update_groups) + len(no_update_groups)
        if total_groups_processed == len(updated_anchor_groups):
            self.log("Match in total counts: Processed={0}, Requested={1}.".format(total_groups_processed, len(updated_anchor_groups)), "DEBUG")
        else:
            self.log("Mismatch in total counts: Processed={0}, Requested={1}.".format(total_groups_processed, len(updated_anchor_groups)), "ERROR")

        # Return the categorized groups
        return create_groups, update_groups, no_update_groups

    def verify_delete_anchor_groups_requirement(self, anchor_groups):
        """
        Determines whether anchor groups need to be deleted based on the requested parameters.
        Args:
            anchor_groups (list): A list of dictionaries containing the requested anchor group parameters for deletion.
        Returns:
            list: A list of anchor groups that need to be deleted, including their IDs.
        """
        # Initialize a list to track anchor groups that need deletion
        delete_anchor_groups_list = []

        # Log the start of the verification process for deletions
        self.log("Starting verification of anchor groups for deletion.", "INFO")

        # Retrieve all existing anchor groups
        existing_anchor_groups = self.get_anchor_groups(get_anchor_groups_params={})
        self.log("Existing Anchor Groups: {0}".format(existing_anchor_groups), "DEBUG")

        # Convert existing anchor groups to a dictionary for quick lookup by group name
        existing_groups_dict = {group['anchorGroupName']: group for group in existing_anchor_groups}
        self.log("Converted existing anchor groups to a dictionary for quick lookup.", "DEBUG")

        # Iterate over the requested anchor groups
        for index, requested_group in enumerate(anchor_groups, start=1):
            group_name = requested_group.get('anchor_group_name')
            self.log("Iteration {0}: Checking anchor group '{1}' for deletion requirement.".format(index, group_name), "DEBUG")

            # Check if the anchor group exists in the existing anchor groups
            if group_name in existing_groups_dict:
                # Add the requested anchor group with the ID from the existing group to the deletion list
                existing_group = existing_groups_dict[group_name]
                group_to_delete = requested_group.copy()
                group_to_delete["id"] = existing_group.get("id")
                delete_anchor_groups_list.append(group_to_delete)
                self.log("Iteration {0}: Anchor Group '{1}' scheduled for deletion.".format(index, group_name), "INFO")
            else:
                # Log that deletion is not required for groups that don't exist
                self.log("Iteration {0}: Deletion not required for anchor group '{1}'. It does not exist.".format(index, group_name), "INFO")

        # Log the list of groups scheduled for deletion
        self.log("Anchor Groups scheduled for deletion: {0} - {1}".format(len(delete_anchor_groups_list), delete_anchor_groups_list), "DEBUG")

        # Return the list of groups that need to be deleted
        return delete_anchor_groups_list

    def create_anchor_group(self, create_anchor_group_params):
        """
        Initiates the creation of an anchor group.
        Args:
            create_anchor_group_params (dict): Parameters required for creating the anchor group.
        Returns:
            dict: The response from the API call containing the task ID for the operation.
        """
        # Log the initiation of the anchor group creation process with the provided parameters
        self.log("Initiating addition of Anchor group with parameters: {0}".format(create_anchor_group_params), "INFO")

        # Perform the API call to create the anchor group and return the task ID
        return self.get_taskid_post_api_call("wireless", "create_anchor_group", create_anchor_group_params)

    def update_anchor_group(self, update_anchor_group_params):
        """
        Initiates the update of an anchor group.
        Args:
            update_anchor_group_params (dict): Parameters required for updating the anchor group.
        Returns:
            dict: The response from the API call containing the task ID for the operation.
        """
        # Log the initiation of the anchor group update process with the provided parameters
        self.log("Initiating update Anchor group with parameters: {0}".format(update_anchor_group_params), "INFO")

        # Perform the API call to update the anchor group and return the task ID
        return self.get_taskid_post_api_call("wireless", "update_anchor_group", update_anchor_group_params)

    def delete_anchor_group(self, delete_anchor_group_params):
        """
        Initiates the deletion of an anchor group.
        Args:
            delete_anchor_group_params (dict): Parameters required for deleting the anchor group.
        Returns:
            dict: The response from the API call containing the task ID for the operation.
        """
        # Log the initiation of the anchor group deletion process with the provided parameters
        self.log("Initiating deletion of Anchor group with parameters: {0}".format(delete_anchor_group_params), "INFO")

        # Perform the API call to delete the anchor group and return the task ID
        return self.get_taskid_post_api_call("wireless", "delete_anchor_group_by_id", delete_anchor_group_params)

    def map_anchor_groups_params(self, anchor_groups):
        """
        Maps the provided anchor group parameters to the parameters required for API calls.
        Args:
            anchor_groups (list): A list of dictionaries containing anchor group parameters.
        Returns:
            list: A list of dictionaries with mapped parameters suitable for API calls.
        """
        self.log("Starting 'map_anchor_groups_params' with anchor groups: {0}".format(anchor_groups), "INFO")
        mapped_anchor_groups = []

        # Check if the anchor_groups list is empty
        if not anchor_groups:
            self.log("No anchor groups provided for mapping. Returning an empty list.", "DEBUG")
            return mapped_anchor_groups

        # Define priority mapping from integer to string representation
        priority_mapping = {
            1: "PRIMARY",
            2: "SECONDARY",
            3: "TERTIARY"
        }
        self.log("Priority mapping defined: {0}".format(priority_mapping), "DEBUG")

        # Iterate over each anchor group to map its parameters
        for index, group in enumerate(anchor_groups, start=1):
            self.log("Mapping parameters for anchor group {0}: {1}".format(index, group), "DEBUG")
            mapped_group = {}

            # Map top-level parameters for the anchor group
            if "anchor_group_name" in group:
                mapped_group["anchorGroupName"] = group["anchor_group_name"]
                self.log("Mapped 'anchor_group_name' to 'anchorGroupName' with value '{0}'.".format(group["anchor_group_name"]), "DEBUG")

            # Initialize the list for mobility anchors in the mapped group
            if "mobility_anchors" in group:
                mapped_group["mobilityAnchors"] = []
                self.log("Initialized 'mobilityAnchors' for mapped group.", "DEBUG")

                # Iterate over each mobility anchor to map its parameters
                for anchor_index, anchor in enumerate(group["mobility_anchors"], start=1):
                    self.log("Mapping mobility anchor {0}: {1}".format(anchor_index, anchor), "DEBUG")
                    mapped_anchor = {}

                    # Define the mapping of anchor parameters to API parameters
                    mappings = {
                        "device_name": "deviceName",
                        "device_ip_address": "ipAddress",
                        "device_mac_address": "macAddress",
                        "device_type": "peerDeviceType",
                        "device_nat_ip_address": "privateIp",
                        "mobility_group_name": "mobilityGroupName",
                        "managed_device": "managedAnchorWlc"
                    }

                    # Apply mappings for each parameter in the anchor
                    for param, api_param in mappings.items():
                        if param in anchor:
                            mapped_anchor[api_param] = anchor[param]
                            self.log("Mapped '{0}' to '{1}' with value '{2}'.".format(param, api_param, anchor[param]), "DEBUG")

                    # Map device_priority to anchorPriority using the defined priority mapping
                    if "device_priority" in anchor:
                        device_priority = anchor["device_priority"]
                        anchor_priority = priority_mapping.get(device_priority, None)
                        if anchor_priority:
                            mapped_anchor["anchorPriority"] = anchor_priority
                            self.log("Mapped 'device_priority' {0} to 'anchorPriority' '{1}'.".format(device_priority, anchor_priority), "DEBUG")

                    # Add the mapped anchor to the mobility anchors list
                    mapped_group["mobilityAnchors"].append(mapped_anchor)

            # Append the fully mapped group to the list of mapped anchor groups
            mapped_anchor_groups.append(mapped_group)
            self.log("Mapped anchor group {0} completed: {1}".format(index, mapped_group), "DEBUG")

        self.log("Finished mapping anchor groups. Result: {0}".format(mapped_anchor_groups), "DEBUG")
        return mapped_anchor_groups

    def process_anchor_groups_common(self, anchor_groups_params, create_or_update_or_delete_anchor_groups, task_name):
        """
        Processes the anchor groups for the specified operation (create, update, delete).

        Args:
            anchor_groups_params (list): A list of dictionaries containing parameters for each anchor group operation.
            create_or_update_or_delete_anchor_groups (function): The function to execute for each anchor group operation.
            task_name (str): The name of the task being performed, e.g., "Create Anchor Group(s) Task".
        """
        # Initialize lists to track successful and failed group operations
        failed_groups = []
        success_groups = []
        msg = {}

        # Iterate over each group parameter set for processing
        for group in anchor_groups_params:
            if create_or_update_or_delete_anchor_groups == self.delete_anchor_group:
                group_name = group.get("anchor_group_name")
            else:
                group_name = group.get("anchorGroupName")
            self.log("Processing anchor group: {0}".format(group_name), "DEBUG")

            # Prepare parameters for the operation
            if create_or_update_or_delete_anchor_groups == self.delete_anchor_group:
                # For delete operations, only the ID is needed
                operation_params = {"id": group.get("id")}
            else:
                # For create or update operations, use the entire group
                operation_params = group

            # Execute the operation and retrieve the task ID
            task_id = create_or_update_or_delete_anchor_groups(operation_params)
            self.log("Task ID for anchor group '{0}': {1}".format(group_name, task_id), "DEBUG")

            # Construct operation message
            operation_msg = "{0} operation has completed successfully for anchor group: {1}.".format(task_name, group_name)

            # Check the status of the operation using the task ID
            self.get_task_status_from_tasks_by_id(task_id, task_name, operation_msg).check_return_status()

            # Determine if the operation was successful and categorize accordingly
            if self.status == "success":
                success_groups.append(group_name)
            else:
                failed_groups.append(group_name)

        # Log and prepare final messages for successful operations
        if success_groups:
            self.log("{0} succeeded for the following anchor group(s): {1}".format(task_name, ", ".join(success_groups)), "INFO")
            msg["{0} succeeded for the following anchor group(s)".format(task_name)] = {
                "success_count": len(success_groups),
                "successful_anchor_groups": success_groups
            }

        # Log and prepare final messages for failed operations
        if failed_groups:
            self.log("{0} failed for the following anchor group(s): {1}".format(task_name, ", ".join(failed_groups)), "ERROR")
            msg["{0} failed for the following anchor group(s)".format(task_name)] = {
                "failed_count": len(failed_groups),
                "failed_anchor_groups": failed_groups
            }

        # Store the message dictionary in the class
        self.msg = msg

        # Determine the final operation result based on success and failure lists
        if success_groups and failed_groups:
            self.set_operation_result("failed", True, self.msg, "ERROR")
        elif success_groups:
            self.set_operation_result("success", True, self.msg, "INFO")
        elif failed_groups:
            self.set_operation_result("failed", True, self.msg, "ERROR")
        else:
            self.set_operation_result("ok", False, self.msg, "INFO")

        # Return the instance for method chaining or further processing
        return self

    def process_add_anchor_groups(self, add_anchor_groups_params):
        """
        Processes the addition of anchor groups.
        This function initiates the creation process for a list of anchor groups by calling a common
        processing function that handles the task execution and logging.
        Args:
            add_anchor_groups_params (list): A list of dictionaries containing the parameters for anchor groups to be added.
        Returns:
            tuple: A tuple containing the results of the add operation, typically indicating success or failure for each group.
        """
        task_name_create = "Create Anchor Group(s) Task"
        self.log("Starting '{0}' with parameters: {1}".format(task_name_create, add_anchor_groups_params), "INFO")
        result = self.process_anchor_groups_common(
            add_anchor_groups_params,
            self.create_anchor_group,
            task_name_create
        )
        self.log("Completed '{0}'.".format(task_name_create), "INFO")
        return result

    def process_update_anchor_groups(self, update_anchor_groups_params):
        """
        Processes the update of anchor groups.
        This function initiates the update process for a list of anchor groups by calling a common
        processing function that handles the task execution and logging.
        Args:
            update_anchor_groups_params (list): A list of dictionaries containing the parameters for anchor groups to be updated.
        Returns:
            tuple: A tuple containing the results of the update operation, typically indicating success or failure for each group.
        """
        task_name_update = "Update Anchor Group(s) Task"
        self.log("Starting '{0}' with parameters: {1}".format(task_name_update, update_anchor_groups_params), "INFO")
        result = self.process_anchor_groups_common(
            update_anchor_groups_params,
            self.update_anchor_group,
            task_name_update
        )
        self.log("Completed '{0}'.".format(task_name_update), "INFO")
        return result

    def process_delete_anchor_groups(self, delete_anchor_groups_params):
        """
        Processes the deletion of anchor groups.
        This function initiates the deletion process for a list of anchor groups by calling a common
        processing function that handles the task execution and logging.
        Args:
            delete_anchor_groups_params (list): A list of dictionaries containing the parameters for anchor groups to be deleted.
        Returns:
            tuple: A tuple containing the results of the delete operation, typically indicating success or failure for each group.
        """
        task_name_delete = "Delete Anchor Group(s) Task"
        self.log("Starting '{0}' with parameters: {1}".format(task_name_delete, delete_anchor_groups_params), "INFO")
        result = self.process_anchor_groups_common(
            delete_anchor_groups_params,
            self.delete_anchor_group,
            task_name_delete
        )
        self.log("Completed '{0}'.".format(task_name_delete), "INFO")
        return result

    def verify_add_anchor_groups_operation(self, add_anchor_groups_params):
        """
        Verifies whether the anchor groups specified in add_anchor_groups_params have been successfully created.
        Args:
            add_anchor_groups_params (list): A list of dictionaries containing the requested anchor group parameters to be added.
        Returns:
            tuple: Two lists containing successfully created anchor groups and failed groups.
        """
        self.log("Starting 'verify_add_anchor_groups_operation' with parameters: {0}".format(add_anchor_groups_params), "INFO")

        # Retrieve all existing anchor groups to verify against
        self.log("Retrieving existing anchor groups for verification.", "DEBUG")
        existing_anchor_groups = self.get_anchor_groups(get_anchor_groups_params={})
        self.log("Existing Anchor Groups: {0}".format(existing_anchor_groups), "DEBUG")
        self.log("Requested Anchor Groups to Add: {0}".format(add_anchor_groups_params), "DEBUG")

        # Initialize lists to track successful and failed group additions
        successful_groups = []
        failed_groups = []
        self.log("Initialized lists to track successful and failed anchor group additions.", "DEBUG")

        # Convert existing anchor groups to a set for quick lookup by group name
        existing_groups_set = {group['anchorGroupName'] for group in existing_anchor_groups}
        self.log("Converted existing anchor groups to a set for quick lookup.", "DEBUG")

        # Iterate over the requested anchor groups to verify their creation
        for index, requested_group in enumerate(add_anchor_groups_params, start=1):
            group_name = requested_group['anchorGroupName']
            self.log("Iteration {0}: Verifying creation for Anchor Group '{1}'.".format(index, group_name), "DEBUG")

            # Check if the group now exists in the existing groups
            if group_name in existing_groups_set:
                successful_groups.append(group_name)
                self.log("Iteration {0}: Anchor Group '{1}' has been successfully created.".format(index, group_name), "INFO")
            else:
                failed_groups.append(group_name)
                self.log("Iteration {0}: Anchor Group '{1}' failed to create.".format(index, group_name), "ERROR")

        # Log the summary of the creation verification
        if failed_groups:
            self.log("The ADD Anchor Group(s) operation may not have been successful since some groups were not successfully created: {0}"
                     .format(failed_groups), "WARNING")
        else:
            self.log("Verified the success of ADD Anchor Group(s) operation for parameters: {0}".format(add_anchor_groups_params), "INFO")

    def verify_update_anchor_groups_operation(self, update_anchor_groups_params):
        """
        Verifies whether the anchor groups specified in update_anchor_groups_params have been successfully updated.
        Args:
            update_anchor_groups_params (list): A list of dictionaries containing the requested anchor group parameters to be updated.
        Returns:
            tuple: Two lists containing successfully updated anchor groups and failed updates.
        """
        self.log("Starting 'verify_update_anchor_groups_operation' with parameters: {0}".format(update_anchor_groups_params), "INFO")

        # Retrieve all existing anchor groups
        self.log("Retrieving existing anchor groups.", "DEBUG")
        existing_anchor_groups = self.get_anchor_groups(get_anchor_groups_params={})
        self.log("Existing Anchor Groups: {0}".format(existing_anchor_groups), "DEBUG")
        self.log("Requested Anchor Groups to Update: {0}".format(update_anchor_groups_params), "DEBUG")

        successful_updates = []
        failed_updates = []

        # Convert existing anchor groups to a dictionary for quick lookup by group name
        existing_groups_dict = {group['anchorGroupName']: group for group in existing_anchor_groups}
        self.log("Converted existing anchor groups to dictionary for quick lookup.", "DEBUG")

        # Iterate over the requested anchor groups to verify updates
        for index, requested_group in enumerate(update_anchor_groups_params, start=1):
            group_name = requested_group['anchorGroupName']
            requested_mobility_anchors = requested_group.get('mobilityAnchors', [])
            self.log("Iteration {0}: Verifying update for Anchor Group '{1}'.".format(index, group_name), "DEBUG")

            # Check if the group exists in the existing groups
            if group_name in existing_groups_dict:
                existing_group = existing_groups_dict[group_name]
                existing_mobility_anchors = existing_group.get('mobilityAnchors', [])
                self.log("Iteration {0}: Found existing Anchor Group '{1}'.".format(index, group_name), "DEBUG")

                # Function to normalize and sort anchors for comparison
                def normalize_anchors(anchors):
                    return sorted([
                        (
                            anchor.get('deviceName'),
                            anchor.get('ipAddress'),
                            anchor.get('macAddress'),
                            anchor.get('peerDeviceType'),
                            anchor.get('anchorPriority'),
                            anchor.get('privateIp'),
                            anchor.get('mobilityGroupName'),
                            anchor.get('managedAnchorWlc'),
                        )
                        for anchor in anchors
                    ])

                # Compare mobility anchors, ignoring the order
                if normalize_anchors(requested_mobility_anchors) == normalize_anchors(existing_mobility_anchors):
                    successful_updates.append(group_name)
                    self.log("Iteration {0}: Anchor Group '{1}' has been successfully updated.".format(index, group_name), "INFO")
                else:
                    failed_updates.append(group_name)
                    self.log("Iteration {0}: Anchor Group '{1}' failed to update.".format(index, group_name), "ERROR")
            else:
                failed_updates.append(group_name)
                self.log("Iteration {0}: Anchor Group '{1}' does not exist and cannot be updated.".format(index, group_name), "ERROR")

        # Log the summary of the operation
        if failed_updates:
            self.log("The UPDATE Anchor Groups operation may not have been successful. The following anchor groups failed verification: {0}."
                     .format(failed_updates), "ERROR")
        else:
            self.log("Successfully verified the UPDATE Anchor Groups operation for the following anchor groups: {0}.".format(successful_updates), "INFO")

    def verify_delete_anchor_groups_operation(self, delete_anchor_groups_params):
        """
        Verifies whether the anchor groups specified in delete_anchor_groups_params have been successfully deleted.
        Args:
            delete_anchor_groups_params (list): A list of dictionaries containing the requested anchor group names to be deleted.
        Returns:
            bool: True if all requested anchor groups were successfully deleted, False otherwise.
        """
        self.log("Starting 'verify_delete_anchor_groups_operation' with parameters: {0}".format(delete_anchor_groups_params), "INFO")

        # Retrieve all existing anchor groups
        self.log("Retrieving existing anchor groups.", "DEBUG")
        existing_anchor_groups = self.get_anchor_groups(get_anchor_groups_params={})
        existing_groups_set = {group['anchorGroupName'] for group in existing_anchor_groups}
        self.log("Current Anchor Groups after DELETE operation: {0}".format(existing_groups_set), "INFO")

        # Log the requested deletions
        self.log("Requested Anchor Groups to Delete: {0}".format(delete_anchor_groups_params), "INFO")

        # Initialize a list to track groups that failed deletion
        failed_deletions = []
        self.log("Initialized list to track failed deletions.", "DEBUG")

        # Iterate over the requested anchor groups to verify deletion
        for index, requested_group in enumerate(delete_anchor_groups_params, start=1):
            group_name = requested_group['anchor_group_name']
            self.log("Iteration {0}: Verifying deletion for Anchor Group '{1}'.".format(index, group_name), "DEBUG")

            # Check if the group still exists in the existing groups
            if group_name in existing_groups_set:
                # If it exists, the deletion failed
                failed_deletions.append(group_name)
                self.log("Iteration {0}: Delete operation failed for Anchor Group '{1}'. It still exists.".format(index, group_name), "ERROR")

        # Log the summary of the deletion verification operation
        if failed_deletions:
            self.log("The DELETE Anchor Group(s) operation may not have been successful since some Anchor Groups still exist: {0}."
                     .format(failed_deletions), "ERROR")
        else:
            self.log("Verified the success of DELETE Anchor Group(s) operation for the following parameters: {0}.".format(delete_anchor_groups_params), "INFO")

    def process_final_result(self, final_status_list):
        """
        Processes a list of final statuses and returns a tuple indicating the result and a boolean flag.
        Args:
            final_status_list (list): List of status strings to process.
        Returns:
            tuple: A tuple containing a status string ("ok" or "success") and a boolean flag
                   (False if all statuses are "ok", True otherwise).
        """
        self.log("Starting 'process_final_result' with final_status_list: {0}".format(final_status_list), "INFO")

        # Convert the list of statuses to a set to identify unique statuses
        status_set = set(final_status_list)
        self.log("Unique statuses identified: {0}".format(status_set), "DEBUG")

        # Determine the final status and change flag based on the unique statuses
        if status_set == {"ok"}:
            self.log("All statuses are 'ok'. Returning ('ok', False).", "INFO")
            return "ok", False
        else:
            self.log("Statuses include non-'ok' values. Returning ('success', True).", "INFO")
            return "success", True

    def get_have(self, config, state):
        """
        Constructs the 'have' dictionary representing the current state of network configurations.
        This function validates the given configuration and determines the current state for SSIDs, interfaces,
        power profiles, access point profiles, radio frequency profiles, and anchor groups based on the specified
        state ('merged' or 'deleted').
        Args:
            config (dict): Configuration data for network elements.
            state (str): Desired state of the network elements ('merged' or 'deleted').
        """
        self.log("Starting 'get_have' operation with state: {0}".format(state), "INFO")
        self.validate_params(config, state)
        have = {}

        ssids = config.get("ssids")
        if ssids:
            global_site_name = "Global"
            self.log("Processing SSIDs for state: {0}".format(state), "DEBUG")
            global_site_exists, global_site_id = self.get_site_id(global_site_name)
            self.validate_site_name_hierarchy(global_site_exists, global_site_id, global_site_name)
            have["global_site_details"] = {"site_name": global_site_name, "site_id": global_site_id}

            if state == "merged":
                add_ssids, update_ssids, no_update_ssids = self.verify_create_update_ssids_requirement(ssids, have["global_site_details"])
                have.update({"add_ssids": add_ssids, "update_ssids": update_ssids, "no_update_ssids": no_update_ssids})
            elif state == "deleted":
                have["delete_ssids"] = self.verify_delete_ssids_requirement(ssids, have["global_site_details"])

        element_mappings = [
            ("interfaces", "interface", self.verify_create_update_interfaces_requirement, self.verify_delete_interfaces_requirement),
            ("power_profiles", "power profile", self.verify_create_update_power_profiles_requirement, self.verify_delete_power_profiles_requirement),
            ("access_point_profiles", "access point profile",
             self.verify_create_update_access_point_profiles_requirement, self.verify_delete_access_point_profiles_requirement),
            ("radio_frequency_profiles", "radio frequency profile",
             self.verify_create_update_radio_frequency_profiles_requirement, self.verify_delete_radio_frequency_profiles_requirement),
            ("anchor_groups", "anchor group", self.verify_create_update_anchor_groups_requirement, self.verify_delete_anchor_groups_requirement),
        ]

        for config_key, log_name, merged_func, deleted_func in element_mappings:
            elements = config.get(config_key)
            if elements:
                self.log("Processing {0}s for state: {1}".format(log_name.capitalize(), state), "DEBUG")
                if state == "merged":
                    add, update, no_update = merged_func(elements)
                    have.update({
                        "add_{0}".format(config_key): add,
                        "update_{0}".format(config_key): update,
                        "no_update_{0}".format(config_key): no_update,
                    })
                elif state == "deleted":
                    have["delete_{0}".format(config_key)] = deleted_func(elements)

        self.have = have
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        return self

    def get_want(self, config, state):
        """
        Creates parameters for API calls based on the specified state.
        This method prepares the parameters required for adding, updating, or deleting
        network configurations such as SSIDs and interfaces in the Cisco Catalyst Center
        based on the desired state. It logs detailed information for each operation.
        Args:
            config (dict): The configuration data for the network elements.
            state (str): The desired state of the network elements ('merged' or 'deleted').
        """
        self.log("Creating Parameters for API Calls with state: {0}".format(state), "INFO")

        want = {}

        # Define operations for each state
        self.log("Defining operations for each state: 'merged' and 'deleted'.", "DEBUG")
        operations = {
            "merged": [
                ("add_ssids", "add_ssids_params", self.have.get("add_ssids")),
                ("update_ssids", "update_ssids_params", self.have.get("update_ssids")),
                ("add_interfaces", "add_interfaces_params", self.map_interface_params(self.have.get("add_interfaces"))),
                ("update_interfaces", "update_interfaces_params", self.map_interface_params(self.have.get("update_interfaces"))),
                ("add_power_profiles", "add_power_profiles_params", self.map_power_profiles_params(self.have.get("add_power_profiles"))),
                ("update_power_profiles", "update_power_profiles_params", self.map_power_profiles_params(self.have.get("update_power_profiles"))),
                ("add_access_point_profiles", "add_access_point_profiles_params", self.have.get("add_access_point_profiles")),
                ("update_access_point_profiles", "update_access_point_profiles_params", self.have.get("update_access_point_profiles")),
                ("add_radio_frequency_profiles", "add_radio_frequency_profiles_params", self.have.get("add_radio_frequency_profiles")),
                ("update_radio_frequency_profiles", "update_radio_frequency_profiles_params", self.have.get("update_radio_frequency_profiles")),
                ("add_anchor_groups", "add_anchor_groups_params", self.have.get("add_anchor_groups")),
                ("update_anchor_groups", "update_anchor_groups_params", self.have.get("update_anchor_groups")),
            ],
            "deleted": [
                ("delete_ssids", "delete_ssids_params", self.have.get("delete_ssids")),
                ("delete_interfaces", "delete_interfaces_params", self.map_interface_params(self.have.get("delete_interfaces"))),
                ("delete_power_profiles", "delete_power_profiles_params", self.map_power_profiles_params(self.have.get("delete_power_profiles"))),
                ("delete_access_point_profiles", "delete_access_point_profiles_params",
                 self.map_access_point_profiles_params(self.have.get("delete_access_point_profiles"))),
                ("delete_radio_frequency_profiles", "delete_radio_frequency_profiles_params", self.have.get("delete_radio_frequency_profiles")),
                ("delete_anchor_groups", "delete_anchor_groups_params", self.have.get("delete_anchor_groups")),
            ]
        }

        # Process operations based on the state
        if state in operations:
            self.log("Processing operations for state: {0}".format(state), "DEBUG")
            for index, (op_name, param_key, value) in enumerate(operations[state], start=1):
                self.log("Iteration {0}: State '{1}', Operation '{2}', Parameter Key '{3}', Value '{4}'.".format(
                    index, state, op_name, param_key, value), "DEBUG")
                if value:
                    want[param_key] = value
                    self.log(
                        "Iteration {0}: State is '{1}' and '{2}' need to be processed in the Cisco Catalyst Center, "
                        "therefore setting '{3}' - {4}.".format(index, state, op_name, param_key, want.get(param_key)),
                        "DEBUG"
                    )

        self.want = want
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")
        self.msg = "Successfully collected all parameters from the playbook for Wireless Design operations."
        self.status = "success"
        return self

    def get_diff_merged(self):
        """
        Executes the merge operations for various network configurations in the Cisco Catalyst Center.
        This method processes additions and updates for SSIDs, interfaces, power profiles, access point profiles,
        radio frequency profiles, and anchor groups. It logs detailed information about each operation,
        updates the result status, and returns a consolidated result.
        """
        self.log("Starting 'get_diff_merged' operation.", "INFO")

        final_status_list = []
        result_details = {}

        # Define a list of operations for adding and updating configurations
        self.log("Defining operations for addition and update.", "DEBUG")
        operations = [
            ("add_ssids_params", "ADD SSIDs", self.process_add_ssids),
            ("update_ssids_params", "UPDATE SSIDs", self.process_update_ssids),
            ("add_interfaces_params", "ADD Interfaces", self.process_add_interfaces),
            ("update_interfaces_params", "UPDATE Interfaces", self.process_update_interfaces),
            ("add_power_profiles_params", "ADD Power Profiles", self.process_add_power_profiles),
            ("update_power_profiles_params", "UPDATE Power Profiles", self.process_update_power_profiles),
            ("add_access_point_profiles_params", "ADD Access Point Profiles", self.process_add_access_point_profiles),
            ("update_access_point_profiles_params", "UPDATE Access Point Profiles", self.process_update_access_point_profiles),
            ("add_radio_frequency_profiles_params", "ADD Radio Frequency Profiles", self.process_add_radio_frequency_profiles),
            ("update_radio_frequency_profiles_params", "UPDATE Radio Frequency Profiles", self.process_update_radio_frequency_profiles),
            ("add_anchor_groups_params", "ADD Anchor Groups", self.process_add_anchor_groups),
            ("update_anchor_groups_params", "UPDATE Anchor Groups", self.process_update_anchor_groups),
        ]

        # Iterate over operations and process them
        self.log("Beginning iteration over defined operations for processing.", "DEBUG")
        for index, (param_key, operation_name, operation_func) in enumerate(operations, start=1):
            self.log("Iteration {0}: Checking parameters for {1} operation with param_key '{2}'.".format(index, operation_name, param_key), "DEBUG")
            params = self.want.get(param_key)
            if params:
                self.log("Iteration {0}: Parameters found for {1}. Starting processing.".format(index, operation_name), "INFO")
                operation_func(params).check_return_status()
                self.log("Iteration {0}: Completed processing of {1}.".format(index, operation_name), "INFO")
                result = self.msg
                result_details.update(result)
                final_status_list.append(self.status)
            else:
                self.log("Iteration {0}: No parameters found for {1}. Skipping operation.".format(index, operation_name), "WARNING")

        self.log("Final Statuses = {0}".format(final_status_list), "DEBUG")

        # Handle the case where no operations are required
        if not final_status_list:
            self.msg = "No Wireless Design operations were required for the provided parameters in the Cisco Catalyst Center."
            self.set_operation_result("ok", False, self.msg, "INFO")
            self.log("No operations were performed.", "DEBUG")
            return self

        # Process the final result
        final_status, is_changed = self.process_final_result(final_status_list)
        self.msg = result_details
        self.log("Completed 'get_diff_merged' operation with final status: {0}, is_changed: {1}".format(final_status, is_changed), "INFO")
        self.set_operation_result(final_status, is_changed, self.msg, "INFO")
        return self

    def get_diff_deleted(self):
        """
        Executes the deletion operations for various network configurations in the Cisco Catalyst Center.
        This method processes deletions for SSIDs, interfaces, power profiles, access point profiles,
        radio frequency profiles, and anchor groups. It logs detailed information about each operation,
        updates the result status, and returns a consolidated result.
        """
        self.log("Starting 'get_diff_deleted' operation.", "INFO")

        final_status_list = []
        result_details = {}

        # Define a list of operations to delete
        self.log("Defining operations for deletion.", "DEBUG")
        operations = [
            ("delete_ssids_params", "DELETE SSIDs", self.process_delete_ssids),
            ("delete_interfaces_params", "DELETE Interfaces", self.process_delete_interfaces),
            ("delete_power_profiles_params", "DELETE Power Profiles", self.process_delete_power_profiles),
            ("delete_access_point_profiles_params", "DELETE Access Point Profiles", self.process_delete_access_point_profiles),
            ("delete_radio_frequency_profiles_params", "DELETE Radio Frequency Profiles", self.process_delete_radio_frequency_profiles),
            ("delete_anchor_groups_params", "DELETE Anchor Groups", self.process_delete_anchor_groups),
        ]

        # Iterate over operations and process deletions
        self.log("Beginning iteration over defined operations for deletion.", "DEBUG")
        for index, (param_key, operation_name, operation_func) in enumerate(operations, start=1):
            self.log("Iteration {0}: Checking parameters for {1} operation with param_key '{2}'.".format(index, operation_name, param_key), "DEBUG")
            params = self.want.get(param_key)
            if params:
                self.log("Iteration {0}: Parameters found for {1}. Starting processing.".format(index, operation_name), "INFO")
                operation_func(params).check_return_status()
                self.log("Iteration {0}: Completed processing of {1}.".format(index, operation_name), "INFO")
                result = self.msg
                result_details.update(result)
                final_status_list.append(self.status)
            else:
                self.log("Iteration {0}: No parameters found for {1}. Skipping operation.".format(index, operation_name), "WARNING")

        self.log("Final Statuses = {0}".format(final_status_list), "DEBUG")

        # Handle the case where no deletions are required
        if not final_status_list:
            self.msg = "No deletions were required for the provided parameters in the Cisco Catalyst Center."
            self.set_operation_result("ok", False, self.msg, "INFO")
            self.log("No deletion operations were performed.", "DEBUG")
            return self

        # Process the final result
        final_status, is_changed = self.process_final_result(final_status_list)
        self.msg = result_details
        self.log("Completed 'get_diff_deleted' operation with final status: {0}, is_changed: {1}".format(final_status, is_changed), "INFO")
        self.set_operation_result(final_status, is_changed, self.msg, "INFO")
        return self

    def verify_diff_merged(self):
        """
        Verifies the merge operations for various network configurations.
        This method ensures that the add and update operations for SSIDs, interfaces, power profiles,
        access point profiles, radio frequency profiles, and anchor groups are verified. It logs detailed
        information about each operation, including the parameter key being processed, and confirms that
        each merge operation is performed as expected.
        """
        self.log("Starting 'verify_diff_merged' operation.", "INFO")

        # Define a list of operations with their parameter keys, descriptive names, and corresponding functions
        self.log("Defining operations and their corresponding verification functions.", "DEBUG")
        operations = [
            ("add_ssids_params", "ADD SSIDs", self.verify_add_ssids_operation),
            ("update_ssids_params", "UPDATE SSIDs", self.verify_update_ssids_operation),
            ("add_interfaces_params", "ADD Interfaces", self.verify_add_interfaces_operation),
            ("update_interfaces_params", "UPDATE Interfaces", self.verify_update_interfaces_operation),
            ("add_power_profiles_params", "ADD Power Profiles", self.verify_add_power_profiles_operation),
            ("update_power_profiles_params", "UPDATE Power Profiles", self.verify_update_power_profiles_operation),
            ("add_access_point_profiles_params", "ADD Access Point Profiles", self.verify_add_access_point_profiles_operation),
            ("update_access_point_profiles_params", "UPDATE Access Point Profiles", self.verify_update_access_point_profiles_operation),
            ("add_radio_frequency_profiles_params", "ADD Radio Frequency Profiles", self.verify_add_radio_frequency_profiles_operation),
            ("update_radio_frequency_profiles_params", "UPDATE Radio Frequency Profiles", self.verify_update_radio_frequency_profiles_operation),
            ("add_anchor_groups_params", "ADD Anchor Groups", self.verify_add_anchor_groups_operation),
            ("update_anchor_groups_params", "UPDATE Anchor Groups", self.verify_update_anchor_groups_operation)
        ]

        # Iterate over operations and perform verification
        self.log("Beginning iteration over defined operations for verification.", "DEBUG")
        for index, (param_key, operation_name, operation_func) in enumerate(operations, start=1):
            # Retrieve the parameters for the current operation
            self.log("Checking parameters for operation {0}: '{1}' with param_key '{2}'.".format(index, operation_name, param_key), "DEBUG")
            params = self.want.get(param_key)
            if params:
                # Log the beginning of the verification process with details
                self.log("Iteration {0}: Parameters found for {1} operation. Starting verification.".format(index, operation_name), "INFO")
                operation_func(params)
                self.log("Iteration {0}: Successfully completed verification of {1} operation with param_key '{2}'.".format(
                    index, operation_name, param_key), "INFO")
            else:
                # Log if no parameters are found for the current operation
                self.log("Iteration {0}: No parameters found for {1} operation. Skipping verification.".format(index, operation_name), "WARNING")

        self.log("Completed 'verify_diff_merged' operation.", "INFO")
        return self

    def verify_diff_deleted(self):
        """
        Verifies the deletion operations for various network configurations.
        This method checks the deletion parameters for SSIDs, interfaces, power profiles,
        access point profiles, radio frequency profiles, and anchor groups, ensuring that
        each specified delete operation is completed as expected. It logs the start and
        completion of each verification process.
        """
        self.log("Starting 'verify_diff_deleted' operation.", "INFO")

        # Define a list of operations to verify
        self.log("Defining operations and their corresponding verification functions.", "DEBUG")
        operations = [
            ("delete_ssids_params", "DELETE Port SSIDs", self.verify_delete_ssids_operation),
            ("delete_interfaces_params", "DELETE Interfaces", self.verify_delete_interfaces_operation),
            ("delete_power_profiles_params", "DELETE Power Profiles", self.verify_delete_power_profiles_operation),
            ("delete_access_point_profiles_params", "DELETE Access Point Profiles", self.verify_delete_access_point_profiles_operation),
            ("delete_radio_frequency_profiles_params", "DELETE Radio Frequency Profiles", self.verify_delete_radio_frequency_profiles_operation),
            ("delete_anchor_groups_params", "DELETE Anchor Groups", self.verify_delete_anchor_groups_operation)
        ]

        # Iterate over operations and perform verification
        self.log("Beginning iteration over defined operations for verification.", "DEBUG")
        for index, (param_key, operation_name, operation_func) in enumerate(operations, start=1):
            self.log(f"Checking parameters for operation {index}: '{operation_name}' with param_key '{param_key}'.", "DEBUG")
            params = self.want.get(param_key)
            if params:
                self.log("Iteration {0}: Found parameters for {1} operation. Starting verification.".format(index, operation_name), "INFO")
                operation_func(params)
                self.log("Iteration {0}: Successfully completed verification of {1} operation with param_key '{2}'.".format(
                    index, operation_name, param_key), "INFO")
            else:
                self.log("Iteration {0}: No parameters found for {1} operation. Skipping verification.".format(index, operation_name), "WARNING")

        self.log("Completed 'verify_diff_deleted' operation.", "INFO")
        return self


def main():
    """ main entry point for module execution
    """
    # Define the specification for the module"s arguments
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
        "state": {"default": "merged", "choices": ["merged", "deleted"]}
    }

    # Initialize the Ansible module with the provided argument specifications
    module = AnsibleModule(argument_spec=element_spec,
                           supports_check_mode=False)

    # Initialize the NetworkCompliance object with the module
    ccc_wireless_design = WirelessDesign(module)

    # Get the state parameter from the provided parameters
    state = ccc_wireless_design.params.get("state")

    # Check if the state is valid
    if state not in ccc_wireless_design.supported_states:
        ccc_wireless_design.status = "invalid"
        ccc_wireless_design.msg = "State {0} is invalid".format(state)
        ccc_wireless_design.check_return_status()

    # Validate the input parameters and check the return status
    ccc_wireless_design.validate_input().check_return_status()

    # Get the config_verify parameter from the provided parameters
    config_verify = ccc_wireless_design.params.get("config_verify")

    # Iterate over the validated configuration parameters
    for config in ccc_wireless_design.validated_config:
        ccc_wireless_design.reset_values()
        ccc_wireless_design.get_have(config, state).check_return_status()
        ccc_wireless_design.get_want(config, state).check_return_status()
        ccc_wireless_design.get_diff_state_apply[state]().check_return_status()

        if config_verify:
            ccc_wireless_design.verify_diff_state_apply[state]().check_return_status()

    module.exit_json(**ccc_wireless_design.result)


if __name__ == "__main__":
    main()
