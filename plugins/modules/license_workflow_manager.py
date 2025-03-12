#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module to perform operations on Assurance issue settings in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ["Sonali Deepthi, Madhan Sankaranarayanan"]

DOCUMENTATION = r"""
---
module: license_workflow_manager
short_description: Resource module for License workflow
description: |
  - Manage operations related to Smart Licensing in Cisco Catalyst Center.
  - Facilitates registration of Smart Account and Virtual Account credentials.
  - Enables configuration and management of Smart Licensing workflows, including license assignment and status monitoring.
  - Supports adding, updating and registering Smart Account and Virtual Account credentials for devices registration.
version_added: '6.31.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - Sonali Deepthi (@skesali)
  - Madhan Sankaranarayanan (@madhansansel)

options:
  config_verify:
    description: |
        Set to True to verify the Cisco Catalyst Center configuration after applying the playbook.
    type: bool
    default: false
  state:
    description: |
        The desired state of Cisco Catalyst Center after module execution.
    type: str
    choices: [merged]
    default: merged

  config:
    description: Licensing configuration details for Cisco Catalyst Center.
    type: list
    elements: dict
    required: true
    suboptions:
        license_register:
        description: Licensing details to configure for the device.
        type: dict
        suboptions:
          smart_account_name:
            description: |
                - The Smart Account name to associate with the device.
                - Must contain only alphanumeric characters, underscores (_), and hyphens (-).
            type: str
            required: false

          virtual_account_name:
            description: |
                - The Virtual Account name under the Smart Account.
                - Must contain only alphanumeric characters, underscores (_), and hyphens (-).
            type: str
            required: false

          update_virtual_account_name:
            description: |
                - The new Virtual Account name under the Smart Account.
                - Must contain only alphanumeric characters, underscores (_), and hyphens (-).
            type: str
            required: false

          device_name: |
            description: Name of the device to configure with the license.
            type: str
            required: false

          device_mac_address:
            description: |
                - MAC address of the device.
                - Must follow the format "d4:ad:bd:c1:67:00" or "d4-ad-bd-c1-67-00" (0-9, A-F).
                - Must be exactly 17 characters, including separators.
            type: str
            required: false

          device_ip_address:
            description: |
                - IP address of the device to configure with the license.
                - Must consist of four octets (0-255) separated by dots (e.g., 192.168.1.1).
            type: str
            required: false

          smart_license_registration:
            description: |
                Specifies whether Smart License registration is enabled (True) or disabled (False).
            type: bool
            required: true

          device_registration:
            description: |
                Specifies whether device registration is enabled (True) or disabled (False).
            type: bool
            required: true
requirements:
  - dnacentersdk == 2.8.6
  - python >= 3.9
notes:
  - SDK Method used are
    license.Licenses.smart_account_details,
    license.Licenses.virtual_account_details,
    license.Licenses.device_registration,
    license.Licenses.device_deregistration,
    license.Licenses.change_virtual_account,
    license.Licenses.update_license_setting,
    license.Licenses.device_license_summary

  - Paths used are
    GET dna/intent/api/v1/licenses/smartAccounts,
    GET dna/intent/api/v1/licenses/smartAccount/${smart_account_id}/virtualAccounts,
    POST dna/system/api/v1/license/register,
    POST dna/system/api/v1/license/deregister,
    GET dna/system/api/v1/license/status,
    PUT dna/intent/api/v1/licenses/smartAccount/virtualAccount/${virtual_account_name}/register,
    PUT dna/intent/api/v1/licenses/smartAccount/virtualAccount/deregister,
    POST dna/intent/api/v1/licenses/smartAccount/${smart_account_id}/virtualAccount/${virtual_account_name}/device/transfer,
    GET dna/intent/api/v1/licenses/device/summary
"""

EXAMPLES = r"""
- name: device registration
  cisco.dnac.license_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: "{{dnac_log}}"
    state: merged
    config:
        - smart_account_name: "Solutions Team - IaC for CatC"
        virtual_account_name: "DEFAULT"
        update_virtual_account_name: "witsang_internaltesting1"
        device_name: "NY-EN-9300"
        device_ip_address: "204.1.2.2"
        device_mac_address: "d4:ad:bd:c1:67:00"
        smart_license_registration: False
        device_registration: True

"""

RETURN = r"""
# Case 1: Successful registration of smart license

successful_smart_license_registration_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center for smart license registration.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }

successful_smart_license_registration_task_execution:
  description: A dictionary with additional details for smart license registration task execution.
  returned: always
  type: dict
  sample:
    {
      "response": "Smart license registration successful."
    }

# Case 2: Successful de-registration of smart license

successful_smart_license_deregistration_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center for smart license de-registration.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }

successful_smart_license_deregistration_task_execution:
  description: A dictionary with additional details for smart license de-registration task execution.
  returned: always
  type: dict
  sample:
    {
      "response": "Smart license de-registration successful."
    }

# Case 3: Attempt to register already registered smartAccountId with virtual_account_name

error_smart_license_registration_task_tracking:
  description: A dictionary with details of the API execution when trying to register an already registered smartAccountId.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }

error_smart_license_registration_task_execution:
  description: A dictionary with additional details for the failed smart license registration task.
  returned: always
  type: dict
  sample:
    {
      "msg": "Smart license registration failed: SmartAccountId already registered.",
      "response": "Smart license registration failed: SmartAccountId already registered."
    }

# Case 4: Attempt to de-register already unregistered smartAccountId with virtual_account_name

error_smart_license_deregistration_task_tracking:
  description: A dictionary with details of the API execution when trying to de-register an already unregistered smartAccountId.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }

error_smart_license_deregistration_task_execution:
  description: A dictionary with additional details for the failed smart license de-registration task.
  returned: always
  type: dict
  sample:
    {
      "msg": "Smart license de-registration failed: SmartAccountId already unregistered.",
      "response": "Smart license de-registration failed: SmartAccountId already unregistered."
    }

# Case 5: Successful device registration with virtual_account_name using device_name

successful_device_registration_by_name_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center for device registration using device_name.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }

successful_device_registration_by_name_task_execution:
  description: A dictionary with additional details for device registration task using device_name.
  returned: always
  type: dict
  sample:
    {
      "response": "Device 'device_name' registered successfully with virtual_account_name."
    }

# Case 6: Successful device registration with virtual_account_name using device_ip_address

successful_device_registration_by_ip_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center for device registration using device_ip_address.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }

successful_device_registration_by_ip_task_execution:
  description: A dictionary with additional details for device registration task using device_ip_address.
  returned: always
  type: dict
  sample:
    {
      "response": "Device with IP 'device_ip_address' registered successfully with virtual_account_name."
    }

# Case 7: Successful device registration with virtual_account_name using device_mac_address

successful_device_registration_by_mac_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center for device registration using device_mac_address.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }

successful_device_registration_by_mac_task_execution:
  description: A dictionary with additional details for device registration task using device_mac_address.
  returned: always
  type: dict
  sample:
    {
      "response": "Device with MAC 'device_mac_address' registered successfully with virtual_account_name."
    }

# Case 8: Successful device unregistration with device_name

successful_device_unregistration_by_name_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center for device unregistration using device_name.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }

successful_device_unregistration_by_name_task_execution:
  description: A dictionary with additional details for device unregistration task using device_name.
  returned: always
  type: dict
  sample:
    {
      "response": "Device 'device_name' unregistered successfully."
    }

# Case 9: Successful device unregistration with device_ip_address

successful_device_unregistration_by_ip_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center for device unregistration using device_ip_address.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }

successful_device_unregistration_by_ip_task_execution:
  description: A dictionary with additional details for device unregistration task using device_ip_address.
  returned: always
  type: dict
  sample:
    {
      "response": "Device with IP 'device_ip_address' unregistered successfully."
    }

# Case 10: Successful device unregistration with device_mac_address

successful_device_unregistration_by_mac_task_tracking:
  description: A dictionary with details of the API execution from Cisco Catalyst Center for device unregistration using device_mac_address.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }

successful_device_unregistration_by_mac_task_execution:
  description: A dictionary with additional details for device unregistration task using device_mac_address.
  returned: always
  type: dict
  sample:
    {
      "response": "Device with MAC 'device_mac_address' unregistered successfully."
    }

# Case 11: Successful update of virtual_account_name to update_virtual_account_name

successful_virtual_account_name_update_task_tracking:
  description: A dictionary with details of the API execution for updating update_virtual_account_name.
  returned: always
  type: dict
  sample:
    {
      "response": {
          "taskId": "str",
          "url": "str"
      },
      "version": "str"
    }

successful_virtual_account_name_update_task_execution:
  description: A dictionary with additional details for the virtual account name update task execution.
  returned: always
  type: dict
  sample:
    {
      "response": "Virtual account name updated from 'virtual_account_name' to 'update_virtual_account_name' successfully."
    }
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)


class License(DnacBase):
    """Class containing member attributes for license workflow_manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged"]
        self.keymap = {}
        self.handle_config = {}
        self.registered = []
        self.not_registered = []

    def validate_input(self):
        """
        Validates the configuration provided in the playbook against a predefined schema.

        Ensures that all required parameters are present and have valid data types and values.
        Updates the instance attributes based on the validation result.

        Parameters:
            self: The instance of the class containing the 'config' attribute to be validated.

        Returns:
            The method updates these attributes of the instance:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation ('success' or 'failed').
                - self.validated_config: If successful, a validated version of the 'config' parameter.
        """
        self.log("Validating playbook configuration parameters: {0}".format(self.pprint(self.config)), "DEBUG")

        if not self.config:
            self.status = "success"
            self.msg = "Configuration is not available in the playbook for validation."
            self.log(self.msg, "INFO")
            return self

        self.log("Configuration details found in the playbook: {0}".format(self.config), "INFO")

        temp_spec = {
            "smart_account_name": {"required": True, "type": "str"},
            "virtual_account_name": {"required": True, "type": "str"},
            "update_virtual_account_name": {"required": False, "type": "str"},
            "device_name": {"required": False, "type": "str"},
            "device_ip_address": {"required": False, "type": "str"},
            "device_mac_address": {"required": False, "type": "str"},
            "smart_license_registration": {"required": False, "type": "bool"},
            "device_registration": {"required": False, "type": "bool"},
        }

        self.config = self.update_site_type_key(self.config)
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)

        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(", ".join(invalid_params))
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook config params: {0}".format(valid_temp)
        self.log(self.msg, "INFO")
        self.status = "success"

        return self

    def get_want(self, config):
        """
        Retrieves all license-related information from the playbook needed for smart license registration
        and deregistration of licenses in Cisco Catalyst Center.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing configuration information.

        Returns:
            self: The current instance of the class with the extracted 'want' configuration.

        Description:
            Extracts license-related information from the provided playbook configuration. It renames
            'smart_account_name' to 'name' if present. The extracted data is stored in 'self.want'.
        """
        want = {}

        for key in [
            "smart_account_name",
            "virtual_account_name",
            "update_virtual_account_name",
            "device_name",
            "device_ip_address",
            "device_mac_address",
            "smart_license_registration",
            "device_registration",
        ]:
            if key in config:
                want[key] = config[key]

        if "smart_account_name" in want:
            want["name"] = want.pop("smart_account_name")

        self.want = want
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        return self

    def validate_license_input_data(self, config):
        """
        Validates license registration input data based on Cisco Catalyst Center requirements.

        Ensures that required fields are present and meet expected constraints.
        Logs validation errors and updates the operation result if invalid data is found.

        Parameters:
            self (object): Instance of a class for interacting with Cisco Catalyst Center.
            config (dict): Dictionary containing input assurance details.

        Returns:
            self: Updates instance attributes with validation results and logs errors if necessary.
        """
        errormsg = []
        self.log("Starting validation of license input data.", "DEBUG")

        if not config:
            self.log("Config data is missing.", "ERROR")
            errormsg.append("Config data is missing.")
            return errormsg

        self.log("Config data found with {0} entries.".format(len(config)), "DEBUG")
        for entry in config:
            self.log("Validating entry in config: {0}".format(entry), "DEBUG")
            license = entry.get("license_register", {})

            smart_license_registration = license.get("smart_license_registration", False)
            device_registration = license.get("device_registration", False)

            if smart_license_registration not in [True, False]:
                errormsg.append("smart_license_registration must be explicitly True or False.")

            if device_registration not in [True, False]:
                errormsg.append("device_registration must be explicitly True or False.")

            if smart_license_registration:
                for key in ["smart_account_name", "virtual_account_name"]:
                    value = license.get(key)
                    if not value:
                        errormsg.append("{} is required when smart_license_registration.".format(key))
                    elif not isinstance(value, str) or len(value) > 40:
                        errormsg.append("Invalid {} (must be a string ≤ 40 characters).".format(key))

            if smart_license_registration:
                for key in ["smart_account_name", "virtual_account_name"]:
                    value = license.get(key)
                    if not value:
                        errormsg.append("{} is required when smart_license_registration is True.".format(key))
                    elif not isinstance(value, str) or len(value) > 40:
                        errormsg.append("Invalid {} (must be a string ≤ 40 characters).".format(key))

            if device_registration:
                device_name = license.get("device_name")
                device_ip_address = license.get("device_ip_address")
                device_mac_address = license.get("device_mac_address")

                if not (device_name or device_ip_address or device_mac_address):
                    errormsg.append("At least one of device_name, device_ip_address, or device_mac_address is required for device registration.")

            update_virtual_account_name = license.get("update_virtual_account_name")
            if update_virtual_account_name and (not isinstance(update_virtual_account_name, str) or len(update_virtual_account_name) > 40):
                errormsg.append("Invalid update_virtual_account_name (must be a string ≤ 40 characters).")

        if errormsg:
            self.msg = "Validation failed: " + ", ".join(errormsg)
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        self.msg = "Successfully validated config params."
        self.log(self.msg, "INFO")
        self.status = "success"
        return self

    def get_have(self, config):
        """Retrieve the current state of the smart license and device details.

        This function gathers smart account details, virtual account details, and device
        information from Catalyst Center. It verifies that the required parameters exist
        in the configuration and fetches the relevant details.

        Args:
            config (dict): Configuration details, including smart and virtual account names
                        and device details.

        Returns:
            self: The updated instance containing the retrieved details in `self.have`.
        """
        self.log("License configuration details: {}".format(config), "INFO")

        smart_license_registration = config.get("smart_license_registration", False)
        device_registration = config.get("device_registration", False)

        self.have = {}

        status_response = self.smart_license_status(config)
        if not status_response:
            self.log("Failed to fetch the smart license status.", "ERROR")
            self.status = "failed"
            return self

        self.log("Smart license status response: {}".format(status_response), "DEBUG")
        registration_status = status_response.get("response", {}).get("registrationStatus", {}).get("status")

        if not registration_status:
            self.log("Registration status is missing from the response.", "ERROR")
            self.status = "failed"
            return self

        self.log("Current registration status: {}".format(registration_status), "INFO")
        self.have["registration_status"] = registration_status

        if smart_license_registration:
            smart_account_name = config.get("smart_account_name")
            virtual_account_name = config.get("virtual_account_name")

            if not smart_account_name or not virtual_account_name:
                self.msg = "Missing required parameters 'smart_account_name' or 'virtual_account_name' for smart license registration."
                self.status = "failed"
                return self

            smart_account_details = self.get_smart_account_details(config)
            if not smart_account_details:
                self.msg = "Failed to retrieve smart account details."
                self.status = "failed"
                return self

            matching_smart_account = next(
                (
                    acc
                    for acc in smart_account_details.get("response", [])
                    if acc["name"] == smart_account_name
                ),
                None,
            )

            if not matching_smart_account:
                self.msg = "Smart account '{}' not found.".format(smart_account_name)
                self.status = "failed"
                return self

            self.have["smart_account_id"] = matching_smart_account["id"]
            self.have["smart_account_name"] = smart_account_name

            virtual_account_details = self.get_virtual_account_details(config)
            if not virtual_account_details:
                self.msg = "Failed to retrieve virtual account details."
                self.status = "failed"
                return self

            matching_virtual_account = next(
                (
                    va
                    for va in virtual_account_details.get("virtual_account_details", [])
                    if va["virtual_account_name"] == virtual_account_name
                ),
                None,
            )

            if not matching_virtual_account:
                self.msg = "Virtual account '{}' not found for smart account '{}'.".format(virtual_account_name, smart_account_name)
                self.status = "failed"
                return self

            self.have["virtual_account_id"] = matching_virtual_account["virtual_account_id"]
            self.have["virtual_account_name"] = virtual_account_name

        if device_registration:
            device_name = config.get("device_name")
            device_ip_address = config.get("device_ip_address")
            device_mac_address = config.get("device_mac_address")

            device_summary = self.device_details_summmary(config)
            if not device_summary:
                self.msg = "Failed to retrieve device details summary."
                self.status = "failed"
                return self

            matching_device = next(
                (
                    device for device in device_summary.get("response", [])
                    if device.get("device_name") == device_name
                    or device.get("ip_address") == device_ip_address
                    or device.get("mac_address") == device_mac_address
                ),
                None,
            )

            if not matching_device:
                self.msg = "Device '{}' not found.".format(device_name or device_ip_address or device_mac_address)
                self.status = "failed"
                return self

            self.have.update({
                "device_name": matching_device.get("device_name"),
                "device_ip_address": matching_device.get("ip_address"),
                "device_mac_address": matching_device.get("mac_address"),
                "device_id": matching_device.get("device_uuid"),
                "device_type": matching_device.get("device_type"),
                "software_version": matching_device.get("software_version"),
            })

        self.log("Current State (have): {}".format(self.have), "INFO")
        self.msg = "Successfully retrieved smart and virtual account details, along with device details (if applicable)."
        self.status = "success"
        return self

    def get_smart_account_details(self, config):
        """
        Retrieves smart account details from Cisco Catalyst Center.

        Calls the Cisco DNA Center API to fetch smart account details based on the provided configuration.
        Logs API responses and errors encountered during execution.

        Parameters:
            self (object): Instance of a class for interacting with Cisco Catalyst Center.
            config (dict): Dictionary containing smart account details.

        Returns:
            dict or None: API response containing smart account details, or None if an error occurs.
        """

        self.log("Retrieving the smart account information '{0}'".format(config))

        param = {}

        try:
            response = self.execute_get_request("licenses", "smart_account_details_v1", param)
            if not response:
                self.log("Empty response received for smart account: {0}".format(response), "WARNING")
                return None

            self.log("Received API response for smart account '{0}':".format(response), "DEBUG")
            return response

        except Exception as e:
            msg = "An error occurred in 'smart_account_details_v1': {0}".format(e)
            self.log(msg, "ERROR")
            self.fail_and_exit(msg)

    def get_virtual_account_details(self, config):
        """
        Retrieves virtual account details for a given smart account.

        Uses the stored `smart_account_id` from the class instance to query the Cisco DNA Center API
        for virtual account details. Logs API responses and errors encountered during execution.

        Parameters:
            self (object): Instance of a class for interacting with Cisco Catalyst Center.
            config (dict): Dictionary containing request parameters (currently unused).

        Returns:
            dict or None: API response containing virtual account details, or None if an error occurs.
        """
        smart_account_id = self.have.get("smart_account_id")
        self.log("Virtual account information for Smart Account ID: {}".format(smart_account_id))

        if not smart_account_id:
            self.log("Smart account ID not found in 'have'.", "ERROR")
            return None

        self.log("Retrieving the Virtual account information for Smart Account ID: {}".format(smart_account_id))

        param = {"smart_account_id": smart_account_id}

        try:
            response = self.execute_get_request("licenses", "virtual_account_details_v1", param)
            if not response:
                self.log("Empty response received for Virtual account", "WARNING")
                return None

            self.log("Received API response for Virtual account: {}".format(response), "DEBUG")
            return response

        except Exception as e:
            msg = "An error occurred in 'virtual_account_details_v1': {0}".format(e)
            self.log(msg, "ERROR")
            self.fail_and_exit(msg)

    def smart_license_registration(self, config):
        """
        Register the smart license using the stored smart and virtual account details.

        This function retrieves the Smart Account ID and Virtual Account ID from the
        existing configuration (`self.have`). If either ID is missing, an error is logged
        and the function returns None.

        It then prepares the necessary parameters and makes an API call to register the
        smart license. The response is logged and returned.

        Args:
            config (dict): Configuration details for the smart license registration.

        Returns:
            dict or None: API response if successful, otherwise None.
        """
        self.log("Registering the smart license with config: {}".format(config), "INFO")

        smart_account_id = self.have.get("smart_account_id")
        virtual_account_id = self.have.get("virtual_account_id")

        if not smart_account_id or not virtual_account_id:
            self.log("Smart or Virtual Account ID is missing.", "ERROR")
            return None

        param = {
            "smartAccountId": smart_account_id,
            "virtualAccountId": virtual_account_id
        }
        self.log("Using parameters: {}".format(param), "DEBUG")

        try:
            response = self.execute_get_request("licenses", "system_licensing_registration_v1", param)

            if not response:
                self.log("Empty response received for registering the smart license. Params: {}".format(param), "WARNING")
                return None

            self.log("Received API response: {}".format(response), "DEBUG")
            return response

        except Exception as e:
            msg = "An error occurred in 'system_licensing_registration_v1': {0}".format(e)
            self.log(msg, "ERROR")
            self.fail_and_exit(msg)

    def smart_license_deregistration(self, config):
        """
        Deregister the smart license.

        This function sends a request to the Cisco DNA Center API to deregister the
        smart license. If the response is empty, a warning is logged. The API response
        is returned if successful.

        Args:
            config (dict): Configuration details for smart license deregistration.

        Returns:
            dict or None: API response if successful, otherwise None.
        """
        self.log("Deregistering the smart license with config: {}".format(config), "INFO")
        param = {}
        self.log("Using parameters: {}".format(param), "DEBUG")

        try:
            response = self.execute_get_request("licenses", "smart_licensing_deregistration_v1", param)

            if not response:
                self.log("Empty response received for Deregistering the smart license. Params: {}".format(param), "WARNING")
                return None

            self.log("Received API response: {}".format(response), "DEBUG")
            return response

        except Exception as e:
            msg = "An error occurred while calling 'system_licensing_deregistering_v1': {0}".format(e)
            self.log(msg, "ERROR")
            self.fail_and_exit(msg)

    def smart_license_status(self, config):
        """
        Retrieve the status of the smart license.

        This function queries the Cisco DNA Center API for the current status of the
        smart license. If the response is empty, a warning is logged. The API response
        is returned if successful.

        Args:
            config (dict): Configuration details for retrieving smart license status.

        Returns:
            dict or None: API response if successful, otherwise None.
        """
        self.log("Status of smart license with config: {}".format(config), "INFO")
        param = {}
        self.log("Using parameters: {}".format(param), "DEBUG")

        try:
            response = self.execute_get_request("licenses", "system_licensing_status_v1", param)

            if not response:
                self.log("Empty response received for status of smart license. Params: {}".format(param), "WARNING")
                return None

            self.log("Received API response: {}".format(response), "DEBUG")
            return response

        except Exception as e:
            msg = "An error occurred while calling 'system_licensing_status_v1': {0}".format(e)
            self.log(msg, "ERROR")
            self.fail_and_exit(msg)

    def get_device_response(self, device_ip):
        """
        Retrieve device response from Cisco Catalyst Center.

        This function checks the configuration for device names, resolves them to IPs,
        and returns a list of device IPs.

        Args:
            device_ip (str): The IP address of the device to retrieve response for.

        Returns:
            list: A list of device IPs if found, otherwise an empty list.
        """
        self.log("Config data: {}".format(self.config), "DEBUG")

        if not isinstance(self.config, list) or not self.config:
            self.log("Config is empty or not a list", "ERROR")
            return []

        device_hostnames = self.config[0].get("device_name")
        self.log("Retrieved device hostnames from config: {}".format(device_hostnames), "DEBUG")

        if device_hostnames:
            device_ip_dict = self.get_device_ips_from_hostnames(device_hostnames)
            self.log("Resolved device IPs from hostnames: {}".format(device_ip_dict), "DEBUG")
            return self.get_list_from_dict_values(device_ip_dict)

        self.log("No device IPs or hostnames found, returning an empty list.", "DEBUG")
        return []

    def device_details_summmary(self, config):
        """Retrieve a summary of device license details.

        This function queries Catalyst Center for device license summary details
        using the 'device_license_summary_v1' API. It logs the request parameters,
        handles API responses, and returns the device summary.

        Args:
            config (dict): Configuration details.

        Returns:
            dict or None: API response containing device license summary, or None if an error occurs.
        """
        self.log("Summary of device details with config: {}".format(config), "INFO")
        param = {
            "limit": 500,
            "order": "asc",
            "page_number": 1
        }
        self.log("Using parameters: {}".format(param), "DEBUG")

        try:
            response = self.execute_get_request("licenses", "device_license_summary_v1", param)

            if not response:
                self.log("Empty response received for status of smart license. Params: {}".format(param), "WARNING")
                return None

            self.log("Received API response: {}".format(response), "DEBUG")
            return response

        except Exception as e:
            self.log("An error occurred while calling 'device_license_summary_v1': {}".format(e), "ERROR")
            return None

    def device_registration(self, config):
        """Register a device with Cisco Smart Licensing.

        This function registers a device with Cisco Smart Licensing using
        Catalyst Center's 'device_registration_v1' API. It retrieves the device UUID
        from `self.have`, logs request parameters, and executes the registration
        process.

        Args:
            config (dict): Configuration details.

        Returns:
            dict or None: API response on success, None if an error occurs.
        """
        self.log("Device registration with config: {}".format(config), "INFO")
        self.log("Value of 'have': {}".format(self.have), "DEBUG")

        if not isinstance(self.have, dict):
            self.log("Unexpected type for 'self.have': {}. Expected dict.".format(type(self.have)), "ERROR")
            return None

        device_uuid = self.have.get("device_uuid")
        virtual_account_name = self.have.get("virtual_account_name")

        device_uuids = [device_uuid] if isinstance(device_uuid, str) else device_uuid
        self.log("Using device_uuids: {}".format(device_uuids), "DEBUG")

        param = {
            "device_uuids": device_uuids,
            "virtual_account_name": virtual_account_name
        }
        self.log("Using parameters: {}".format(param), "DEBUG")

        try:
            response = self.execute_get_request("licenses", "device_registration_v1", param)

            if not response:
                self.log("Empty response received for device registration. Params: {}".format(param), "WARNING")
                return None

            self.log("Received API response: {}".format(response), "DEBUG")
            return response

        except Exception as e:
            msg = "An error occurred while calling 'device_registration_v1': {0}".format(e)
            self.log(msg, "ERROR")
            self.fail_and_exit(msg)

    def device_deregistration(self, config):
        """Deregister a device from Cisco Smart Licensing.

        This function removes a device from Cisco Smart Licensing using Catalyst
        Center's 'device_deregistration_v1' API. It fetches the device UUID from
        `self.have`, constructs the request parameters, and executes the
        deregistration process.

        Args:
            config (dict): Configuration details.

        Returns:
            dict or None: API response on success, None if an error occurs.
        """
        self.log("Device deregistration with config: {}".format(config), "INFO")
        device_uuid = self.have.get("device_uuid")
        param = {
            "device_uuids": device_uuid
        }
        self.log("Using parameters: {}".format(param), "DEBUG")

        try:
            response = self.execute_get_request("licenses", "device_deregistration_v1", param)

            if not response:
                self.log("Empty response received for Device deregistration. Params: {}".format(param), "WARNING")
                return None

            self.log("Received API response: {}".format(response), "DEBUG")
            return response

        except Exception as e:
            msg = "An error occurred while calling 'device_deregistration_v1': {0}".format(e)
            self.log(msg, "ERROR")
            self.set_operation_result("failed", False, msg, "ERROR").check_return_status()
            self.fail_and_exit(msg)

    def update_device_virtual_account(self, config):
        """Update a device's associated Smart Licensing account.

        This function updates the Smart Licensing association for a device using
        Catalyst Center's 'change_virtual_account_v1' API. It retrieves the Smart
        Account ID and Virtual Account Name from `self.have`, logs request
        parameters, and executes the update process.

        Args:
            config (dict): Configuration details.

        Returns:
            dict or None: API response on success, None if an error occurs.
        """
        self.log("Update virtual account with config: {}".format(config), "INFO")
        virtual_account_name = self.have.get("virtual_account_name")
        smart_account_id = self.have.get("smart_account_id")
        payload = {
            "virtual_account_name": virtual_account_name,
            "smart_account_id": smart_account_id
        }
        self.log("Using parameters: {}".format(payload), "DEBUG")

        try:
            response = self.execute_get_request("licenses", "change_virtual_account_v1", payload)

            if not response:
                self.log("Empty response received for Update virtual account. Params: {}".format(payload), "WARNING")
                return None

            self.log("Received API response: {}".format(response), "DEBUG")
            return response

        except Exception as e:
            msg = "An error occurred while calling 'change_virtual_account_v1': {0}".format(e)
            self.log(msg, "ERROR")
            self.set_operation_result("failed", False, msg, "ERROR").check_return_status()
            self.fail_and_exit(msg)

    def verify_diff_merged(self, config):
        """
        Validates the Cisco Catalyst Center configuration with the playbook details
        when state is merged (Create/Update).

        Parameters:
            config (dict): Playbook details containing license registration details.

        Returns:
            self: Updated instance with validation logs.
        """

        self.get_have(config)
        self.get_want(config)
        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.log("Desired State (want): {0}".format(self.want), "INFO")

        if not self.want.get("license_register"):
            self.log("No license registration details found in the playbook.", "WARNING")
            return self

        smart_license_registration = self.want["license_register"].get("smart_license_registration", False)
        have_smart_license = self.have.get("smart_account_name")

        if smart_license_registration and not have_smart_license:
            self.log("Smart license registration is requested but no smart account found.", "ERROR")
        elif not smart_license_registration and have_smart_license:
            self.log("Smart license registration is not requested but an existing smart account is found.", "INFO")

        virtual_account_name = self.want["license_register"].get("virtual_account_name")
        have_virtual_account = self.have.get("virtual_account_name")

        if virtual_account_name and not have_virtual_account:
            self.log(f"Virtual account '{virtual_account_name}' not found in existing configuration.", "ERROR")
        elif not virtual_account_name and have_virtual_account:
            self.log(f"Existing virtual account '{have_virtual_account}' is present but not defined in the playbook.", "INFO")

        device_registration = self.want["license_register"].get("device_registration", False)
        have_device_name = self.have.get("device_name")

        if device_registration and not have_device_name:
            self.log("Device registration is requested but no matching device found.", "ERROR")
        elif not device_registration and have_device_name:
            self.log(f"Device '{have_device_name}' is already registered but not requested in the playbook.", "INFO")

        self.log("Validation completed for get_diff_merged.", "INFO")
        return self

    def get_diff_merged(self, config):
        """Manage Smart License registration status and device registration.

        This function checks the current Smart Licensing registration status using
        `smart_license_status()`. Based on the retrieved status, it determines whether
        to register or deregister the device from Cisco Smart Licensing.

        Args:
            config (dict): Configuration containing the expected license registration state.

        Returns:
            None
        """
        self.log("Starting the get_diff_merged process.", "INFO")

        registration_status = self.have.get("registration_status")
        if not registration_status:
            self.log("No registration status found in self.have. Fetching it again.", "WARNING")
            self.get_have(config)
            registration_status = self.have.get("registration_status")

        self.log("Current registration status: {}".format(registration_status), "INFO")

        smart_license_registration = config.get("smart_license_registration")
        if not smart_license_registration and registration_status == "REGISTERED":
            self.log("Smart license registration is False, but the license is currently REGISTERED. Deregistering...", "INFO")
            self.smart_license_deregistration(config)
        elif smart_license_registration and registration_status == "UNREGISTERED":
            self.log("Smart license registration is True, but the license is currently UNREGISTERED. Registering...", "INFO")
            self.smart_license_registration(config)
        elif not smart_license_registration and registration_status == "UNREGISTERED":
            self.log("Smart license registration is False, and the license is already UNREGISTERED.", "INFO")
        elif smart_license_registration and registration_status == "REGISTERED":
            self.log("Smart license registration is True, and the license is already REGISTERED.", "INFO")
        else:
            self.log("Unexpected condition: smart_license_registration={}, registration_status={}".
                     format(smart_license_registration, registration_status), "WARNING")

        software_version = self.have.get("software_version")
        if software_version == "17.3.2":
            self.log("Device software version {} is 17.3.2 or higher. This version is not compatible for registration.".format(software_version), "ERROR")
            raise ValueError("Device software version {} is not compatible for registration.".format(software_version))

        device_registration = self.have.get("registration_status")

        if device_registration is False and registration_status == "REGISTERED":
            self.log("Device registration is False, but the device is currently REGISTERED. Deregistering...", "INFO")
            self.device_deregistration(config)

        elif device_registration is True and registration_status == "UNREGISTERED":
            self.log("Device registration is True, but the device is currently DEREGISTERED. Registering...", "INFO")
            self.device_registration(config)

        elif device_registration is False and registration_status == "UNREGISTERED":
            self.log("Device registration is False, and the device is already DEREGISTERED.", "INFO")

        elif device_registration is True and registration_status == "REGISTERED":
            self.log("Device registration is True, and the device is already REGISTERED.", "INFO")

        self.log("Completed the get_diff_merged process.", "INFO")

    def final_response_message(self, state):
        """
        Generate the final log message summarizing the license registration process.

        Parameters:
            state (str): The operation state ('merged' for registration).

        Returns:
            None: Logs the final status and sets the operation result.
        """
        if state == "merged":
            if (self.registered and self.not_registered) or (self.registered and not self.not_registered):
                self.msg = "Smart License registration completed successfully for: {0}.".format(
                    str(self.registered)
                )
                if self.not_registered:
                    self.msg += "Registration failed for the following devices: {0}.".format(
                        self.not_registered
                    )
                self.log(self.msg, "INFO")
                self.set_operation_result("success", True, self.msg, "INFO", self.registered).check_return_status()
            elif not self.registered and not self.not_registered:
                self.msg = "No changes required. License registration status is already as expected."
                self.log(self.msg, "INFO")
                self.set_operation_result("success", False, self.msg, "INFO").check_return_status()
            else:
                self.msg = "Failed to register the following devices: {0}.".format(str(self.not_registered))
                self.log(self.msg, "ERROR")
                self.set_operation_result("failed", False, self.msg, "ERROR", self.not_registered).check_return_status()


def main():
    """ main entry point for module execution
    """

    element_spec = {'dnac_host': {'required': True, 'type': 'str'},
                    'dnac_port': {'type': 'str', 'default': '443'},
                    'dnac_username': {'type': 'str', 'default': 'admin', 'aliases': ['user']},
                    'dnac_password': {'type': 'str', 'no_log': True},
                    'dnac_verify': {'type': 'bool', 'default': 'True'},
                    'dnac_version': {'type': 'str', 'default': '2.2.3.3'},
                    'dnac_debug': {'type': 'bool', 'default': False},
                    'dnac_log_level': {'type': 'str', 'default': 'WARNING'},
                    "dnac_log_file_path": {"type": 'str', "default": 'dnac.log'},
                    "dnac_log_append": {"type": 'bool', "default": True},
                    'dnac_log': {'type': 'bool', 'default': False},
                    'validate_response_schema': {'type': 'bool', 'default': True},
                    'config_verify': {'type': 'bool', "default": False},
                    'dnac_api_task_timeout': {'type': 'int', "default": 1200},
                    'dnac_task_poll_interval': {'type': 'int', "default": 2},
                    'config': {'required': True, 'type': 'list', 'elements': 'dict'},
                    'state': {'default': 'merged', 'choices': ['merged', 'deleted']}
                    }

    module = AnsibleModule(argument_spec=element_spec,
                           supports_check_mode=False)

    ccc_license = License(module)
    state = ccc_license.params.get("state")

    current_version = ccc_license.get_ccc_version()
    required_version = "2.3.7.9"

    if ccc_license.compare_dnac_versions(current_version, required_version) < 0:
        ccc_license.status = "failed"
        ccc_license.msg = (
            "The specified version '{0}' does not support the license workflow workflow feature. "
            "Supported versions start from '{1}' onwards.".format(current_version, required_version)
        )
        ccc_license.log(ccc_license.msg, "ERROR")
        ccc_license.check_return_status()

    if state not in ccc_license.supported_states:
        ccc_license.status = "invalid"
        ccc_license.msg = "State {0} is invalid".format(state)
        ccc_license.check_return_status()

    ccc_license.validate_input().check_return_status()
    # config_verify = ccc_license.params.get("config_verify")
    ccc_license.validate_license_input_data(ccc_license.validated_config)

    for config in ccc_license.validated_config:
        ccc_license.reset_values()
        ccc_license.get_want(config).check_return_status()
        ccc_license.get_have(config).check_return_status()
        ccc_license.get_diff_merged(config)
        # ccc_license.get_diff_state_apply[state](config).check_return_status()
        # if config_verify:
        #     ccc_license.verify_diff_state_apply[state](config).check_return_status()

    # ccc_license.update_site_messages().check_return_status()

    module.exit_json(**ccc_license.result)


if __name__ == '__main__':
    main()
