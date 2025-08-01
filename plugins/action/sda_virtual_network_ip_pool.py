#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
from ansible.plugins.action import ActionBase

try:
    from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
        AnsibleArgSpecValidator,
    )
except ImportError:
    ANSIBLE_UTILS_IS_INSTALLED = False
else:
    ANSIBLE_UTILS_IS_INSTALLED = True
from ansible.errors import AnsibleActionFail
from ansible_collections.cisco.dnac.plugins.plugin_utils.dnac import (
    DNACSDK,
    dnac_argument_spec,
    dnac_compare_equality,
    get_dict_result,
)
from ansible_collections.cisco.dnac.plugins.plugin_utils.exceptions import (
    AnsibleSDAException,
)

# Get common arguments specification
argument_spec = dnac_argument_spec()
# Add arguments specific for this module
argument_spec.update(
    dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        siteNameHierarchy=dict(type="str"),
        virtualNetworkName=dict(type="str"),
        isLayer2Only=dict(type="bool"),
        ipPoolName=dict(type="str"),
        vlanId=dict(type="str"),
        vlanName=dict(type="str"),
        autoGenerateVlanName=dict(type="bool"),
        trafficType=dict(type="str"),
        scalableGroupName=dict(type="str"),
        isL2FloodingEnabled=dict(type="bool"),
        isThisCriticalPool=dict(type="bool"),
        isWirelessPool=dict(type="bool"),
        isIpDirectedBroadcast=dict(type="bool"),
        isCommonPool=dict(type="bool"),
        isBridgeModeVm=dict(type="bool"),
        poolType=dict(type="str"),
    )
)

required_if = []
required_one_of = []
mutually_exclusive = []
required_together = []


class SdaVirtualNetworkIpPool(object):
    def __init__(self, params, dnac):
        self.dnac = dnac
        self.new_object = dict(
            site_name_hierarchy=params.get("siteNameHierarchy"),
            siteNameHierarchy=params.get("siteNameHierarchy"),
            virtualNetworkName=params.get("virtualNetworkName"),
            isLayer2Only=params.get("isLayer2Only"),
            ipPoolName=params.get("ipPoolName"),
            vlanId=params.get("vlanId"),
            vlanName=params.get("vlanName"),
            autoGenerateVlanName=params.get("autoGenerateVlanName"),
            trafficType=params.get("trafficType"),
            scalableGroupName=params.get("scalableGroupName"),
            isL2FloodingEnabled=params.get("isL2FloodingEnabled"),
            isThisCriticalPool=params.get("isThisCriticalPool"),
            isWirelessPool=params.get("isWirelessPool"),
            isIpDirectedBroadcast=params.get("isIpDirectedBroadcast"),
            isCommonPool=params.get("isCommonPool"),
            isBridgeModeVm=params.get("isBridgeModeVm"),
            poolType=params.get("poolType"),
            virtual_network_name=params.get("virtualNetworkName"),
            ip_pool_name=params.get("ipPoolName"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        new_object_params["siteNameHierarchy"] = self.new_object.get(
            "site_name_hierarchy"
        )
        new_object_params["virtual_network_name"] = self.new_object.get(
            "virtualNetworkName"
        ) or self.new_object.get("virtual_network_name")
        new_object_params["ip_pool_name"] = self.new_object.get(
            "ipPoolName"
        ) or self.new_object.get("ip_pool_name")
        return new_object_params

    def create_params(self):
        new_object_params = {}
        new_object_params["siteNameHierarchy"] = self.new_object.get(
            "siteNameHierarchy"
        )
        new_object_params["virtualNetworkName"] = self.new_object.get(
            "virtualNetworkName"
        )
        new_object_params["isLayer2Only"] = self.new_object.get("isLayer2Only")
        new_object_params["ipPoolName"] = self.new_object.get("ipPoolName")
        new_object_params["vlanId"] = self.new_object.get("vlanId")
        new_object_params["vlanName"] = self.new_object.get("vlanName")
        new_object_params["autoGenerateVlanName"] = self.new_object.get(
            "autoGenerateVlanName"
        )
        new_object_params["trafficType"] = self.new_object.get("trafficType")
        new_object_params["scalableGroupName"] = self.new_object.get(
            "scalableGroupName"
        )
        new_object_params["isL2FloodingEnabled"] = self.new_object.get(
            "isL2FloodingEnabled"
        )
        new_object_params["isThisCriticalPool"] = self.new_object.get(
            "isThisCriticalPool"
        )
        new_object_params["isWirelessPool"] = self.new_object.get("isWirelessPool")
        new_object_params["isIpDirectedBroadcast"] = self.new_object.get(
            "isIpDirectedBroadcast"
        )
        new_object_params["isCommonPool"] = self.new_object.get("isCommonPool")
        new_object_params["isBridgeModeVm"] = self.new_object.get("isBridgeModeVm")
        new_object_params["poolType"] = self.new_object.get("poolType")
        return new_object_params

    def delete_all_params(self):
        new_object_params = {}
        new_object_params["siteNameHierarchy"] = self.new_object.get(
            "site_name_hierarchy"
        )
        new_object_params["site_name_hierarchy"] = self.new_object.get(
            "site_name_hierarchy"
        )
        new_object_params["virtual_network_name"] = self.new_object.get(
            "virtual_network_name"
        )
        new_object_params["ip_pool_name"] = self.new_object.get("ip_pool_name")
        return new_object_params

    def get_object_by_name(self, name, is_absent=False):
        result = None
        # NOTE: Does not have a get by name method, using get all
        try:
            items = self.dnac.exec(
                family="sda",
                function="get_ip_pool_from_sda_virtual_network",
                params=self.get_all_params(name=name),
            )
            if isinstance(items, dict):
                if "response" in items:
                    items = items.get("response")
                if isinstance(items, dict) and items.get("status") == "failed":
                    if is_absent:
                        raise AnsibleSDAException(response=items)
                    result = None
                    return result
            result = get_dict_result(items, "name", name)
        except Exception:
            if is_absent:
                raise
            result = None
        return result

    def get_object_by_id(self, id):
        result = None
        # NOTE: Does not have a get by id method or it is in another action
        return result

    def exists(self, is_absent=False):
        name = self.new_object.get("name")
        prev_obj = self.get_object_by_name(name, is_absent=is_absent)
        it_exists = (
            prev_obj is not None
            and isinstance(prev_obj, dict)
            and prev_obj.get("status") != "failed"
        )
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("siteNameHierarchy", "siteNameHierarchy"),
            ("virtualNetworkName", "virtualNetworkName"),
            ("isLayer2Only", "isLayer2Only"),
            ("ipPoolName", "ipPoolName"),
            ("vlanId", "vlanId"),
            ("vlanName", "vlanName"),
            ("autoGenerateVlanName", "autoGenerateVlanName"),
            ("trafficType", "trafficType"),
            ("scalableGroupName", "scalableGroupName"),
            ("isL2FloodingEnabled", "isL2FloodingEnabled"),
            ("isThisCriticalPool", "isThisCriticalPool"),
            ("isWirelessPool", "isWirelessPool"),
            ("isIpDirectedBroadcast", "isIpDirectedBroadcast"),
            ("isCommonPool", "isCommonPool"),
            ("isBridgeModeVm", "isBridgeModeVm"),
            ("poolType", "poolType"),
            ("siteNameHierarchy", "site_name_hierarchy"),
            ("virtualNetworkName", "virtual_network_name"),
            ("ipPoolName", "ip_pool_name"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(
            not dnac_compare_equality(
                current_obj.get(dnac_param), requested_obj.get(ansible_param)
            )
            for (dnac_param, ansible_param) in obj_params
        )

    def create(self):
        result = self.dnac.exec(
            family="sda",
            function="add_ip_pool_in_sda_virtual_network",
            params=self.create_params(),
            op_modifies=True,
        )
        if isinstance(result, dict):
            if "response" in result:
                result = result.get("response")
            if isinstance(result, dict) and result.get("status") == "failed":
                raise AnsibleSDAException(response=result)
        return result

    def delete(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        result = self.dnac.exec(
            family="sda",
            function="delete_ip_pool_from_sda_virtual_network",
            params=self.delete_all_params(),
        )
        return result


class ActionModule(ActionBase):
    def __init__(self, *args, **kwargs):
        if not ANSIBLE_UTILS_IS_INSTALLED:
            raise AnsibleActionFail(
                "ansible.utils is not installed. Execute 'ansible-galaxy collection install ansible.utils'"
            )
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_async = False
        self._supports_check_mode = False
        self._result = None

    # Checks the supplied parameters against the argument spec for this module
    def _check_argspec(self):
        aav = AnsibleArgSpecValidator(
            data=self._task.args,
            schema=dict(argument_spec=argument_spec),
            schema_format="argspec",
            schema_conditionals=dict(
                required_if=required_if,
                required_one_of=required_one_of,
                mutually_exclusive=mutually_exclusive,
                required_together=required_together,
            ),
            name=self._task.action,
        )
        valid, errors, self._task.args = aav.validate()
        if not valid:
            raise AnsibleActionFail(errors)

    def run(self, tmp=None, task_vars=None):
        self._task.diff = False
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._result["changed"] = False
        self._check_argspec()

        dnac = DNACSDK(self._task.args)
        obj = SdaVirtualNetworkIpPool(self._task.args, dnac)

        state = self._task.args.get("state")

        response = None
        if state == "present":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                if obj.requires_update(prev_obj):
                    response = prev_obj
                    dnac.object_present_and_different()
                else:
                    response = prev_obj
                    dnac.object_already_present()
            else:
                try:
                    response = obj.create()
                    dnac.object_created()
                except AnsibleSDAException as e:
                    dnac.fail_json("Could not create object {e}".format(e=e._response))
        elif state == "absent":
            try:
                (obj_exists, prev_obj) = obj.exists(is_absent=True)
                if obj_exists:
                    response = obj.delete()
                    dnac.object_deleted()
                else:
                    dnac.object_already_absent()
            except AnsibleSDAException as e:
                dnac.fail_json(
                    "Could not get object to be delete {e}".format(e=e._response)
                )

        self._result.update(dict(dnac_response=response))
        self._result.update(dnac.exit_json())
        return self._result
