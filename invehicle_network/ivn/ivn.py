import json
import time
import os
import sys
import subprocess
try:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
except IndexError:
    pass
from invehicle_network.ivn.ecu import Ecu
from invehicle_network.ivn.bus import Bus
from invehicle_network.ivn.vul import Vul
from invehicle_network.protocol.carla_can_control import CAN
#from ecu import Ecu
#from bus import Bus
#from vul import Vul
#from can_define import CAN

class IVN:
    def __init__(self, ecus=None, buses=None, vuls=None):
        self.ecus = ecus if ecus else []
        self.buses = buses if buses else []
        self.vuls = vuls if vuls else []

    @staticmethod
    def load_ivn_from_json(file_path):
        with open(file_path, 'r') as json_file:
            ivn_data = json.load(json_file)

        ecus = []
        for ecu_data in ivn_data['ivn'][0]['ecu']:
            bus_data = ecu_data['bus']

            # Handle both single object and array of objects for bus
            if isinstance(bus_data, list):
                buses = [Bus(bus['name'], bus['protocol']) for bus in bus_data]
            else:
                buses = [Bus(bus_data['name'], bus_data['protocol'])]

            components = []
            for component_data in ecu_data['components']:
                services = []
                for service_data in component_data['services']:
                    vuls = [Vul(vul['name'], vul['accessvector'], vul['probability'], vul['impact']) for vul in service_data['vuls']]
                    service = Ecu.Service(service_data['name'], service_data['privilege'], service_data.get('functionality', None), service_data['connection'], vuls)
                    services.append(service)
                component = Ecu.Component(component_data['name'], component_data['os'], component_data['connection'], services)
                components.append(component)
            ecu = Ecu(ecu_data['name'], ecu_data['ecutype'], buses, components)  # Updated to pass an array of buses
            ecus.append(ecu)
        return IVN(ecus, [], [])


    def list_full_info(ivn):
        for ecu in ivn.ecus:
            print(f"\n ALL INFORMATION OF ECU {ecu.name}:")
            for component in ecu.components:
                print(f"  Component: {component.name}")
                for service in component.services:
                    print(f"    Service: {service.name}, Privilege: {service.privilege}, Functionality: {service.functionality}")
                    for vul in service.vuls:
                        print(f"     Vulnerabilities: {vul.name}, AccessVector: {vul.accessvector}")

    def list_all_ecus(ivn):
        print("All ECUs:")
        for ecu in ivn.ecus:
            print(f"  - {ecu.name}")

    def list_all_components(ivn):
        print("All Components:")
        for ecu in ivn.ecus:
            for component in ecu.components:
                print(f"  - {component.name}")

    def list_all_services(ivn):
        print("All Services:")
        for ecu in ivn.ecus:
            for component in ecu.components:
                for service in component.services:
                    print(f"  - {service.name}")

    def list_all_vulnerabilities(ivn):
        print("All Vulnerabilities:")
        for ecu in ivn.ecus:
            for component in ecu.components:
                for service in component.services:
                    for vul in service.vuls:
                        print(f"  - {vul.name}")


    def list_all_components_of_ecu(ivn, ecu_name):
        # Search for the ECU with the given name
        target_ecu = None
        for ecu in ivn.ecus:
            if ecu.name == ecu_name:
                target_ecu = ecu
                break
        if target_ecu is None:
            print(f"ECU with the name {ecu_name} not found.")
            return
        # Search for component
        print(f"\nAll Components of ECU {target_ecu.name}:")
        has_components = False
        for component in target_ecu.components:
            if component:
                print(f"  - {component.name}")
                has_components = True
        if not has_components:
            print("There is no component.")


    def list_all_services_of_ecu(ivn, ecu_name):
        # Search for the ECU with the given name
        target_ecu = None
        for ecu in ivn.ecus:
            if ecu.name == ecu_name:
                target_ecu = ecu
                break
        if target_ecu is None:
            print(f"ECU with the name {ecu_name} not found.")
            return
        # Search for service
        print(f"\nAll Services of ECU {target_ecu.name}:")
        has_services = False
        for component in target_ecu.components:
            print(f"Component {component.name}: ")
            for service in component.services:
                if service:
                    print(f"  - {service.name}")
                    has_services = True
        if not has_services:
            print("There is no service.")


    def list_all_vulnerabilities_of_ecu(ivn, ecu_name):
        # Search for the ECU with the given name
        target_ecu = None
        for ecu in ivn.ecus:
            if ecu.name == ecu_name:
                target_ecu = ecu
                break
        if target_ecu is None:
            print(f"ECU with the name {ecu_name} not found.")
            return
        # Search for vulnerability
        print(f"\nAll Vulnerabilities of ECU {target_ecu.name}:")
        has_vulnerabilities = False
        for component in target_ecu.components:
            for service in component.services:
                for vul in service.vuls:
                    if vul:
                        print(f"  - {vul.name}")
                        has_vulnerabilities = True
        if not has_vulnerabilities:
            print("There is no vulnerability.")


    def find_service(service_name, ivn):
        for ecu in ivn.ecus:
            for component in ecu.components:
                for service in component.services:
                    if service.name == service_name:
                        return service
