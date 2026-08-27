import os, sys
try:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/carla')
except IndexError:
    pass

from seccom.ivn import IVN
import threading

ivn_instance = IVN.load_ivn_from_json("ivn.json")

head_unit = next(ecu for ecu in ivn_instance.ecus if ecu.name == 'HeadUnit')
huintel = next(comp for comp in head_unit.components if comp.name == 'huintel')
api_control = next(service for service in huintel.services if service.name == 'api_ctr')

api_control.app.run(host='0.0.0.0', port=6667)
