# !/home/vel/miniforge3/envs/carlasec/bin/python
# This file can be run with python=3.8 and carla=0.9.14

# [11.05.2025] - [guhnn] - [ziz0301@gmail.com]
# This work pertains to a PhD project on vehicle security modeling.

# This class allows the Carla vehicle to connect with the CANBUS and dump/receive messages from it.
# The CAN message structure is taken from the bmw_e9x_e8x.dbc - commaai/opendbc
# Using WheelSpeeds, EngineAndBrake, SteeringWheelAngle, Speed, Door, Light, Gear

import threading
import queue
import time
import can
import cantools
import carla
import random
import csv


can_queue = queue.PriorityQueue()
class CAN():
    def __init__(self):
        self.db = cantools.database.load_file('bmw.dbc') # Define CAN-message format

        #Define CAN message by name
        self.door_message = self.db.get_message_by_name('DoorControlSensors')
        self.light_message = self.db.get_message_by_name('LightControl')
        self.wheelspeed_message = self.db.get_message_by_name('WheelSpeeds')
        self.enginedata_message = self.db.get_message_by_name('EngineData')
        self.handbrake_message = self.db.get_message_by_name('InstrumentHandBrake')
        self.steering_message = self.db.get_message_by_name('SteeringWheelAngle')
        self.gear_message = self.db.get_message_by_name('GearSelectorSwitch')
        self.gear_message_test = self.db.get_message_by_name('TransmissionData')
        self.log_only = False
        self._log_lock = threading.Lock()
        self._vcan0_bus = can.interface.Bus(channel='vcan0', interface='socketcan')
        
        
        #print("[INFO] CAN frame IDs:")
        #print(f"WheelSpeed: {hex(self.wheelspeed_message.frame_id)}")
        #print(f"Door: {hex(self.door_message.frame_id)}")
        #print(f"Light: {hex(self.light_message.frame_id)}")
        #print(f"EngineData: {hex(self.enginedata_message.frame_id)}")
        #print(f"Steering: {hex(self.steering_message.frame_id)}")
        #print(f"HandBrake: {hex(self.handbrake_message.frame_id)}")
        #print(f"Gear: {hex(self.gear_message.frame_id)}")
        #print(f"GearTest: {hex(self.gear_message_test.frame_id)}")


    #---------------------------------------------------------
    # FUNCTIONS FOR DEFINEDING AND DUMPING CAN MESSAGES
    #---------------------------------------------------------

    # Define and dump wheelspeed message
    def dump_wheelspeed(self,speed):        
        data = self.wheelspeed_message.encode({'Wheel_FL': speed,'Wheel_FR':speed, 'Wheel_RL':speed, 'Wheel_RR': speed})
        message = can.Message(arbitration_id=self.wheelspeed_message.frame_id, data=data, timestamp=time.time())
        
        self._log_message(message)
        if not self.log_only:
            with can.interface.Bus(bustype='socketcan', channel='kcan4') as kcan4:
                kcan4.send(message)

    # Define and dump door message
    def dump_door(self,world, trunk=0, mirror=2, checksum=0):        
        door_open = world.doors_are_open
        data = self.door_message.encode({'Door_FL': int(door_open),
                                         'Door_FR': int(door_open),
                                         'Door_RL': int(door_open),
                                         'Door_RR': int(door_open),
                                         'TrunkStatus': trunk,
                                         'MirrorStatus': mirror,
                                         'Checksum_416': checksum})
        message = can.Message(arbitration_id=self.door_message.frame_id, data=data, timestamp=time.time())
        
        self._log_message(message)
        if not self.log_only:
            with can.interface.Bus(bustype='socketcan', channel='kcan4') as kcan4:
                kcan4.send(message)

    # Define and dump light message
    def dump_light(self, vehicle):
        light_none, light_lowbeam, light_highbeam, light_reverse = False, False, False, False
        light_brake, light_rightblinker, light_leftblinker, light_fog = False, False, False, False
        light_interior, light_special1, light_special2= False, False, False                
        light_state = vehicle.get_light_state()
        #print(f"Light State: {light_state}")
        if light_state == carla.VehicleLightState.NONE:
            light_none = True
        elif light_state == carla.libcarla.VehicleLightState(3):
            light_lowbeam = True
        elif light_state == carla.VehicleLightState.HighBeam:
            light_highbeam = True
        elif light_state == carla.VehicleLightState.Reverse:
            light_reverse = True
        elif light_state == carla.VehicleLightState.Brake:
            light_brake = True
        elif light_state == carla.VehicleLightState.RightBlinker:
            light_rightblinker = True
        elif light_state == carla.VehicleLightState.LeftBlinker:
            light_leftblinker = True
        elif light_state == carla.VehicleLightState.Fog:
            light_fog = True
        elif light_state == carla.VehicleLightState.Interior:
            light_interior = True
        elif light_state == carla.VehicleLightState.Special1:
            light_special1 = True
        elif light_state == carla.VehicleLightState.Special2:
            light_special2 = True
            
        data = self.light_message.encode({'LowBeam':int(light_lowbeam),'HighBeam':int(light_highbeam), 'Reverse':int(light_reverse), 'LightOff':int(light_none), 'Brake':int(light_brake), 'RightBlinker':int(light_rightblinker), 'LeftBlinker':int(light_leftblinker), 'Fog':int(light_fog), 'Interior':int(light_interior), 'Special1':int(light_special1), 'Special2':int(light_special2)})
        message = can.Message(arbitration_id=self.light_message.frame_id, data=data, timestamp=time.time())
        
        
        self._log_message(message)
        if not self.log_only:
            with can.interface.Bus(bustype='socketcan', channel='kcan4') as kcan4:
                kcan4.send(message)

    # Define and dump throttle message
    def dump_throttle(self, control, speed, checksum=0):        
        brake_value = control.brake
        brake_flag = 1 if brake_value > 0.0 else 0
        encoded_data = bytearray(self.enginedata_message.encode({
            'VehicleSpeed': speed,
            'MovingForward': control.throttle,
            'MovingReverse': control.reverse,
            'BrakePressed': brake_value,
            'Brake_active': brake_flag,
            'Damping_rate_full_throttle': 0.15,
            'Damping_rate_zero_throttle_clutch_engaged': 2.0,
            'Damping_rate_zero_throttle_clutch_disengaged': 0.35, 
            'Checksum_416': 0  
        }))
        data = bytearray(encoded_data)
        checksum = sum(data[:7]) % 256
        data[7] = checksum        
        message = can.Message(arbitration_id=self.enginedata_message.frame_id, data=data, timestamp=time.time())
        
        self._log_message(message)
        self._vcan0_bus.send(message)
        if not self.log_only:
            self._vcan0_bus.send(message)


    # Define and dump hand brake message
    def dump_handbrake(self, control, speed, checksum=0):    
        data = self.handbrake_message.encode({'VehicleSpeed': speed, 'HandbrakeActive':control.hand_brake,'Checksum': checksum})
        message = can.Message(arbitration_id=self.handbrake_message.frame_id, data=data, timestamp=time.time())
        
        self._log_message(message)
        self._vcan0_bus.send(message)
        if not self.log_only:
            self._vcan0_bus.send(message)


    # Define and dump steer message
    def dump_steering(self, control, vehicle, speed, checksum=0):    
        yaw = vehicle.get_transform().rotation.yaw
        yaw_normalized = yaw / 180.0   # → [-1, 1]
        #encoded = self.steering_message.encode({'SteeringPosition': control.steer,
        #                                    'FrontWheel': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.Front_Wheel)),
        #                                    'BackWheel': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.Back_Wheel)),
        #                                    'SteeringWheelFL': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.FL_Wheel)),
        #                                    'SteeringWheelFR': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.FR_Wheel)),
        #                                    'SteeringWheelBL': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.BL_Wheel)),
        #                                    'SteeringWheelBR': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.BR_Wheel)),
        #                                     'Checksum_416': checksum})   
        data = self.steering_message.encode({'SteeringPosition': control.steer,
                                            'FrontWheel': yaw_normalized,
                                            'BackWheel': vehicle.get_transform().rotation.pitch,
                                            'SteeringWheelFL': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.FL_Wheel)),
                                            'SteeringWheelFR': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.FR_Wheel)),
                                            'SteeringWheelBL': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.BL_Wheel)),
                                            'SteeringWheelBR': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.BR_Wheel)),
                                            'Checksum_416': 0})       
        data = bytearray(encoded)
        checksum = sum(data[:7]) % 256 
        data[7] = checksum  # Set byte 7 with calculated checksum
        message = can.Message(arbitration_id=self.steering_message.frame_id, data=data, timestamp=time.time())  
        
        self._log_message(message)
        self._vcan0_bus.send(message)
        if not self.log_only:
            self._vcan0_bus.send(message)


    # Define and dump gear message
    def dump_gear(self, control):        
        manual_flag = 0 if control.manual_gear_shift else 1            
        encoded_data = self.gear_message.encode({
                'ManualGear': manual_flag,
                'AutoGear': manual_flag,
            'GearSwitchTime': 0.5,
            'Ratio': 1.0,
            'DownRatio': 0.5,
            'UpRatio': 0.65,
            'GearState': control.gear,
            'Checksum': 0  # placeholder
        })
        data = bytearray(encoded_data)
        checksum = sum(data[:7]) % 256
        data[7] = checksum 
        message = can.Message(arbitration_id=self.gear_message.frame_id, data=data, timestamp=time.time())
        
        self._log_message(message)
        self._vcan0_bus.send(message)
        if not self.log_only:
            self._vcan0_bus.send(message)



    def dump_gear_test(self, control, checksum=0):        
        data = self.gear_message_test.encode({'GearTar': -1})
        message = can.Message(arbitration_id=self.gear_message_test.frame_id, data=data, timestamp=time.time())
        
        self._log_message(message)
        self._vcan0_bus.send(message)
        if not self.log_only:
            self._vcan0_bus.send(message)

    
    #Helper function for log-only
    def _log_message(self, msg, label="benign", attack_type="", attack_id=""):
        # Prepare CSV row
        row = [
            getattr(msg, "timestamp", None),               # timestamp
            hex(msg.arbitration_id),     # CAN ID
            msg.dlc,                     # data length
            msg.data.hex()               # raw payload
        ]
        # Append label info
        row += [label, attack_type, attack_id]
        # at end of _log_message, instead of direct open(...)
        with self._log_lock:
            with open("can_sniff_log.csv", "a", newline='') as f:
                csv.writer(f).writerow(row)


    #---------------------------------------------------------
    # FUNCTIONS FOR CONVERT CAN MESSAGE TO CARLA.VEHICLE.CONTROL
    #---------------------------------------------------------

    # Convert WheelSpeed message to carla vehicle
    def control_wheelspeed(self,velocity):
        kcan4 = can.interface.Bus(bustype='socketcan', channel='vcan0')
        print("KCAN4 is listening")
        while True:
            try:
                msg = kcan4.recv()
                if msg is not None:
                    data = self.wheelspeed_message.decode(msg.data)
                    self.can_speed = data.get("Wheel_FL")
                    print(data)
                    return self.can_speed
                else:
                    return velocity
            except Exception as e:
                print(f"Exception in CAN Bus Listener: {e}")

    # Convert door message to carla vehicle
    def control_door(self, vehicle, msg):
        #can_queue.put((msg.arbitration_id, msg))
        data = self.door_message.decode(msg.data)
        print (f"data: {data}")
        if data.get("Door_FL") == 1 and data.get("Door_RL") == 1 and data.get("Door_FR") == 1 and data.get("Door_RR") == 1:
            print ("Door Open")
            return vehicle.open_door(carla.VehicleDoor.All)
        if data.get("Door_FL") == 0 and data.get("Door_RL") == 0 and data.get("Door_FR") == 0 and data.get("Door_RR") == 0:
            print (vehicle)
            return vehicle.close_door(carla.VehicleDoor.All)

    # Convert light message to carla vehicle
    def control_light(self, vehicle, msg):
        #can_queue.put((msg.arbitration_id, msg))
        data = self.light_message.decode(msg.data)
        if data.get("LowBeam") == 1:
            light_mask=carla.VehicleLightState.LowBeam
            return vehicle.set_light_state(carla.VehicleLightState(light_mask))
        elif data.get("HighBeam") == 1:
            light_mask=carla.VehicleLightState.HighBeam
            return vehicle.set_light_state(carla.VehicleLightState(light_mask))
        elif data.get("Reverse") == 1:
            light_mask=carla.VehicleLightState.Reverse
            return vehicle.set_light_state(carla.VehicleLightState(light_mask))
        elif data.get("LightOff") == 1:
            light_mask=carla.VehicleLightState.NONE
            return vehicle.set_light_state(carla.VehicleLightState(light_mask))

        else:
            print("ERROR")

    # Convert Throttle message to carla vehicle control
    def control_throttle(self, control, msg):
        #vcan0 = can.interface.Bus(bustype='socketcan', channel='vcan0')
        #msg = self.vcan0.recv()
        #print(f"Message information: {msg.data}")
        data = self.throttle_message.decode(msg.data)
        print(data)
        if data.get("Checksum_416") == 15:
            control.throttle = data.get("MovingForward")
            control.reverse = data.get("MovingReverse")
            control.manual_gear_shift = True
        else:
            control.manual_gear_shift = False
        #print(control)
        return control

    
    def control_enginedata_seperate(self, control, msg):
        data = self.enginedata_message.decode(msg.data)
        #print("[DEBUG] Raw engine data values:", data)
        if data.get("Checksum_416") != 0:
            moving_forward = data.get("MovingForward", 0)
            moving_reverse = data.get("MovingReverse", 0)
            brake_active = data.get("Brake_active", 0)
            brake_value = data.get("BrakePressed", 0.0)
            brake_value = max(0.0, min(brake_value, 1.0))
            
            if moving_forward == 1 and moving_reverse == 1:
                print("Conflict: Both forward and reverse set. Ignoring input.")
                return None
            if brake_active == 1:
                control.brake = brake_value
            else:
                speed = data.get("VehicleSpeed", 0)
                throttle_value = min(speed / 100.0, 1.0)
                if moving_forward == 1:
                    control.throttle = throttle_value
                    control.reverse = False
                elif moving_reverse == 1:
                    control.throttle = throttle_value
                    control.reverse = True
                else:
                    control.throttle = 0.0
                    control.reverse = False
            return control
        else:
            control.manual_gear_shift = False
            return None

    def control_steering_seperate(self, vehicle, control, msg):
        data = self.steering_message.decode(msg.data)        
        #print("[DEBUG] Raw steering control values:", data)
        if data.get("Checksum_416") != 0 :
            vehicle.set_wheel_steer_direction(carla.VehicleWheelLocation.FL_Wheel, float(data.get("SteeringWheelFL")))
            vehicle.set_wheel_steer_direction(carla.VehicleWheelLocation.FR_Wheel, float(data.get("SteeringWheelFR")))
            vehicle.set_wheel_steer_direction(carla.VehicleWheelLocation.BL_Wheel, float(data.get("SteeringWheelBL")))
            vehicle.set_wheel_steer_direction(carla.VehicleWheelLocation.BR_Wheel, float(data.get("SteeringWheelBR")))
            vehicle.set_wheel_steer_direction(carla.VehicleWheelLocation.Front_Wheel, float(data.get("FrontWheel")))
            vehicle.set_wheel_steer_direction(carla.VehicleWheelLocation.Back_Wheel, float(data.get("BackWheel")))
            control.steer = data.get("SteeringPosition")
            return control
            #return None;
        else:
            #print("No hack")
            return None
    
    #------------------------------------------------------------------------------
    # OLD FUNCTION, PUT HERE TO STORE
    # TESTING ONLY - FUNCTIONS FOR CONVERT CAN MESSAGE TO CARLA.VEHICLE.CONTROL
    # Using cansend vcan0 to test
    #-----------------------------------------------------------------------------

    # Convert Speed message to carla vehicle control seperatly - For test only

    def control_wheelspeed_seperate(self, control, msg):
        data = self.enginedata_message.decode(msg.data)

        '''
        control.throttle = data.get("MovingForward")
        control.reverse = data.get("MovingReverse")
        control.manual_gear_shift = True
        '''

        if data.get("Checksum_416") != 0 :
            print(data)
            control.throttle = data.get("MovingForward")
            control.reverse = data.get("MovingReverse")
            #control.manual_gear_shift = True
            return control
            #control_can.gear = 2
        else:
            control.manual_gear_shift = False
            #print("No hack")
            return None

        #print(control)
        #return control


    def control_gear_seperate(self, control, msg):
        data = self.gear_message.decode(msg.data)
        #print(f"Message data:{msg.data}")
        if data.get("Checksum_416") != 0 :
            #print(f"Decode data:{data}")
            control.gear = data.get("AutoGear")
            control.manual_gear_shift = data.get("ManualGear")
            return control
        else:
            #print("No hack")
            return None


    

    # Convert door message to carla vehicle control seperatly. Done, has been used for counting door open time
    def control_door_seperate1(self, vehicle, msg):
        data = self.door_message.decode(msg.data)
        if data.get("Checksum_416") != 0:
            #print(data)
            if data.get("Door_FL") == 1 and data.get("Door_RL") == 1 and data.get("Door_FR") == 1 and data.get(
                    "Door_RR") == 1:
                vehicle.open_door(carla.VehicleDoor.All)
                return 1
            if data.get("Door_FL") == 0 and data.get("Door_RL") == 0 and data.get("Door_FR") == 0 and data.get(
                    "Door_RR") == 0:
                vehicle.close_door(carla.VehicleDoor.All)
                return 0
        else:
            #print("No hack")
            return
            
            
    #while true; do cansend kcan4 000002f6#0000000000000100; done
    def control_light_seperate(self, vehicle, msg):
        data = self.light_message.decode(msg.data)
        #print("[DEBUG] Raw light control values:", data)
        light_mask = 0
        if data.get("LowBeam") == 1:
            light_mask |= carla.VehicleLightState.LowBeam
        if data.get("HighBeam") == 1:
            light_mask |= carla.VehicleLightState.HighBeam
        if data.get("Reverse") == 1:
            light_mask |= carla.VehicleLightState.Reverse
        if data.get("Brake") == 1:
            light_mask |= carla.VehicleLightState.Brake
        if data.get("RightBlinker") == 1:
            light_mask |= carla.VehicleLightState.RightBlinker
        if data.get("LeftBlinker") == 1:
            light_mask |= carla.VehicleLightState.LeftBlinker
        if data.get("Fog") == 1:
            light_mask |= carla.VehicleLightState.Fog
        if data.get("Interior") == 1:
            light_mask |= carla.VehicleLightState.Interior      

        # If LightOff is 1, override everything
        if data.get("LightOff") == 1:
            light_mask = carla.VehicleLightState.NONE

        if light_mask != 0 or data.get("LightOff") == 1:
            return vehicle.set_light_state(carla.VehicleLightState(light_mask))
        else:
            #print("ERROR sending light message: no valid bit set")
            return




    def control_wheelspeed_seperate1(self, vehicle, message):
        kcan4 = can.interface.Bus(bustype='socketcan', channel='vcan0')
        while True:
            try:
                msg = kcan4.recv()
                if msg is not None:
                    print(f"Listenner received message with CAN ID: {hex(msg.arbitration_id)}")
                    data = self.wheelspeed_message.decode(msg.data)
                    self.wheelspeed_message = data.get("Wheel_FL")
                    print(data)
                    return self.wheelspeed_message
                else:
                    print("Listener time out, no message received")
            except Exception as e:
                print(f"Exception in CAN Bus Listener: {e}")


    # Convert door message to carla vehicle control seperatly - For test only
    def control_door_seperate(self, vehicle):
        kcan4 = can.interface.Bus(bustype='socketcan', channel='kcan4')
        msg = kcan4.recv()
        data = self.door_message.decode(msg.data)
        if data.get("Door_FL") == 1 and data.get("Door_RL") == 1 and data.get("Door_FR") == 1 and data.get("Door_RR") == 1:
            print (vehicle)
            return vehicle.open_door(carla.VehicleDoor.All)
        if data.get("Door_FL") == 0 and data.get("Door_RL") == 0 and data.get("Door_FR") == 0 and data.get("Door_RR") == 0:
            print (vehicle)
            return vehicle.close_door(carla.VehicleDoor.All)

    

    # Convert Throttle message to carla vehicle control seperatly - For test only
    def control_throttle_seperate(self, control):
        vcan0 = can.interface.Bus(bustype='socketcan', channel='vcan0')
        msg = vcan0.recv()
        #print(f"Message information: {msg.data}")
        data = self.throttle_message.decode(msg.data)
        print(data)
        if data.get("Checksum_416") == 15:
            control.throttle = data.get("MovingForward")
            control.gear = data.get("MovingReverse")
            control.manual_gear_shift = True
        else:
            control.manual_gear_shift = False
        #print(control)
        return control
