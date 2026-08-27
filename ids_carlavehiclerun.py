#!/usr/bin/env python3
"""
carlavehicle.py
A lightweight CARLA client that runs a behaviour agent, samples vehicle state,
encodes CAN messages via cantools DB (you can re-use your message objects),
and sends newline-delimited JSON to the server.

This script also optionally spawns an attacker terminal (attacker.sh).
"""

import carla
import time
import socket
import json
import threading
import subprocess
import argparse
import cantools
import os
import sys
import random
import pygame
import numpy as np


try:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/carla')
except IndexError:
    pass
    
from agents.navigation.behavior_agent import BehaviorAgent


# ================= CONFIG =================
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000
DB_FILE = "bmw.dbc"
ATTACKER_CMD = ['gnome-terminal', '--', 'bash', '-ic', './ids_attacker2.sh; exec bash']
SEND_INTERVAL = 0.2

WIDTH = 800
HEIGHT = 600

# =========================================
def load_db():
    if os.path.exists(DB_FILE):
        return cantools.database.load_file(DB_FILE)
    return None

# ================= IDS LISTENER =================
def listen_for_ids_alert(world, vehicle):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 5005))

    print("[CARLA] Listening IDS alerts...")
    while True:
        data, _ = sock.recvfrom(1024)
        msg = data.decode().strip()
        print(f"[IDS ALERT] {msg}")

# ================= CAMERA =================
def camera_callback(image, display_surface):
    array = np.frombuffer(image.raw_data, dtype=np.uint8)
    array = array.reshape((image.height, image.width, 4))
    array = array[:, :, :3]
    array = array[:, :, ::-1]

    surface = pygame.surfarray.make_surface(array.swapaxes(0, 1))
    display_surface.blit(surface, (0, 0))
    pygame.display.update()

# ================= SOCKET =================
def connect_to_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_HOST, SERVER_PORT))
    return s
    
# ================= ATTACKER =================    
def spawn_attacker():
    try:
        subprocess.Popen(ATTACKER_CMD)
        print("[carla] attacker launched")
    except Exception as e:
        print("[carla] failed to launch attacker:", e)    


def recover_vehicle(vehicle, spawn_points):
    print("[carla] Recovering vehicle...")
    
    new_spawn = random.choice(spawn_points)
    vehicle.set_transform(new_spawn)
    
    vehicle.set_target_velocity(carla.Vector3D(0, 0, 0))
    vehicle.set_target_angular_velocity(carla.Vector3D(0, 0, 0))

    time.sleep(0.2)
        
    
class SimpleVehicleDumper:
    def __init__(self, client_sock, db):
        self.sock = client_sock
        self.db = db
        # reuse your message lookups (names from your earlier code)
        
        if db:
            try:
                self.enginedata_message = db.get_message_by_name('EngineData')
                self.handbrake_message = db.get_message_by_name('InstrumentHandBrake')
                self.steering_message = db.get_message_by_name('SteeringWheelAngle')
                self.gear_message = db.get_message_by_name('GearSelectorSwitch')
            except Exception as e:
                print("[carla] message lookup error:", e)
                self.enginedata_message = None
        else:
            self.enginedata_message = None

    def send_json(self, obj):
        line = (json.dumps(obj) + "\n").encode("utf-8")
        try:
            self.sock.sendall(line)
        except Exception as e:
            print("[carla] send error:", e)

    def dump_throttle(self, control, speed):
        data = self.enginedata_message.encode({
            'VehicleSpeed': speed,
            'MovingForward': control.throttle,
            'MovingReverse': control.reverse,
            'BrakePressed': control.brake,
            'Brake_active': 1 if control.brake > 0 else 0,
            'Damping_rate_full_throttle': 0.15,
            'Damping_rate_zero_throttle_clutch_engaged': 2.0,
            'Damping_rate_zero_throttle_clutch_disengaged': 0.35,
            'Checksum_416': 0
        })
        data = bytearray(data)
        data[7] = sum(data[:7]) % 256
        
        payload_hex = data.hex()                
        can_id = self.enginedata_message.frame_id        
        msg = { "timestamp": time.time(), "can_id": can_id, "payload_hex": payload_hex, "label":"benign", "attack_type":"", "attack_id":"",}
        self.send_json(msg)

    def dump_handbrake(self, control, speed):    
        #data = self.handbrake_message.encode({'HandbrakeActive': control.hand_brake, 'Checksum':0})        
        data = self.handbrake_message.encode({'VehicleSpeed': speed, 'HandbrakeActive': control.brake, 'Checksum':0})        
        data = bytearray(data)
        data[7] = sum(data[:7]) % 256
        
        payload_hex = data.hex()
        can_id = self.handbrake_message.frame_id        
        msg = {"timestamp": time.time(), "can_id": can_id, "payload_hex": payload_hex, "label":"benign", "attack_type":"", "attack_id":""}
        self.send_json(msg)
        #if speed != 0:
        #    print(f"[DEBUG] Vehicle is moving with speed = {speed}")
    
    def dump_steering(self, control, vehicle):
        yaw = vehicle.get_transform().rotation.yaw
        yaw_normalized = yaw / 180.0   # → [-1, 1]
        #data = self.steering_message.encode({'SteeringPosition': control.steer,
        #                                    'FrontWheel': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.Front_Wheel)),
        #                                    'BackWheel': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.Back_Wheel)),
        #                                    'SteeringWheelFL': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.FL_Wheel)),
        #                                    'SteeringWheelFR': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.FR_Wheel)),
        #                                    'SteeringWheelBL': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.BL_Wheel)),
        #                                    'SteeringWheelBR': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.BR_Wheel)),
        #                                    'Checksum_416': 0})
        data = self.steering_message.encode({'SteeringPosition': control.steer,
                                            'FrontWheel': yaw_normalized,
                                            'BackWheel': vehicle.get_transform().rotation.pitch,
                                            'SteeringWheelFL': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.FL_Wheel)),
                                            'SteeringWheelFR': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.FR_Wheel)),
                                            'SteeringWheelBL': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.BL_Wheel)),
                                            'SteeringWheelBR': float(vehicle.get_wheel_steer_angle(carla.VehicleWheelLocation.BR_Wheel)),
                                            'Checksum_416': 0})                                    
        data = bytearray(data)
        data[7] = sum(data[:7]) % 256
        
        payload_hex = data.hex()
        can_id = self.steering_message.frame_id       
        msg = {"timestamp": time.time(), "can_id": can_id, "payload_hex": payload_hex, "label":"benign", "attack_type":"", "attack_id":""}
        self.send_json(msg)
        

    def dump_gear(self, control):        
        manual_flag = 0 if control.manual_gear_shift else 1
        data = self.gear_message.encode({'ManualGear': manual_flag,
                                        'AutoGear': manual_flag,
                                        'GearSwitchTime': 0.5,
                                        'Ratio': 1.0,
                                        'DownRatio': 0.5,
                                        'UpRatio': 0.65,
                                        'GearState': control.gear,
                                        'Checksum': 0 })
        data = bytearray(data); 
        data[7] = sum(data[:7]) % 256
        
        payload_hex = data.hex(); 
        can_id = self.gear_message.frame_id            
        msg = {"timestamp": time.time(), "can_id": can_id, "payload_hex": payload_hex, "label":"benign", "attack_type":"", "attack_id":""}
        self.send_json(msg)




def run_carla_loop(args):
    pygame.init()
    display = pygame.display.set_mode((WIDTH, HEIGHT))
    pygame.display.set_caption("CARLA View")
    tick_counter = 0
    client = carla.Client(args.host, args.port)
    client.set_timeout(20.0)
    world = client.get_world()
    blueprint_library = world.get_blueprint_library()
    #carla.TrafficLight.set_state(Green)
    for actor in world.get_actors():
        if 'traffic_light' in actor.type_id:
            actor.set_state(carla.TrafficLightState.Green)
            actor.freeze(True)

    # ========= SPAWN =========
    bp = blueprint_library.filter('vehicle.*')[0]
    spawn_points = world.get_map().get_spawn_points()
    vehicle = world.spawn_actor(bp, random.choice(spawn_points))
    print(f"[carla] spawned vehicle id={vehicle.id}")

    # ========= AGENT =========
    agent = BehaviorAgent(vehicle, behavior='normal')
    agent.set_destination(random.choice(spawn_points).location)

    # ========= CAMERA =========
    camera_bp = blueprint_library.find('sensor.camera.rgb')
    camera_bp.set_attribute('image_size_x', str(WIDTH))
    camera_bp.set_attribute('image_size_y', str(HEIGHT))
    camera_bp.set_attribute('fov', '110')
    camera = world.spawn_actor(camera_bp,carla.Transform(carla.Location(x=-5, z=2.5), carla.Rotation(pitch=-10)),attach_to=vehicle)
    camera.listen(lambda image: camera_callback(image, display))

    # ========= COLLISION SENSOR =========
    collision_flag = {"hit": False, "last_time": 0}
    collision_bp = blueprint_library.find('sensor.other.collision')
    collision_sensor = world.spawn_actor(collision_bp, carla.Transform(), attach_to=vehicle)
    def collision_callback(event):
        now = time.time()
        # prevent spam (0.5s cooldown)
        if now - collision_flag["last_time"] > 0.5:
            print("[CARLA] Collision detected!")
            collision_flag["hit"] = True
            collision_flag["last_time"] = now
    collision_sensor.listen(collision_callback)

    # ========= IDS =========
    threading.Thread(target=listen_for_ids_alert, args=(world, vehicle), daemon=True).start()
    sock = connect_to_server()
    db = load_db()
    dumper = SimpleVehicleDumper(sock, db)
    if args.attacker:
        spawn_attacker()

    # ========= RECOVERY =========
    def recover_vehicle(error):
        nonlocal agent
        print(f"[carla] Recovering due to: {error}")
        new_spawn = random.choice(spawn_points)
        vehicle.set_simulate_physics(False)
        vehicle.set_transform(new_spawn)
        time.sleep(0.3)
        vehicle.set_simulate_physics(True)
        # reset physics properly
        vehicle.set_target_velocity(carla.Vector3D(0, 0, 0))
        vehicle.set_target_angular_velocity(carla.Vector3D(0, 0, 0))
        # reset agent (VERY IMPORTANT)
        agent = BehaviorAgent(vehicle, behavior='normal')
        agent.set_target_speed(80)  # km/h
        agent.set_destination(random.choice(spawn_points).location)
        if "is_junction" in str(error):
            print("[ATTACK EFFECT] Agent lost road reference")
        time.sleep(0.2)

    # ========= LOOP =========
    try:
        while True:

            # ===== pygame =====
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    return

            # ===== collision recovery =====
            if collision_flag["hit"]:
                recover_vehicle("collision")
                collision_flag["hit"] = False
                time.sleep(0.2)  # prevent immediate retrigger
                continue

            try:
                # ===== CONTROL =====
                control = agent.run_step()
                vehicle.apply_control(control)

                # reroute if destination reached
                if agent.done():
                    agent.set_destination(random.choice(spawn_points).location)

                # ===== SPEED =====
                vel = vehicle.get_velocity()
                speed = (vel.x**2 + vel.y**2 + vel.z**2) ** 0.5 * 3.6
                tick_counter += 1
                if tick_counter % 10 == 0:
                    print(f"[SPEED] {int(speed)} km/h")
                    
                # ===== DUMP =====
                dumper.dump_throttle(control, int(speed))
                dumper.dump_steering(control, vehicle)
                dumper.dump_handbrake(control, int(speed))
                dumper.dump_gear(control)

            except Exception as e:
                print(f"[carla] Loop error: {e}")
                recover_vehicle(e)
                continue

            time.sleep(SEND_INTERVAL)

    finally:
        print("[carla] cleanup")

        try:
            sock.close()
        except:
            pass

        try:
            camera.stop()
            camera.destroy()
        except:
            pass

        try:
            collision_sensor.stop()
            collision_sensor.destroy()
        except:
            pass

        try:
            vehicle.destroy()
        except:
            pass

        pygame.quit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="192.168.160.1")
    parser.add_argument("--port", type=int, default=2000)
    parser.add_argument("--attacker", action="store_true")
    args = parser.parse_args()
    run_carla_loop(args)
