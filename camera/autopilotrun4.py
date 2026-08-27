#!/usr/bin/env python3
"""
hybrid_camera_planner_video.py

Hybrid controller:
- BasicAgent (planner) => high-level steering & desired speed
- Vision lane follower => low-level steering correction
- Blend steering: steer = ALPHA*vision + (1-ALPHA)*planner
- PID throttle to follow planner target speed
- Headless MP4 export + collision logging

Run while CARLA server is up:
  python3 hybrid_camera_planner_video.py
"""
import carla
import random
import time
import queue
import math
from pathlib import Path
import numpy as np
import cv2
import os
import sys
from ultralytics import YOLO

# ==============================================================================
# -- Add PythonAPI for release mode --------------------------------------------
# ==============================================================================
try:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/../carla')
except IndexError:
    pass

try:
    from agents.navigation.basic_agent import BasicAgent
except Exception as e:
    raise SystemExit("Cannot import BasicAgent. Run script from CARLA PythonAPI examples folder or set PYTHONPATH to include 'PythonAPI'.\nError: " + str(e))

# -------------------------
# Configuration
# -------------------------
OUT_DIR = Path("output")
OUT_DIR.mkdir(exist_ok=True)
VIDEO_PATH = OUT_DIR / "hybrid_run.mp4"

IMAGE_W = 640
IMAGE_H = 480
FPS = 20.0

ALPHA = 0.9          # vision blending weight (0 = planner only, 1 = vision only)
THROTTLE_LIMIT = 0.6  # max throttle command
DEFAULT_TARGET_SPEED = 20.0  # m/s (fallback if agent doesn't expose target speed)
LOG_EVERY_N = 50

# PID parameters for throttle (simple P-I-D)
PID_KP = 1.2
PID_KI = 0.06
PID_KD = 0.03
PID_INTEGRAL_LIMIT = 5.0

# Vision params
STEER_GAIN = 0.6  # gain to convert deviation -> steering contribution
CANNY_THRESH = (50, 150)

# -------------------------
# Helper functions
# -------------------------
def ensure_contiguous_rgb(carla_image):
    """Return a BGR contiguous numpy array from carla.Image"""
    arr = np.frombuffer(carla_image.raw_data, dtype=np.uint8)
    arr = arr.reshape((carla_image.height, carla_image.width, 4))
    bgr = np.ascontiguousarray(arr[:, :, :3][:, :, ::-1], dtype=np.uint8)
    return bgr

def vision_steer(bgr_image):
    """Simple centroid-based lane steering (returns [-1,1])"""
    gray = cv2.cvtColor(bgr_image, cv2.COLOR_BGR2GRAY)
    blur = cv2.GaussianBlur(gray, (5, 5), 0)
    edges = cv2.Canny(blur, CANNY_THRESH[0], CANNY_THRESH[1])
    h, w = edges.shape
    roi = edges[int(h * 0.45):h, :]  # look further ahead

    M = cv2.moments(roi)
    if M['m00'] == 0:
        return 0.0, edges  # no edges found
    cx = (M['m10'] / M['m00'])
    deviation = (cx - (w / 2)) / (w / 2)  # -1..1
    steer = -STEER_GAIN * deviation  # negative sign: steer toward center
    steer = float(max(-1.0, min(1.0, steer)))
    return steer, edges

def get_yolo_obstacle_info(results, image_w, image_h):
    """Analyse YOLO results to estimate if an obstacle is ahead and its position."""
    obstacle_ahead = False
    lateral_bias = 0.0  # negative: obstacle left, positive: right
    nearest_conf = 0.0

    for r in results:
        for box in r.boxes:
            cls_id = int(box.cls[0])
            label = r.names[cls_id]
            conf = float(box.conf[0])
            x1, y1, x2, y2 = map(int, box.xyxy[0])

            if label in ["car", "truck", "bus", "person", "motorcycle"]:
                # Compute relative position
                box_cx = (x1 + x2) / 2
                box_cy = (y1 + y2) / 2
                box_height = y2 - y1
                vertical_ratio = box_cy / image_h

                # Focus only on bottom-half objects (in front of car)
                if vertical_ratio > 0.55:
                    obstacle_ahead = True
                    nearest_conf = max(nearest_conf, conf)
                    lateral_bias += (box_cx - image_w / 2) / (image_w / 2)  # left/right offset

    if obstacle_ahead:
        lateral_bias = max(-1.0, min(1.0, lateral_bias))
    return obstacle_ahead, lateral_bias, nearest_conf


def speed_magnitude(v):
    """Return speed magnitude in m/s from carla.Vector3D"""
    return math.sqrt(v.x**2 + v.y**2 + v.z**2)

# -------------------------
# PID controller class
# -------------------------
class PIDController:
    def __init__(self, kp, ki, kd, integral_limit=None):
        self.kp = kp
        self.ki = ki
        self.kd = kd
        self.integral = 0.0
        self.last_error = None
        self.last_time = None
        self.integral_limit = integral_limit

    def reset(self):
        self.integral = 0.0
        self.last_error = None
        self.last_time = None

    def step(self, target, measurement, t_now=None):
        # target & measurement are speeds (m/s)
        if t_now is None:
            t_now = time.time()
        error = float(target - measurement)
        if self.last_time is None:
            dt = 1e-3
            derivative = 0.0
        else:
            dt = max(1e-4, t_now - self.last_time)
            derivative = (error - self.last_error) / dt if self.last_error is not None else 0.0

        self.integral += error * dt
        if self.integral_limit is not None:
            self.integral = max(-self.integral_limit, min(self.integral_limit, self.integral))

        output = self.kp * error + self.ki * self.integral + self.kd * derivative

        self.last_error = error
        self.last_time = t_now
        return output

# -------------------------
# Main: setup CARLA and run loop
# -------------------------
def main():
    # connect to server
    client = carla.Client("192.168.160.1", 10000)
    client.set_timeout(100.0)
    world = client.get_world()
    blueprint_lib = world.get_blueprint_library()

    # spawn ego
    spawn_points = world.get_map().get_spawn_points()
    if not spawn_points:
        raise SystemExit("No spawn points available in the map.")
    veh_bp = blueprint_lib.find("vehicle.lincoln.mkz_2020")
    ego = world.try_spawn_actor(veh_bp, random.choice(spawn_points))
    if ego is None:
        raise SystemExit("Failed to spawn ego vehicle.")
    ego.set_autopilot(False)  # we will control

    # attach RGB camera (main view)
    cam_bp = blueprint_lib.find("sensor.camera.rgb")
    cam_bp.set_attribute("image_size_x", str(IMAGE_W))
    cam_bp.set_attribute("image_size_y", str(IMAGE_H))
    cam_bp.set_attribute("fov", "90")
    cam_transform = carla.Transform(carla.Location(x=1.5, z=2.4))
    cam = world.spawn_actor(cam_bp, cam_transform, attach_to=ego)
    img_q = queue.Queue()
    cam.listen(img_q.put)

    # attach semantic segmentation camera (same position)
    seg_bp = blueprint_lib.find("sensor.camera.semantic_segmentation")
    seg_bp.set_attribute("image_size_x", str(IMAGE_W))
    seg_bp.set_attribute("image_size_y", str(IMAGE_H))
    seg_bp.set_attribute("fov", "90")
    seg_cam = world.spawn_actor(seg_bp, cam_transform, attach_to=ego)
    seg_q = queue.Queue()
    seg_cam.listen(seg_q.put)

    
    # collision sensor (log collisions)
    col_bp = blueprint_lib.find("sensor.other.collision")
    col = world.spawn_actor(col_bp, carla.Transform(), attach_to=ego)
    col_q = queue.Queue()
    col.listen(lambda e: col_q.put((e.frame, e.timestamp, str(e.other_actor.type_id))))

    # spawn some NPCs (optional)
    npc_list = []
    for _ in range(30):
        try:
            bp = random.choice(blueprint_lib.filter("vehicle"))
            npc = world.try_spawn_actor(bp, random.choice(spawn_points))
            if npc:
                npc.set_autopilot(True)
                npc_list.append(npc)
        except Exception:
            pass
    print(f"Spawned {len(npc_list)} NPC vehicles safely away from ego.")
    
    
    # create BasicAgent planner and set random destination
    agent = BasicAgent(ego)
    dest = carla.Location(x=spawn_points[25].location.x, 
                      y=spawn_points[25].location.y, 
                      z=spawn_points[25].location.z)
    agent.set_destination(dest)

    #dest = random.choice(spawn_points).location
    #agent.set_destination(carla.Location(x=dest.x, y=dest.y, z=dest.z))


    # choose planner target speed if available
    try:
        # many BasicAgent versions expose target_speed or desired_speed
        planner_target_speed = float(getattr(agent, "target_speed", getattr(agent, "desired_speed", DEFAULT_TARGET_SPEED)))
    except Exception:
        planner_target_speed = DEFAULT_TARGET_SPEED

    # prepare sync mode
    orig_settings = world.get_settings()
    settings = world.get_settings()
    settings.synchronous_mode = True
    settings.fixed_delta_seconds = 1.0 / FPS
    world.apply_settings(settings)
    # Load YOLOv8 model (pretrained on COCO)
    yolo_model = YOLO('yolov8n.pt')


    # video writer headless
    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    video_writer = cv2.VideoWriter(str(VIDEO_PATH), fourcc, FPS, (IMAGE_W, IMAGE_H))

    pid = PIDController(PID_KP, PID_KI, PID_KD, integral_limit=PID_INTEGRAL_LIMIT)

    print("Hybrid planner+vision started. Recording to:", VIDEO_PATH)
    frame_count = 0
    try:
        while True:
            world.tick()
            # planner step: BasicAgent.run_step() returns a VehicleControl suggestion
            planner_control = agent.run_step()  # type: carla.VehicleControl
            # planner may update internal target speed; try to read it dynamically
            try:
                planner_target_speed = float(getattr(agent, "target_speed", getattr(agent, "desired_speed", planner_target_speed)))
            except Exception:
                pass

            # camera frame
            carla_img = img_q.get(timeout=100.0)
            frame_bgr = ensure_contiguous_rgb(carla_img)
            
            # --- optional camera degradation tests ---
            # Apply random Gaussian blur or brightness drop
            # --- Optional camera degradation tests ---
            if random.random() < 0.0:  # 30% of frames degraded
                degrade_type = random.choice(["blur", "darken", "gaussian_noise", "salt_pepper", "brightness_flicker"])
                
                if degrade_type == "blur":
                    frame_bgr = cv2.GaussianBlur(frame_bgr, (9, 9), 0)
                
                elif degrade_type == "darken":
                    frame_bgr = np.clip(frame_bgr * 0.5, 0, 255).astype(np.uint8)
                
                elif degrade_type == "gaussian_noise":
                    noise = np.random.normal(0, 25, frame_bgr.shape).astype(np.float32)
                    frame_bgr = np.clip(frame_bgr.astype(np.float32) + noise, 0, 255).astype(np.uint8)
                
                elif degrade_type == "salt_pepper":
                    prob = 0.02
                    mask = np.random.choice((0, 1, 2), size=frame_bgr.shape[:2], p=[prob/2, prob/2, 1-prob])
                    frame_bgr[mask == 0] = 0
                    frame_bgr[mask == 1] = 255
                
                elif degrade_type == "brightness_flicker":
                    factor = random.uniform(0.6, 1.4)
                    frame_bgr = np.clip(frame_bgr.astype(np.float32) * factor, 0, 255).astype(np.uint8)

            
            # vision steering
            steer_vision, edges = vision_steer(frame_bgr)
            
            # YOLO object detection (car, person, traffic light, etc.)
            results = yolo_model.predict(frame_bgr, classes=[0, 1, 2, 3, 5, 7], verbose=False)
            for r in results:
                for box in r.boxes:
                    cls_id = int(box.cls[0])
                    conf = float(box.conf[0])
                    label = f"{yolo_model.names[cls_id]} {conf:.2f}"
                    x1, y1, x2, y2 = map(int, box.xyxy[0])
                    # Draw bounding box and label
                    cv2.rectangle(frame_bgr, (x1, y1), (x2, y2), (0, 255, 0), 2)
                    cv2.putText(frame_bgr, label, (x1, y1 - 5),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 1)
            # Analyse YOLO results for obstacle influence
            obstacle_ahead, lateral_bias, conf = get_yolo_obstacle_info(results, IMAGE_W, IMAGE_H)


            
            
            # ------------------------------------------------------------
            # Steering and throttle control with YOLO + lane + PID
            # ------------------------------------------------------------
            planner_steer = float(planner_control.steer) if planner_control is not None else 0.0
            steer = ALPHA * steer_vision + (1.0 - ALPHA) * planner_steer

            # If obstacle detected, slightly steer away
            if obstacle_ahead:
               # steer -= 0.4 * lateral_bias  # steer opposite to obstacle direction
               pass 

            steer = float(max(-1.0, min(1.0, steer)))

            # --- compute current speed ---
            current_speed = speed_magnitude(ego.get_velocity())

            # --- handle vehicle stopped too long ---
            if current_speed < 0.1:
                if 'stop_start' not in locals():
                    stop_start = time.time()
                elif time.time() - stop_start > 40.0:
                    print("Vehicle stopped for >10 s. Exiting.")
                    break
            else:
                if 'stop_start' in locals():
                    del stop_start

            # --- set adaptive target speed ---
            target_speed = planner_target_speed
            if obstacle_ahead:
                # slow down proportionally to confidence (0–60%)
                target_speed = max(2.0, planner_target_speed * (1.0 - 0.4 * conf))
                #target_speed *= (1.0 - 0.6 * conf)
                if target_speed < 2.0:
                    target_speed = 0.0  # stop completely

            # --- PID throttle control ---
            throttle_raw = pid.step(target_speed, current_speed, t_now=time.time())
            throttle = float(max(0.0, min(THROTTLE_LIMIT, throttle_raw)))

            # --- respect planner braking ---
            brake = float(getattr(planner_control, "brake", 0.0)) if planner_control is not None else 0.0
            if brake > 0.05:
                throttle = 0.0

            # emergency slow-down: if vision shows huge deviation, reduce throttle
            if abs(steer_vision) > 0.9:
                throttle = min(throttle, 0.2)

            # apply control
            ctrl = carla.VehicleControl(throttle=throttle, steer=steer, brake=brake)
            ego.apply_control(ctrl)

            # record annotations on frame
            overlay = frame_bgr.copy()
            txt1 = f"Frame:{carla_img.frame} Speed:{current_speed:.2f}m/s Target:{planner_target_speed:.2f}m/s"
            txt2 = f"PlannerSteer:{planner_steer:+.2f} VisionSteer:{steer_vision:+.2f} Blended:{steer:+.2f}"
            txt3 = f"Throttle:{throttle:.2f} Brake:{brake:.2f}"
            cv2.putText(overlay, txt1, (12, 28), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255,255,0), 2)
            cv2.putText(overlay, txt2, (12, 56), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0,255,0), 2)
            cv2.putText(overlay, txt3, (12, 84), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0,200,255), 2)
            
            if obstacle_ahead:
                cv2.putText(overlay, f"Obstacle detected (conf={conf:.2f})", (12, 110),
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 255), 2)


           
            # put edges scaled into top-right corner
            edges_rgb = cv2.cvtColor(edges, cv2.COLOR_GRAY2BGR)
            er = cv2.resize(edges_rgb, (160, 120))
            h, w = overlay.shape[:2]
            overlay[4:4+120, w-4-160:w-4] = er
            overlay[4:4+120, w-4-160:w-4] = er

            video_writer.write(overlay)

            # log occasional info
            if frame_count % LOG_EVERY_N == 0:
                print(f"[frame {carla_img.frame}] speed={current_speed:.2f} target={planner_target_speed:.2f} steer={steer:+.2f} throttle={throttle:.2f}")

            # check collisions
            while not col_q.empty():
                ev = col_q.get_nowait()
                print(f"[COLLISION] frame={ev[0]} with {ev[2]} at ts={ev[1]}")

            frame_count += 1

    except KeyboardInterrupt:
        print("User requested stop.")
    except Exception as e:
        print("Exception:", e)
    finally:
        print("Finalizing: releasing resources and saving video.")
        video_writer.release()
        
        # cleanup actors
        try:
            cam.stop(); cam.destroy()
        except Exception:
            pass
        try:
            col.stop(); col.destroy()
        except Exception:
            pass
        try:
            ego.destroy()
        except Exception:
            pass
        for npc in npc_list:
            try:
                npc.destroy()
            except Exception:
                pass
        try:
            seg_cam.stop(); seg_cam.destroy()
        except Exception:
            pass
        # restore settings
        try:
            world.apply_settings(orig_settings)
        except Exception:
            pass

        print("Saved video to:", VIDEO_PATH)
        print("Exit.")

if __name__ == "__main__":
    main()
