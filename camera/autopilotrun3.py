#!/usr/bin/env python3


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
# Add PythonAPI
# ==============================================================================
try:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/../carla')
except IndexError:
    pass

try:
    from agents.navigation.basic_agent import BasicAgent
except Exception as e:
    raise SystemExit("Cannot import BasicAgent. Run from CARLA PythonAPI examples folder.\nError: " + str(e))

# ==============================================================================
# CONFIGURATION
# ==============================================================================
OUT_DIR = Path("output")
OUT_DIR.mkdir(exist_ok=True)
VIDEO_PATH = OUT_DIR / "hybrid_run.mp4"

IMAGE_W, IMAGE_H =800, 600
FPS = 20.0
ALPHA = 0.8           # blending between vision (1) and planner (0)
ALPHA = 0.8           # blending between vision (1) and planner (0)
THROTTLE_LIMIT = 0.6
DEFAULT_TARGET_SPEED = 20.0  # m/s
LOG_EVERY_N = 50

# PID parameters for throttle
PID_KP, PID_KI, PID_KD = 1.2, 0.06, 0.03
PID_INTEGRAL_LIMIT = 5.0

# Vision processing parameters
STEER_GAIN = 0.4
CANNY_THRESH = (50, 150)
SMOOTHING = 0.25  # steering smoothing factor

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================
def apply_vision_disruption(frame_bgr, degrade_type):
    # ============================================================
    # Adjustable parameters
    # ============================================================
    BLUR_KERNEL = (13, 13)           # Larger = more blur
    DARKEN_FACTOR = 0.2            # Smaller = darker (e.g. 0.3 very dark)
    NOISE_STDDEV = 40              # Higher = more Gaussian noise
    SALT_PEPPER_PROB = 0.5        # Higher = more white/black dots
    BRIGHTNESS_MIN = 0.5           # Lower bound for random flicker
    BRIGHTNESS_MAX = 1.5           # Upper bound for random flicker
    # ============================================================

    if degrade_type == "blur":
        return cv2.GaussianBlur(frame_bgr, BLUR_KERNEL, 0)
    
    
    elif degrade_type == "darken":
        return np.clip(frame_bgr * DARKEN_FACTOR, 0, 255).astype(np.uint8)
    
    elif degrade_type == "gaussian_noise":
        noise = np.random.normal(0, NOISE_STDDEV, frame_bgr.shape).astype(np.float32)
        return np.clip(frame_bgr.astype(np.float32) + noise, 0, 255).astype(np.uint8)
    
    elif degrade_type == "salt_pepper":
        prob = SALT_PEPPER_PROB
        mask = np.random.choice((0, 1, 2), size=frame_bgr.shape[:2], p=[prob/2, prob/2, 1-prob])
        frame_bgr[mask == 0] = 0
        frame_bgr[mask == 1] = 255
        return frame_bgr

    elif degrade_type == "brightness_flicker":
        factor = random.uniform(BRIGHTNESS_MIN, BRIGHTNESS_MAX)
        return np.clip(frame_bgr.astype(np.float32) * factor, 0, 255).astype(np.uint8)
    
    return frame_bgr


def destroy_all_vehicles(world):
    vehicles = world.get_actors().filter('vehicle.*')
    for vehicle in vehicles:
        #print(f"Destroying vehicle ID {vehicle.id}")
        vehicle.destroy()

def destroy_all_walkers(world):
    walkers = world.get_actors().filter('walker.pedestrian.*')
    for walker in walkers:
        #print(f"Destroying walker ID {walker.id}")
        walker.destroy()

def ensure_contiguous_rgb(carla_image):
    """Convert CARLA image to contiguous OpenCV BGR numpy array"""
    arr = np.frombuffer(carla_image.raw_data, dtype=np.uint8)
    arr = arr.reshape((carla_image.height, carla_image.width, 4))
    return np.ascontiguousarray(arr[:, :, :3][:, :, ::-1], dtype=np.uint8)

def vision_steer(bgr_image, degrade_active=False, prev_steer=0.0):
    # --- Preprocess ---
    gray  = cv2.cvtColor(bgr_image, cv2.COLOR_BGR2GRAY)
    blur  = cv2.GaussianBlur(gray, (5,5), 0)
    edges = cv2.Canny(blur, 50, 150)
    h, w  = edges.shape

    # --- Adaptive ROI ---
    roi_top = int(h * (0.45 - 0.10 * min(1.0, abs(prev_steer))))
    roi = edges[roi_top:h, :]

    # ---Moment-based deviation ---
    M = cv2.moments(roi)
    if M['m00'] == 0:
        steer = 0.0
        confidence = 0.0
    else:
        cx = M['m10'] / M['m00']
        deviation = (cx - (w / 2)) / (w / 2)
        steer = -STEER_GAIN * deviation

        # Confidence from edge density
        edge_density = np.sum(roi > 0) / roi.size
        confidence = min(1.0, edge_density * 4.0)

    # --- Apply degradation effect ---
    if degrade_active:
        confidence *= 0.3
        steer *= 0.6

    # --- Confidence-weighted smoothing ---
    global SMOOTHING
    #steer = SMOOTHING * prev_steer + (1 - SMOOTHING * confidence) * steer
    adaptive_smooth = SMOOTHING + 0.2 * abs(prev_steer)   # more smoothing when turning
    steer = adaptive_smooth * prev_steer + (1 - adaptive_smooth * confidence) * steer


    # --- Clamp range ---
    steer = float(max(-1.0, min(1.0, steer))) 

    return steer, edges, confidence, roi_top


def get_yolo_obstacle_info(results, image_w, image_h):
    """Analyse YOLO results to detect nearby obstacles and bias"""
    obstacle_ahead, lateral_bias, nearest_conf = False, 0.0, 0.0
    for r in results:
        for box in r.boxes:
            cls_id = int(box.cls[0])
            label = r.names[cls_id]
            conf = float(box.conf[0])
            x1, y1, x2, y2 = map(int, box.xyxy[0])
            if label in ["car", "truck", "bus", "person", "motorcycle"]:
                box_cx = (x1 + x2) / 2
                box_cy = (y1 + y2) / 2
                if box_cy / image_h > 0.5:  # only consider front-lower region
                    obstacle_ahead = True
                    nearest_conf = max(nearest_conf, conf)
                    lateral_bias += (box_cx - image_w / 2) / (image_w / 2)
    if obstacle_ahead:
        lateral_bias = max(-1.0, min(1.0, lateral_bias))
    return obstacle_ahead, lateral_bias, nearest_conf

def speed_magnitude(v):
    return math.sqrt(v.x**2 + v.y**2 + v.z**2)

# ==============================================================================
# PID CONTROLLER CLASS
# ==============================================================================
class PIDController:
    """Simple PID controller for throttle"""
    def __init__(self, kp, ki, kd, integral_limit=None):
        self.kp, self.ki, self.kd = kp, ki, kd
        self.integral, self.last_error, self.last_time = 0.0, None, None
        self.integral_limit = integral_limit

    def step(self, target, measurement, t_now=None):
        if t_now is None:
            t_now = time.time()
        error = float(target - measurement)
        dt = max(1e-4, (t_now - self.last_time)) if self.last_time else 1e-3
        derivative = (error - self.last_error) / dt if self.last_error is not None else 0.0
        self.integral = max(-self.integral_limit, min(self.integral_limit, self.integral + error * dt))
        self.last_error, self.last_time = error, t_now
        return self.kp * error + self.ki * self.integral + self.kd * derivative

# ==============================================================================
# MAIN EXECUTION LOOP
# ==============================================================================
def main():
    # ------------------------------------------------------------
    # CARLA WORLD AND VEHICLE SETUP
    # ------------------------------------------------------------
    client = carla.Client("192.168.160.1", 2000)
    client.set_timeout(200.0)
    world = client.get_world()
    bp_lib = world.get_blueprint_library()

                
    # Ego vehicle spawn
    ego_bp = bp_lib.find("vehicle.lincoln.mkz_2020")
    spawn_points = world.get_map().get_spawn_points()
    spawn_index = 10
    ego = world.try_spawn_actor(ego_bp, spawn_points[spawn_index])
    if not ego:
        raise SystemExit(f"Failed to spawn ego vehicle at index {spawn_index}.")
    print(f"Vehicle spawned at point {spawn_index}")
    ego.set_autopilot(False)
    

    # --- Attach RGB and Segmentation cameras ---
    cam_transform = carla.Transform(carla.Location(x=1.5, z=2.4))
    cam_bp = bp_lib.find("sensor.camera.rgb")
    cam_bp.set_attribute("image_size_x", str(IMAGE_W))
    cam_bp.set_attribute("image_size_y", str(IMAGE_H))
    cam_bp.set_attribute("fov", "90")
    cam_bp.set_attribute("exposure_mode", "manual")
    #cam_bp.set_attribute("sensor_tick", str(1.0 / FPS))
    #cam_bp.set_attribute("gamma", "2.2")
    #cam_bp.set_attribute("enable_postprocess_effects", "true")
    #cam_bp.set_attribute("motion_blur_intensity", "0.4")
    #cam_bp.set_attribute("motion_blur_max_distortion", "0.1")
    #cam_bp.set_attribute("motion_blur_min_object_screen_size", "0.01")
    #cam_bp.set_attribute("shutter_speed", "0.005")
    cam = world.spawn_actor(cam_bp, cam_transform, attach_to=ego)
    img_q = queue.Queue(); cam.listen(img_q.put)

    seg_bp = bp_lib.find("sensor.camera.semantic_segmentation")
    seg_bp.set_attribute("image_size_x", str(IMAGE_W))
    seg_bp.set_attribute("image_size_y", str(IMAGE_H))
    seg_cam = world.spawn_actor(seg_bp, cam_transform, attach_to=ego)
    seg_q = queue.Queue(); seg_cam.listen(seg_q.put)

    # Collision sensor
    col_bp = bp_lib.find("sensor.other.collision")
    col = world.spawn_actor(col_bp, carla.Transform(), attach_to=ego)
    col_q = queue.Queue(); col.listen(lambda e: col_q.put((e.frame, e.timestamp, str(e.other_actor.type_id))))

    # ---- NPC VEHICLE SPAWNING — Avoid Ego Spawn Area----
    npc_list = []
    for _ in range(20):
        try:
            bp = random.choice(bp_lib.filter("vehicle"))
            npc = world.try_spawn_actor(bp, random.choice(spawn_points))
            if npc:
                npc.set_autopilot(True)
                npc_list.append(npc)
        except Exception:
            pass
    print(f"Spawned {len(npc_list)} NPC vehicles safely away from ego.")

    

    # ---- NPC WALKERS SPAWNING — Avoid Ego Spawn Area----
    walker_list = []
    all_id = []
    walker_bps = bp_lib.filter('walker.pedestrian.*')
    walker_spawn_points = []
    for _ in range(15):
        loc = world.get_random_location_from_navigation()
        if loc:
            walker_spawn_points.append(carla.Transform(loc))

    # spawn walkers
    walker_batch = []
    for spawn_point in walker_spawn_points:
        walker_bp = random.choice(walker_bps)
        if walker_bp.has_attribute('is_invincible'):
            walker_bp.set_attribute('is_invincible', 'false')
        speed = 1.4 if random.random() < 0.5 else 2.8  # random walk speed
        if walker_bp.has_attribute('speed'):
            walker_bp.set_attribute('speed', str(speed))
        walker_batch.append(carla.command.SpawnActor(walker_bp, spawn_point))

    # apply batch to world
    results = client.apply_batch_sync(walker_batch, True)
    for res in results:
        if res.error:
            continue
        walker_list.append(res.actor_id)

    # spawn AI controllers for each walker
    controller_bp = bp_lib.find('controller.ai.walker')
    controller_batch = [carla.command.SpawnActor(controller_bp, carla.Transform(), wid)
                        for wid in walker_list]
    results_ctrl = client.apply_batch_sync(controller_batch, True)
    for res in results_ctrl:
        if res.error:
            continue
        all_id.append((res.actor_id, walker_list[len(all_id)]))

    # start walker AI
    world.wait_for_tick()
    for ctrl_id, walker_id in all_id:
        controller = world.get_actor(ctrl_id)
        walker = world.get_actor(walker_id)
        controller.start()
        controller.go_to_location(world.get_random_location_from_navigation())
        controller.set_max_speed(1.4 if random.random() < 0.5 else 2.8)

    print(f"Spawned {len(all_id)} pedestrians walking randomly.")


    # ------------------------------------------------------------
    # FORCE ALL TRAFFIC LIGHTS TO GREEN
    # ------------------------------------------------------------
    lights = world.get_actors().filter('traffic.traffic_light')
    for light in lights:
        light.set_state(carla.TrafficLightState.Green)
        light.set_green_time(9999.0)   # stay green a long time
        light.freeze(True)             # freeze so it never changes
    print(f"All {len(lights)} traffic lights set to GREEN.")

    # ----- BasicAgent route planning -----
    dest_index = 20
    destination = spawn_points[dest_index].location
    agent = BasicAgent(ego)
    agent.set_destination(destination)    
    print(f"Destination set to point {dest_index}")
    

    # --- Simulation sync mode ---
    settings = world.get_settings()
    settings.synchronous_mode = True
    settings.fixed_delta_seconds = 1.0 / FPS
    orig_settings = world.get_settings()
    world.apply_settings(settings)

    # --- Load YOLO (vehicle/pedestrian detection) ---
    yolo = YOLO("yolov8n.pt")

    # --- Video export setup ---
    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    video_writer = cv2.VideoWriter(str(VIDEO_PATH), fourcc, FPS, (IMAGE_W, IMAGE_H))

    pid = PIDController(PID_KP, PID_KI, PID_KD, PID_INTEGRAL_LIMIT)
    prev_steer = 0.0  # smoothing memory

    print("Hybrid planner+vision running... Saving video to:", VIDEO_PATH)

    # ------------------------------------------------------------
    # MAIN CONTROL LOOP
    # ------------------------------------------------------------
    frame_count = 0
    start_time = time.time()
    degrade_started = False
    degrade_ended = False
    degrade_type = None
    try:
        while True:
            world.tick()
            current_time = time.time() - start_time

            # === Get planned control ===
            planner_control = agent.run_step()
            planner_steer = float(planner_control.steer)
            planner_target_speed = float(getattr(agent, "target_speed", DEFAULT_TARGET_SPEED))

            # === Get camera frame ===
            img = img_q.get(timeout=100.0)
            frame = ensure_contiguous_rgb(img)
            
            # ------------------------------------------------------------
            # VISION DEGRADATION CONTROL
            # ------------------------------------------------------------
            current_time = time.time() - start_time
            degrade_start = 0.0
            degrade_duration = 0.0
            degrade_end = degrade_start + degrade_duration

            if not degrade_started and current_time >= degrade_start:
                #degrade_type = random.choice(["blur", "darken", "gaussian_noise", "salt_pepper", "brightness_flicker"])
                degrade_type = "blur"
                print(f"Vision degradation started: {degrade_type}")
                degrade_started = True

            if degrade_started and not degrade_ended and current_time > degrade_end:
                print("✅Vision degradation ended.")
                degrade_ended = True

            if degrade_started and not degrade_ended:
                frame = apply_vision_disruption(frame, degrade_type)
                degrade_active = True
            else:
                degrade_active = False

            # --- After calling vision_steer ---
            steer_vision, edges, vision_conf, roi_top = vision_steer(frame, degrade_active, prev_steer)

            # ------------------------------------------------------------
            # VISUALISATION LAYER — Create shared overlay frame
            # ------------------------------------------------------------
            overlay = frame.copy()   # base colour frame for all drawings

            # === LANE DETECTION VISUALISATION ===
            edges_rgb = cv2.cvtColor(edges, cv2.COLOR_GRAY2BGR)
            h, w = edges.shape
            cv2.rectangle(edges_rgb, (0, roi_top), (w, h), (255, 0, 0), 2)

            # --- Detect left/right lane lines using Hough Transform ---
            roi = edges[roi_top:h, :]
            lines = cv2.HoughLinesP(roi, 1, np.pi / 180, threshold=60,
                                    minLineLength=40, maxLineGap=25)

            left_lines, right_lines = [], []
            if lines is not None:
                for x1, y1, x2, y2 in lines[:, 0]:
                    slope = (y2 - y1) / (x2 - x1 + 1e-6)
                    if abs(slope) < 0.3 or abs(slope) > 1.2:
                        continue  # ignore too flat or too vertical
                    if slope < 0:
                        left_lines.append((x1, y1, x2, y2))
                    else:
                        right_lines.append((x1, y1, x2, y2))

            # --- Average and draw left/right lanes ---
            def average_line(lines):
                if not lines:
                    return None
                x1s, y1s, x2s, y2s = zip(*lines)
                return (int(np.mean(x1s)), int(np.mean(y1s)),
                        int(np.mean(x2s)), int(np.mean(y2s)))

            left_avg = average_line(left_lines)
            right_avg = average_line(right_lines)

            if left_avg is not None:
                cv2.line(edges_rgb,
                         (left_avg[0], roi_top + left_avg[1]),
                         (left_avg[2], roi_top + left_avg[3]),
                         (255, 100, 0), 4)
            if right_avg is not None:
                cv2.line(edges_rgb,
                         (right_avg[0], roi_top + right_avg[1]),
                         (right_avg[2], roi_top + right_avg[3]),
                         (0, 255, 100), 4)

            # --- Draw lane centre and image centre ---
            M = cv2.moments(edges[roi_top:h, :])
            if M['m00'] > 0:
                cx = int(M['m10'] / M['m00'])
                cv2.line(edges_rgb, (cx, roi_top), (cx, h), (0, 255, 255), 3)  # yellow = detected lane centre
            cv2.line(edges_rgb, (w//2, roi_top), (w//2, h), (0, 0, 255), 2)    # red = image centre

            cv2.putText(edges_rgb, f"Vision conf: {vision_conf:.2f}", (10, 10),
                        cv2.FONT_HERSHEY_SIMPLEX, 1.2, (0, 255, 255), 3)

            # === INSERT MINI VIEW OF LANE DETECTION ===
            mini_w, mini_h = 480, 360
            mini_edges = cv2.resize(edges_rgb, (mini_w, mini_h), interpolation=cv2.INTER_NEAREST)
            overlay[10:10+mini_h, 10:10+mini_w] = cv2.addWeighted(
                overlay[10:10+mini_h, 10:10+mini_w], 0.4, mini_edges, 0.6, 0)



            
            
            

            # ------------------------------------------------------------
            # YOLO bounding boxes (draw on same overlay)
            # ------------------------------------------------------------
            results = yolo.predict(frame, classes=[0, 1, 2, 3, 5, 7], conf=0.35, verbose=False)
            for r in results:
                for box in r.boxes:
                    cls_id = int(box.cls[0])
                    conf_box = float(box.conf[0])
                    label = f"{yolo.names[cls_id]} {conf_box:.2f}"
                    x1, y1, x2, y2 = map(int, box.xyxy[0])
                    color = (0, 255, 0) if conf_box > 0.5 else (0, 200, 200)
                    cv2.rectangle(overlay, (x1, y1), (x2, y2), color, 2)
                    cv2.putText(overlay, label, (x1, max(20, y1 - 5)), cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 1)

            
            
            # --- Analyse YOLO results for obstacle awareness ---
            obstacle_ahead, lateral_bias, conf = get_yolo_obstacle_info(results, IMAGE_W, IMAGE_H)

            # ------------------------------------------------------------
            # STEER CONTROLLING — Lane + Planner + Obstacle Awareness
            # ------------------------------------------------------------
            # --- Step 1: Fixed ALPHA blending ---
            # ALPHA = 0.8 → 80% vision, 20% planner steering
            steer = ALPHA * steer_vision + (1.0 - ALPHA) * planner_steer

            # --- Step 2: Obstacle correction ---
            # If an obstacle is detected, gently push steering away
            if obstacle_ahead:
                steer -= 0.1 * lateral_bias * conf  # push away smoothly
                #pass

            # --- Step 3: Speed-based damping ---
            # Reduce steering sensitivity at high speed for stability
            current_speed = speed_magnitude(ego.get_velocity())
            #speed_factor = max(0.4, 1.0 - 0.03 * current_speed)
           # steer *= speed_factor

            # --- Step 4: Low-pass filtering for smoother response ---
            #steer = SMOOTHING * prev_steer + (1 - SMOOTHING) * steer
            #prev_steer = steer

            # --- Step 5: Clamp steering to [-1.0, 1.0] ---
            #steer = float(max(-1.0, min(1.0, steer)))

            # --- Step 7: Safety stop timeout (avoid infinite idle) ---
            if current_speed < 0.1:
                if 'stop_start' not in locals():
                    stop_start = time.time()
                elif time.time() - stop_start > 500.0:
                    print("Vehicle stopped for >10 s. Exiting.")
                    break
            else:
                if 'stop_start' in locals():
                    del stop_start

            # ------------------------------------------------------------
            # THROTTLE CONTROLLING (PID)
            # ------------------------------------------------------------
            target_speed = planner_target_speed
            if obstacle_ahead:
                target_speed = max(2.0, planner_target_speed * (1.0 - 0.4 * conf))

            throttle_raw = pid.step(target_speed, current_speed, t_now=time.time())
            throttle = float(max(0.0, min(THROTTLE_LIMIT, throttle_raw)))

            brake = float(getattr(planner_control, "brake", 0.0))
            if brake > 0.05:
                throttle = 0.0
            if abs(steer_vision) > 0.9:
                throttle = min(throttle, 0.2)

            ego.apply_control(carla.VehicleControl(throttle=throttle, steer=steer, brake=brake))
            # ------------------------------------------------------------
            # DESTINATION CHECK
            # ------------------------------------------------------------
            if agent.done():
                print("Destination reached! Stopping simulation.")
                ego.apply_control(carla.VehicleControl(throttle=0.0, brake=1.0))
                break

            # ------------------------------------------------------------
            # VIDEO TEXT INFO (draw on same overlay)
            # ------------------------------------------------------------
            txt1 = f"Frame:{img.frame}  Speed:{current_speed:.2f} m/s"
            txt2 = f"PlannerSteer:{planner_steer:+.2f}  VisionSteer:{steer_vision:+.2f}  Blended:{steer:+.2f}"
            txt3 = f"Throttle:{throttle:.2f}  Brake:{brake:.2f}"
            cv2.putText(overlay, txt1, (12, 28), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255,255,0), 2)
            cv2.putText(overlay, txt2, (12, 56), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0,255,0), 2)
            cv2.putText(overlay, txt3, (12, 84), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0,200,255), 2)

            if obstacle_ahead:
                cv2.putText(overlay, f"Obstacle detected (conf={conf:.2f})", (12, 140),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0,0,255), 2)

            # ------------------------------------------------------------
            # WRITE FINAL OVERLAY TO VIDEO
            # ------------------------------------------------------------
            video_writer.write(overlay)
            

            # --- optional: show progress ---
            if frame_count % LOG_EVERY_N == 0:
                print(f"[frame {img.frame}] speed={current_speed:.2f} target={target_speed:.2f} steer={steer:+.2f}")
            frame_count += 1

            # --- check collisions ---
            while not col_q.empty():
                ev = col_q.get_nowait()
                print(f"[COLLISION] frame={ev[0]} with {ev[2]} at ts={ev[1]}")

    except KeyboardInterrupt:
        print("User interrupted. Exiting.")
    finally:
        print("Finalizing and releasing resources...")        
        video_writer.release()
        for actor in [cam, seg_cam, col, ego]:
            try:
                actor.stop(); actor.destroy()
            except Exception:
                pass
        destroy_all_vehicles(world)
        destroy_all_walkers(world)
        world.apply_settings(orig_settings)
        print("Video saved to:", VIDEO_PATH)

# ==============================================================================
# ENTRY POINT
# ==============================================================================
if __name__ == "__main__":
    main()
