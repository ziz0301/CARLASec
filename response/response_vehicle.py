import math
import carla
import os
import sys

try:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/carla')
except IndexError:
    pass
from benchmark_tools.traffic_rule_infractions import CountOffRoadViolation

class RSSStateResponse:
    NORMAL = "Normal"
    OBSERVATION = "Observation"
    SAFETY = "Safety"
    RECOVERY = "Recovery"

    def __init__(
        self,
        world,
        ego_vehicle,
        observation_time=1.5,
        recovery_time=2.0,
        max_safety_time=12.0,
        rss_brake=0.6,
        recovery_speed_factor=0.5,
        debug=True
    ):
        self.world = world
        self.ego = ego_vehicle
        self.state = self.NORMAL

        self.observation_time = observation_time
        self.recovery_time = recovery_time
        self.max_safety_time = max_safety_time
        self.rss_brake = rss_brake
        self.recovery_speed_factor = recovery_speed_factor
        self.debug = debug

        self.state_start_time = self._time()

        # RSS parameters
        self.rho = 1.0
        self.a_max_accel = 2.5
        self.a_min_brake = 4.0
        self.a_max_brake = 8.0
        self.a_lat_max_accel = 1.5
        self.a_lat_min_brake = 2.0
        self.mu = 0.5
        
        #offroad
        self.offroad_checker = CountOffRoadViolation(
            self.ego,
            self.world.get_map()
        )

    def _time(self):
        return self.world.get_snapshot().timestamp.elapsed_seconds

    def _set_state(self, new_state):
        if new_state != self.state:
            if self.debug:
                print(f"[RSS RESPONSE] {self.state} -> {new_state}")
            self.state = new_state
            self.state_start_time = self._time()

    def _state_duration(self):
        return self._time() - self.state_start_time

    def _speed(self, vehicle):
        v = vehicle.get_velocity()
        return math.sqrt(v.x ** 2 + v.y ** 2 + v.z ** 2)

    def _get_lane_info(self, vehicle):
        wp = self.world.get_map().get_waypoint(
            vehicle.get_location(),
            project_to_road=True,
            lane_type=carla.LaneType.Driving
        )

        loc = vehicle.get_location()
        center = wp.transform.location

        right = wp.transform.get_right_vector()
        forward = wp.transform.get_forward_vector()

        rel = loc - center

        lateral_offset = (
            rel.x * right.x +
            rel.y * right.y +
            rel.z * right.z
        )

        vel = vehicle.get_velocity()

        v_long = (
            vel.x * forward.x +
            vel.y * forward.y +
            vel.z * forward.z
        )

        v_lat = (
            vel.x * right.x +
            vel.y * right.y +
            vel.z * right.z
        )

        return wp, lateral_offset, v_long, v_lat

    def _safe_distance_same_direction(self, ego_speed, front_speed):
        v_rho = ego_speed + self.rho * self.a_max_accel

        d_safe = (
            ego_speed * self.rho
            + 0.5 * self.a_max_accel * self.rho ** 2
            + (v_rho ** 2) / (2 * self.a_min_brake)
            - (front_speed ** 2) / (2 * self.a_max_brake)
        )

        return max(d_safe, 0.0)

    def _safe_lateral_distance(self, ego_lat_speed, target_lat_speed):
        v1_rho = ego_lat_speed + self.rho * self.a_lat_max_accel
        v2_rho = target_lat_speed - self.rho * self.a_lat_max_accel

        d_safe = (
            ((ego_lat_speed + v1_rho) / 2) * self.rho
            + (v1_rho ** 2) / (2 * self.a_lat_min_brake)
            - ((target_lat_speed + v2_rho) / 2) * self.rho
            + (v2_rho ** 2) / (2 * self.a_lat_min_brake)
        )

        return self.mu + max(d_safe, 0.0)

    def _find_front_vehicle(self):
        ego_wp, ego_lat, ego_v_long, ego_v_lat = self._get_lane_info(self.ego)
        ego_loc = self.ego.get_location()
        ego_forward = ego_wp.transform.get_forward_vector()

        nearest = None
        nearest_distance = float("inf")

        vehicles = self.world.get_actors().filter("vehicle.*")

        for vehicle in vehicles:
            if vehicle.id == self.ego.id:
                continue

            target_wp, target_lat, target_v_long, target_v_lat = self._get_lane_info(vehicle)

            if target_wp.road_id != ego_wp.road_id:
                continue

            rel = vehicle.get_location() - ego_loc
            longitudinal_distance = (
                rel.x * ego_forward.x +
                rel.y * ego_forward.y +
                rel.z * ego_forward.z
            )

            if longitudinal_distance <= 0:
                continue

            if longitudinal_distance < nearest_distance:
                nearest_distance = longitudinal_distance
                nearest = {
                    "vehicle": vehicle,
                    "distance": longitudinal_distance,
                    "ego_lat": ego_lat,
                    "target_lat": target_lat,
                    "ego_v_long": ego_v_long,
                    "target_v_long": target_v_long,
                    "ego_v_lat": ego_v_lat,
                    "target_v_lat": target_v_lat,
                }

        return nearest

    def check_rss_danger(self):
        target = self._find_front_vehicle()

        if target is None:
            return False, {
                "reason": "no_target",
                "long_danger": False,
                "lat_danger": False,
            }

        ego_speed = max(target["ego_v_long"], 0.0)
        front_speed = max(target["target_v_long"], 0.0)

        actual_long_distance = target["distance"]
        safe_long_distance = self._safe_distance_same_direction(
            ego_speed,
            front_speed
        )

        actual_lat_distance = abs(target["ego_lat"] - target["target_lat"])
        safe_lat_distance = self._safe_lateral_distance(
            target["ego_v_lat"],
            target["target_v_lat"]
        )

        long_danger = actual_long_distance < safe_long_distance
        lat_danger = actual_lat_distance < safe_lat_distance

        danger = long_danger and lat_danger

        info = {
            "reason": "rss_check",
            "target_id": target["vehicle"].id,
            "actual_long_distance": actual_long_distance,
            "safe_long_distance": safe_long_distance,
            "actual_lat_distance": actual_lat_distance,
            "safe_lat_distance": safe_lat_distance,
            "long_danger": long_danger,
            "lat_danger": lat_danger,
            "danger": danger,
        }

        return danger, info

    def update(self, control_auto, ids_alert=False, ids_last_time=None, ids_source=None):
        rss_danger, rss_info = self.check_rss_danger()
        self.offroad_checker.update()
        offroad_risk = self.offroad_checker._offroad_active
        rss_info["offroad_risk"] = offroad_risk
        safety_risk = rss_danger or offroad_risk
        
        ego_speed = self._speed(self.ego)

        speed_risk = ego_speed > 10.0   # m/s, about 43 km/h;
        rss_info["ego_speed"] = ego_speed
        rss_info["speed_risk"] = speed_risk
        steer_risk = control_auto.steer > 0.3
        emergency_risk = rss_danger or offroad_risk or speed_risk or steer_risk
        
        now = self._time()

        if not hasattr(self, "last_seen_ids_time"):
            self.last_new_ids_sim_time = None
            self.ids_recent_timeout = 1.0
            self.last_seen_ids_time = None
            self.observation_start_time = None
            self.observation_alert_count = 0
            self.safe_since = None
            self.mrc_active = False
            self.last_debug_print = 0

        # Detect only NEW IDS packets
        new_ids_alert = False
        if ids_alert and ids_last_time is not None:
            if ids_last_time != self.last_seen_ids_time:
                new_ids_alert = True
                self.last_seen_ids_time = ids_last_time
        
        # Record the simulation time when a new IDS alert arrives
        if new_ids_alert:
            self.last_new_ids_sim_time = now

        # IDS is considered recent only for a short time after the latest new alert
        recent_ids_alert = (
            self.last_new_ids_sim_time is not None
            and now - self.last_new_ids_sim_time <= self.ids_recent_timeout
        )

        # Debug every 1 second
        if self.debug and now - self.last_debug_print >= 1.0:
            obs_elapsed = 0.0
            state_elapsed = self._state_duration()
            if self.observation_start_time is not None:
                obs_elapsed = now - self.observation_start_time
                

            print(
                f"[RSS DEBUG] state={self.state} | "
                f"ids_alert={ids_alert} | "
                f"new_ids={new_ids_alert} | "
                f"obs_time={obs_elapsed:.1f}/{self.observation_time}s | "
                f"state_time={state_elapsed:.1f}/{self.max_safety_time}s | "
                f"obs_count={self.observation_alert_count} | "
                f"rss_danger={rss_danger} | "
                f"offroad={offroad_risk} | "
                f"speed={ego_speed} | "
                f"speedrisk={speed_risk} | "
                f"safety_risk={safety_risk} | "
                f"long={rss_info.get('long_danger')} | "
                f"lat={rss_info.get('lat_danger')} | "
                f"mrc={self.mrc_active}"
            )
            self.last_debug_print = now

        def clear_ids_flag():
            if ids_source is not None:
                ids_source.ids_alert = False
                if hasattr(ids_source, "cancontrol_flag"):
                    ids_source.cancontrol_flag = True

        # -------------------------
        # State transition logic
        # -------------------------

        if self.state == self.NORMAL:
            if new_ids_alert:
                if emergency_risk:
                    print("[RSS CHECK] IDS alert + emergency physical risk. Normal -> Safety")
                    self._set_state(self.SAFETY)
                    
                else:
                    self.observation_start_time = now
                    self.observation_alert_count = 1
                    self._set_state(self.OBSERVATION)

        elif self.state == self.OBSERVATION:                      
            if new_ids_alert:
                self.observation_alert_count += 1
                
            if ids_alert and emergency_risk:
                print("[RSS CHECK] Emergency physical risk detected. Observation -> Safety")
                self._set_state(self.SAFETY)
                self.mrc_active = True
            obs_elapsed = now - self.observation_start_time

            if obs_elapsed >= self.observation_time:
                if self.observation_alert_count >= 2 and safety_risk:
                    print("[RSS CHECK] Repeated IDS alerts + safety risk. Observation -> Safety")
                    self._set_state(self.SAFETY)
                else:
                    print("[RSS CHECK] Observation finished. Condition not enough. Observation -> Normal")
                    self.observation_start_time = None
                    self.observation_alert_count = 0
                    clear_ids_flag()
                    self._set_state(self.NORMAL)

        elif self.state == self.SAFETY:
            # Escalate to MRC only if attack is still actively coming
            if self._state_duration() >= self.max_safety_time and recent_ids_alert and safety_risk:
                if not self.mrc_active:
                    print("[RSS CHECK] Persistent attack + safety risk. Safety -> MRC")
                self.mrc_active = True

            # Recovery condition:
            # no recent IDS alert AND no RSS danger.
            # Off-road does not block recovery forever, because the agent may need control back to return to the road.
            if not recent_ids_alert and not rss_danger:
                if self.safe_since is None:
                    self.safe_since = now
                    print("[RSS CHECK] IDS quiet and no RSS danger. Starting recovery timer.")
                elif now - self.safe_since >= 1.5:
                    print("[RSS CHECK] Safe long enough. Safety -> Recovery")
                    self.safe_since = None
                    self.mrc_active = False
                    self.observation_start_time = None
                    self.observation_alert_count = 0
                    clear_ids_flag()
                    self._set_state(self.RECOVERY)
            else:
                self.safe_since = None

        elif self.state == self.RECOVERY:
            if new_ids_alert and safety_risk:
                print("[RSS CHECK] Alert and danger returned. Recovery -> Safety")
                self._set_state(self.SAFETY)

            elif new_ids_alert:
                print("[RSS CHECK] Alert returned. Recovery -> Observation")
                self.observation_start_time = now
                self.observation_alert_count = 1
                self._set_state(self.OBSERVATION)

            elif self._state_duration() >= self.recovery_time:
                print("[RSS CHECK] Recovery completed. Recovery -> Normal")
                clear_ids_flag()
                self._set_state(self.NORMAL)

        # -------------------------
        # Control action
        # -------------------------

        if self.state == self.NORMAL:
            return control_auto, self.state, rss_info

        if self.state == self.OBSERVATION:
            # Paper logic: still use agent control
            return control_auto, self.state, rss_info

        if self.state == self.SAFETY:
            if self.mrc_active:
                control_auto.throttle = 0.0
                control_auto.steer = 0.00
                control_auto.brake = max(control_auto.brake, 0.8)
                rss_info["mrc_active"] = True
                return control_auto, "Safety_MRC", rss_info

            if recent_ids_alert and emergency_risk:
                control_auto.throttle = 0.2
                control_auto.brake = max(control_auto.brake, 0.4)
                control_auto.steer *= -0.3
            else:
                control_auto.throttle = min(control_auto.throttle, 0.3)
                control_auto.brake = min(control_auto.brake, 0.2)

            rss_info["mrc_active"] = False
            return control_auto, self.state, rss_info

        if self.state == self.RECOVERY:
            control_auto.throttle *= self.recovery_speed_factor
            control_auto.brake = min(control_auto.brake, 0.1)
            return control_auto, self.state, rss_info

        return control_auto, self.state, rss_info