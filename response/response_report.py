"""
response_report.py

Small helper for CARLASec response experiments.
Place this file in the `response/` folder. It creates `response/log/`
automatically and saves each run as run1.txt, run2.txt, ...

Typical use in client_run_response.py:

    from response.response_report import ResponseRunReport

    report = ResponseRunReport(
        attack_type=getattr(args, "attack_type", "unknown"),
        controller_mode="proposed_response",
    )

    # inside the main simulation loop, after rss_response.update(...):
    report.update_tick(
        sim_time=world.world.get_snapshot().timestamp.elapsed_seconds,
        state=response_state,
        ids_alert=getattr(scenario, "ids_alert", False),
        ids_last_time=getattr(scenario, "last_ids_time", None),
        ego_speed=rss_info.get("ego_speed"),
        distance_travelled=safety_metrics.total_distance_meters,
        rss_info=rss_info,
    )

    # inside finally, after data_exporter.results, data_exporter.infractions,
    # and safety_analyse are available:
    report.finalize(
        results=data_exporter.results,
        infractions=data_exporter.infractions,
        safety_analyse=safety_analyse,
        args=args,
        extra={"fully_completed": fully_completed},
    )
"""

from __future__ import annotations

import json
import math
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


class ResponseRunReport:
    """Collects run-level metrics and writes an experiment report to response/log."""

    STATE_NORMAL = "Normal"
    STATE_OBSERVATION = "Observation"
    STATE_SAFETY = "Safety"
    STATE_RECOVERY = "Recovery"
    STATE_MRC = "Safety_MRC"

    REPORT_FIELDS = [
        "attack_type",
        "controller_mode",
        "run_id",
        "start_positon",
        "number_of_vehicles",
        "number_of_walker",
        "destination_position",
        "Duration",
        "Red_light_infractions",
        "Stop_sign_infractions",
        "Offroad_infractions",
        "collision_pedestrian_count",
        "list_of_collision_pedestrian_infraction",
        "collision_static_count",
        "list_of_collision_static_infraction",
        "collision_vehicle_count",
        "list_of_collision_vehicle_infraction",
        "offroad_count",
        "Total distance traveled",
        "number_of_IDS_alerts",
        "number_of_Safety_transitions",
        "number_of_MRC_transitions",
        "time_to_Observation",
        "time_to_Safety",
        "time_to_MRC",
        "time_to_Recovery",
        "time_spent_in_Normal",
        "time_spent_in_Observation",
        "time_spent_in_Safety",
        "time_spent_in_Recovery",
        "maximum_speed",
        "mean_speed",
    ]

    def __init__(
        self,
        attack_type: str = "unknown",
        controller_mode: str = "unknown",
        log_dir: Optional[str | Path] = None,
        run_id: Optional[int] = None,
    ) -> None:
        self.attack_type = attack_type
        self.controller_mode = controller_mode

        # If this file is placed in response/, the log folder becomes response/log/.
        self.log_dir = Path(log_dir) if log_dir is not None else Path(__file__).resolve().parent / "log"
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.run_id = run_id if run_id is not None else self._next_run_id()
        self.txt_path = self.log_dir / f"run{self.run_id}.txt"
        self.json_path = self.log_dir / f"run{self.run_id}.json"

        self.wall_start_time = time.time()
        self.first_sim_time: Optional[float] = None
        self.last_sim_time: Optional[float] = None
        self.last_tick_time: Optional[float] = None

        self.last_state: Optional[str] = None
        self.last_ids_time: Any = None
        self.last_mrc_active = False

        self.number_of_IDS_alerts = 0
        self.number_of_Safety_transitions = 0
        self.number_of_MRC_transitions = 0

        self.time_to_Observation: Optional[float] = None
        self.time_to_Safety: Optional[float] = None
        self.time_to_MRC: Optional[float] = None
        self.time_to_Recovery: Optional[float] = None

        self.state_time = {
            self.STATE_NORMAL: 0.0,
            self.STATE_OBSERVATION: 0.0,
            self.STATE_SAFETY: 0.0,
            self.STATE_RECOVERY: 0.0,
        }

        self.speed_sum = 0.0
        self.speed_count = 0
        self.maximum_speed = 0.0
        self.latest_distance_travelled = 0.0
        self.tick_records = []  # optional detailed timeline for debugging/plotting

    def _next_run_id(self) -> int:
        existing_ids = []
        for path in self.log_dir.glob("run*.*"):
            match = re.match(r"run(\d+)\.", path.name)
            if match:
                existing_ids.append(int(match.group(1)))
        return max(existing_ids, default=0) + 1

    @staticmethod
    def _normalise_state(state: Optional[str]) -> str:
        if state == ResponseRunReport.STATE_MRC:
            return ResponseRunReport.STATE_SAFETY
        if state in {
            ResponseRunReport.STATE_NORMAL,
            ResponseRunReport.STATE_OBSERVATION,
            ResponseRunReport.STATE_SAFETY,
            ResponseRunReport.STATE_RECOVERY,
        }:
            return state
        return ResponseRunReport.STATE_NORMAL

    @staticmethod
    def _safe_float(value: Any, default: Optional[float] = None) -> Optional[float]:
        try:
            if value is None:
                return default
            value = float(value)
            if math.isnan(value) or math.isinf(value):
                return default
            return value
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _serialise(value: Any) -> Any:
        """Convert CARLA objects and other objects to readable strings/lists."""
        if value is None:
            return None
        if isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, dict):
            return {str(k): ResponseRunReport._serialise(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [ResponseRunReport._serialise(v) for v in value]

        # CARLA Location/Rotation/Transform-like objects are easier to read this way.
        attrs = []
        for attr in ("x", "y", "z"):
            if hasattr(value, attr):
                attrs.append(f"{attr}={getattr(value, attr):.3f}")
        if attrs:
            return ", ".join(attrs)
        return str(value)

    def _elapsed_from_start(self, sim_time: float) -> float:
        if self.first_sim_time is None:
            self.first_sim_time = sim_time
        return sim_time - self.first_sim_time

    def update_tick(
        self,
        sim_time: float,
        state: Optional[str],
        ids_alert: bool = False,
        ids_last_time: Any = None,
        ego_speed: Optional[float] = None,
        distance_travelled: Optional[float] = None,
        rss_info: Optional[Dict[str, Any]] = None,
        store_timeline: bool = True,
    ) -> None:
        """Call once per simulation tick."""
        sim_time = float(sim_time)
        elapsed = self._elapsed_from_start(sim_time)
        current_state = self._normalise_state(state)
        is_mrc = state == self.STATE_MRC or bool((rss_info or {}).get("mrc_active", False))

        # Accumulate time spent in the previous state.
        if self.last_tick_time is not None and self.last_state is not None:
            dt = max(0.0, sim_time - self.last_tick_time)
            self.state_time[self._normalise_state(self.last_state)] += dt

        # Count new IDS packets if ids_last_time is available; otherwise count rising edge.
        if ids_alert:
            if ids_last_time is not None:
                if ids_last_time != self.last_ids_time:
                    self.number_of_IDS_alerts += 1
                    self.last_ids_time = ids_last_time
            elif not getattr(self, "_previous_ids_alert", False):
                self.number_of_IDS_alerts += 1
        self._previous_ids_alert = bool(ids_alert)

        # Count transitions and first arrival times.
        if self.last_state is not None and current_state != self._normalise_state(self.last_state):
            if current_state == self.STATE_SAFETY:
                self.number_of_Safety_transitions += 1
            if current_state == self.STATE_OBSERVATION and self.time_to_Observation is None:
                self.time_to_Observation = elapsed
            if current_state == self.STATE_SAFETY and self.time_to_Safety is None:
                self.time_to_Safety = elapsed
            if current_state == self.STATE_RECOVERY and self.time_to_Recovery is None:
                self.time_to_Recovery = elapsed

        # If the first state observed is already not Normal, record its time as zero.
        if self.last_state is None:
            if current_state == self.STATE_OBSERVATION:
                self.time_to_Observation = 0.0
            elif current_state == self.STATE_SAFETY:
                self.time_to_Safety = 0.0
            elif current_state == self.STATE_RECOVERY:
                self.time_to_Recovery = 0.0

        # Count first activation of MRC episodes.
        if is_mrc and not self.last_mrc_active:
            self.number_of_MRC_transitions += 1
            if self.time_to_MRC is None:
                self.time_to_MRC = elapsed
        self.last_mrc_active = is_mrc

        speed = self._safe_float(ego_speed)
        if speed is not None:
            self.maximum_speed = max(self.maximum_speed, speed)
            self.speed_sum += speed
            self.speed_count += 1

        distance = self._safe_float(distance_travelled)
        if distance is not None:
            self.latest_distance_travelled = distance

        self.last_tick_time = sim_time
        self.last_sim_time = sim_time
        self.last_state = state

        if store_timeline:
            self.tick_records.append(
                {
                    "time": round(elapsed, 3),
                    "state": state,
                    "ids_alert": bool(ids_alert),
                    "ego_speed": speed,
                    "distance_travelled": distance,
                    "mrc_active": is_mrc,
                    "rss_info": self._serialise(rss_info or {}),
                }
            )

    def _finish_time_accounting(self) -> None:
        if self.last_tick_time is not None and self.last_state is not None and self.last_sim_time is not None:
            # No extra dt is added here because update_tick already accounts up to the latest tick.
            pass

    def _get_infraction_list(self, infractions: Optional[Dict[str, Iterable[Any]]], key: str) -> list:
        if not infractions:
            return []
        return list(infractions.get(key, []))

    def build_summary(
        self,
        results: Optional[Dict[str, Any]] = None,
        infractions: Optional[Dict[str, Iterable[Any]]] = None,
        safety_analyse: Optional[Dict[str, Any]] = None,
        args: Optional[Any] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build the final summary dictionary without writing files."""
        self._finish_time_accounting()
        results = results or {}
        safety_analyse = safety_analyse or {}
        extra = extra or {}

        ped_list = self._get_infraction_list(infractions, "Collisions with pedestrians")
        static_list = self._get_infraction_list(infractions, "Collisions with layout")
        vehicle_list = self._get_infraction_list(infractions, "Collisions with vehicles")

        duration = results.get("total_time_run")
        if not duration:
            duration = time.time() - self.wall_start_time

        mean_speed = self.speed_sum / self.speed_count if self.speed_count else results.get("average_speed", 0.0)

        summary = {
            "attack_type": extra.get("attack_type", self.attack_type),
            "controller_mode": extra.get("controller_mode", self.controller_mode),
            "run_id": self.run_id,
            "start_positon": results.get("start_positon"),
            "number_of_vehicles": results.get("number_of_vehicles"),
            "number_of_walker": results.get("number_of_walker"),
            "destination_position": results.get("destination_position"),
            "Duration": duration,
            "Red_light_infractions": results.get("count_red_light_violation"),
            "Stop_sign_infractions": results.get("count_stop_sign_violation"),
            "Offroad_infractions": results.get("count_off_road"),
            "collision_pedestrian_count": results.get("count_collision_pedestrians", len(ped_list)),
            "list_of_collision_pedestrian_infraction": ped_list,
            "collision_static_count": results.get("count_collision_others", len(static_list)),
            "list_of_collision_static_infraction": static_list,
            "collision_vehicle_count": results.get("count_collision_vehicles", len(vehicle_list)),
            "list_of_collision_vehicle_infraction": vehicle_list,
            "offroad_count": results.get("count_off_road"),
            "Total distance traveled": results.get("total_metre_run", self.latest_distance_travelled),
            "number_of_IDS_alerts": self.number_of_IDS_alerts,
            "number_of_Safety_transitions": self.number_of_Safety_transitions,
            "number_of_MRC_transitions": self.number_of_MRC_transitions,
            "time_to_Observation": self.time_to_Observation,
            "time_to_Safety": self.time_to_Safety,
            "time_to_MRC": self.time_to_MRC,
            "time_to_Recovery": self.time_to_Recovery,
            "time_spent_in_Normal": self.state_time[self.STATE_NORMAL],
            "time_spent_in_Observation": self.state_time[self.STATE_OBSERVATION],
            "time_spent_in_Safety": self.state_time[self.STATE_SAFETY],
            "time_spent_in_Recovery": self.state_time[self.STATE_RECOVERY],
            "maximum_speed": self.maximum_speed,
            "mean_speed": mean_speed,
        }

        # Useful extra values, not required by your list but helpful for the paper.
        if safety_analyse:
            summary["DSR"] = safety_analyse.get("Driving_score")
            summary["Route_completion"] = safety_analyse.get("Route_completion")
            summary["Infraction_penalty"] = safety_analyse.get("Infraction_penalty")
        if args is not None:
            summary["weather"] = getattr(args, "weather", None)
            summary["agent"] = getattr(args, "agent", None)
            summary["seed"] = getattr(args, "seed", None)
        summary.update(extra)

        return {key: self._serialise(value) for key, value in summary.items()}

    def finalize(
        self,
        results: Optional[Dict[str, Any]] = None,
        infractions: Optional[Dict[str, Iterable[Any]]] = None,
        safety_analyse: Optional[Dict[str, Any]] = None,
        args: Optional[Any] = None,
        extra: Optional[Dict[str, Any]] = None,
        save_timeline: bool = True,
    ) -> Dict[str, Any]:
        """Write runN.txt and runN.json. Returns the summary dictionary."""
        summary = self.build_summary(results, infractions, safety_analyse, args, extra)

        with self.txt_path.open("w", encoding="utf-8") as f:
            f.write(f"RESPONSE EXPERIMENT REPORT - run{self.run_id}\n")
            f.write("=" * 60 + "\n\n")
            for field in self.REPORT_FIELDS:
                f.write(f"{field}: {summary.get(field)}\n")

            f.write("\nAdditional values\n")
            f.write("-" * 60 + "\n")
            for key, value in summary.items():
                if key not in self.REPORT_FIELDS:
                    f.write(f"{key}: {value}\n")

            if save_timeline:
                f.write("\nState timeline per tick\n")
                f.write("-" * 60 + "\n")
                for record in self.tick_records:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")

        json_payload = {"summary": summary}
        if save_timeline:
            json_payload["timeline"] = self.tick_records
        with self.json_path.open("w", encoding="utf-8") as f:
            json.dump(json_payload, f, indent=2, ensure_ascii=False, default=str)

        print(f"[ResponseRunReport] Saved report to {self.txt_path}")
        print(f"[ResponseRunReport] Saved JSON report to {self.json_path}")
        return summary
