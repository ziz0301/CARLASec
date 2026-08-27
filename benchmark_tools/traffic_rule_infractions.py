#!/usr/bin/env python

# This code is derived from 'atomic_criteria.py' in the CARLA Scenario Runner project.
# The original code is available at: https://github.com/carla-simulator/scenario_runner
# Modifications made to the original code include:
# - Counting instances when the vehicle violates stop signs.
# - Counting instances when the vehicle violates red light traffic signals.
# - Counting instances when the vehicle goes off the road.
# These counts are used to formulate safety metrics for the vehicles.
# Author: ziz0301 - Mail: ziz0301@gmail.com
# This code is part of CARLASec, a PhD research project on cybersecurity and safety evaluation for autonomous vehicles.



import sys
import os
import math
import numpy as np
import shapely.geometry
from shapely import box, LineString, normalize, Polygon
import logging
import datetime

import carla


try:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
except IndexError:
    pass


class CountRunningStopViolation:
    PROXIMITY_THRESHOLD = 4.0  # Stops closer than this distance will be detected [m]
    SPEED_THRESHOLD = 0.1 # Minimum speed to consider the actor has stopped [m/s]
    WAYPOINT_STEP = 0.5  #

    def __init__(self, actor, map, world):
        self.actor = actor
        self._map = map
        self._world = world

        self._list_stop_signs = []
        self._target_stop_sign = None
        self._stop_completed = False
        self._count_runningstop_violation = 0
        self._last_failed_stop = None

        self.infractions = {
            "Stop sign infractions": []
        }

        for _actor in self._world.get_actors():
            if 'traffic.stop' in _actor.type_id:
                self._list_stop_signs.append(_actor)

    def update(self):
        """
        Check if the actor is running a red light
        """
        actor_transform = self.actor.get_transform()
        check_wps = self._get_waypoints(self.actor)
        self._target_stop_sign = self._scan_for_stop_sign(actor_transform, check_wps)

        if self._target_stop_sign:
            actor_vec = self.actor.get_velocity()
            current_speed = math.sqrt(actor_vec.x**2 + actor_vec.y**2 + actor_vec.z**2)
            if current_speed < self.SPEED_THRESHOLD:
                self._stop_completed = True

            if not self._stop_completed and self._last_failed_stop != self._target_stop_sign.id:
                self._count_runningstop_violation += 1
                print(f"Stop sign violation: {self._count_runningstop_violation}")
                self.log_stoprun_violation(self._target_stop_sign)
                self._last_failed_stop = self._target_stop_sign.id

            if not self.is_actor_affected_by_stop(check_wps, self._target_stop_sign):
	            self._target_stop_sign = None
	            self._stop_completed = False


    def get_violation_count(self):
        return self._count_runningstop_violation

    def log_stoprun_violation(self, stopsign):
        """
        Log the stop sign run violation to a file.
        """
        stop_location = stopsign.get_transform().location
        message = "Agent ran a stop sign with id={} at (x={}, y={}, z={})".format(
            self._target_stop_sign.id,
            round(stop_location.x, 3),
            round(stop_location.y, 3),
            round(stop_location.z, 3))
        self.infractions['Stop sign infractions'].append(message)
        #log_dict = {'id': self._target_stop_sign.id, 'location': stop_location}

        #with open("violation_log.txt", "a") as file:
        #    file.write("Stop sign violation \n")
        #    file.write(f"{message}\n{log_dict}\n")

    def _get_waypoints(self, actor):
        """Returns a list of waypoints starting from the ego location and a set amount forward"""
        wp_list = []
        steps = int(self.PROXIMITY_THRESHOLD / self.WAYPOINT_STEP)

        # Add the actor location
        wp = self._map.get_waypoint(actor.get_location())
        wp_list.append(wp)

        # And its forward waypoints
        next_wp = wp
        for _ in range(steps):
            next_wps = next_wp.next(self.WAYPOINT_STEP)
            if not next_wps:
                break
            next_wp = next_wps[0]
            wp_list.append(next_wp)

        return wp_list

    def _scan_for_stop_sign(self, actor_transform, wp_list):
        """
        Check the stop signs to see if any of them affect the actor.
        Ignore all checks when going backwards or through an opposite direction"""

        actor_direction = actor_transform.get_forward_vector()
        # Ignore all when going backwards
        actor_velocity = self.actor.get_velocity()
        if actor_velocity.dot(actor_direction) < -0.17:  # 100º, just in case
            return None

        # Ignore all when going in the opposite direction
        lane_direction = wp_list[0].transform.get_forward_vector()
        if actor_direction.dot(lane_direction) < -0.17:  # 100º, just in case
            return None

        for stop in self._list_stop_signs:
            if self.is_actor_affected_by_stop(wp_list, stop):
                return stop

    def is_actor_affected_by_stop(self, wp_list, stop):
        """
        Check if the given actor is affected by the stop.
        Without using waypoints, a stop might not be detected if the actor is moving at the lane edge.
        """
        # Quick distance test
        stop_location = stop.get_transform().transform(stop.trigger_volume.location)
        actor_location = wp_list[0].transform.location
        if stop_location.distance(actor_location) > self.PROXIMITY_THRESHOLD:
            return False

        # Check if the any of the actor wps is inside the stop's bounding box.
        # Using more than one waypoint removes issues with small trigger volumes and backwards movement
        stop_extent = stop.trigger_volume.extent
        for actor_wp in wp_list:
            if self.point_inside_boundingbox(actor_wp.transform.location, stop_location, stop_extent):
                return True
        return False

    def point_inside_boundingbox(self, point, bb_center, bb_extent, multiplier=1.2):
        """Checks whether or not a point is inside a bounding box."""
        # pylint: disable=invalid-name
        A = carla.Vector2D(bb_center.x - multiplier * bb_extent.x, bb_center.y - multiplier * bb_extent.y)
        B = carla.Vector2D(bb_center.x + multiplier * bb_extent.x, bb_center.y - multiplier * bb_extent.y)
        D = carla.Vector2D(bb_center.x - multiplier * bb_extent.x, bb_center.y + multiplier * bb_extent.y)
        M = carla.Vector2D(point.x, point.y)

        AB = B - A
        AD = D - A
        AM = M - A
        am_ab = AM.x * AB.x + AM.y * AB.y
        ab_ab = AB.x * AB.x + AB.y * AB.y
        am_ad = AM.x * AD.x + AM.y * AD.y
        ad_ad = AD.x * AD.x + AD.y * AD.y

        return am_ab > 0 and am_ab < ab_ab and am_ad > 0 and am_ad < ad_ad


class CountRunningRedLightViolation:
    """
    Check if an actor is running a red light

    Important parameters:
    - actor: CARLA actor to be used for this test
    """
    DISTANCE_LIGHT = 15  # m

    def __init__(self, actor, map, world):
        self.actor = actor
        self._world = world
        self._map = map
        self._red_light_violation_count = 0
        self._list_traffic_lights = []
        self._last_red_light_id = None
        self.debug = False
        self.infractions = {
            "Red lights infractions": []
        }

        all_actors = self._world.get_actors()
        for _actor in all_actors:
            if 'traffic_light' in _actor.type_id:
                center, waypoints = self.get_traffic_light_waypoints(_actor)
                self._list_traffic_lights.append((_actor, center, waypoints))

    # pylint: disable=no-self-use
    def is_vehicle_crossing_line(self, seg1, seg2):
        """
        check if vehicle crosses a line segment
        """
        line1 = shapely.geometry.LineString([(seg1[0].x, seg1[0].y), (seg1[1].x, seg1[1].y)])
        line2 = shapely.geometry.LineString([(seg2[0].x, seg2[0].y), (seg2[1].x, seg2[1].y)])
        inter = line1.intersection(line2)
        return not inter.is_empty

    def update(self):
        """
        Check if the actor is running a red light
        """

        transform = self.actor.get_transform()
        location = transform.location

        veh_extent = self.actor.bounding_box.extent.x

        tail_close_pt = self.rotate_point(carla.Vector3D(-0.8 * veh_extent, 0, 0), transform.rotation.yaw)
        tail_close_pt = location + carla.Location(tail_close_pt)

        tail_far_pt = self.rotate_point(carla.Vector3D(-veh_extent - 1, 0, 0), transform.rotation.yaw)
        tail_far_pt = location + carla.Location(tail_far_pt)

        for traffic_light, center, waypoints in self._list_traffic_lights:
            center_loc = carla.Location(center)

            if self._last_red_light_id and self._last_red_light_id == traffic_light.id:
                continue
            if center_loc.distance(location) > self.DISTANCE_LIGHT:
                continue
            if traffic_light.state != carla.TrafficLightState.Red:
                continue

            for wp in waypoints:
                tail_wp = self._map.get_waypoint(tail_far_pt)
                # Calculate the dot product (Might be unscaled, as only its sign is important)
                ve_dir = self.actor.get_transform().get_forward_vector()
                wp_dir = wp.transform.get_forward_vector()

                # Check the lane until all the "tail" has passed

                if tail_wp.road_id == wp.road_id and tail_wp.lane_id == wp.lane_id and ve_dir.dot(wp_dir) > 0:
                    # This light is red and is affecting our lane
                    yaw_wp = wp.transform.rotation.yaw
                    lane_width = wp.lane_width
                    location_wp = wp.transform.location

                    lft_lane_wp = self.rotate_point(carla.Vector3D(0.6 * lane_width, 0, 0), yaw_wp + 90)
                    lft_lane_wp = location_wp + carla.Location(lft_lane_wp)
                    rgt_lane_wp = self.rotate_point(carla.Vector3D(0.6 * lane_width, 0, 0), yaw_wp - 90)
                    rgt_lane_wp = location_wp + carla.Location(rgt_lane_wp)

                    # Is the vehicle traversing the stop line?
                    if self.is_vehicle_crossing_line((tail_close_pt, tail_far_pt), (lft_lane_wp, rgt_lane_wp)):
                        self._red_light_violation_count += 1
                        print(f"Red light violation: {self._red_light_violation_count}")
                        self.log_redlight_violation(traffic_light)
                        self._last_red_light_id = traffic_light.id
                        break

    def get_violation_count(self):
        return self._red_light_violation_count

    def log_redlight_violation(self, traffic_light):
        """
        Log the red light violation to a file.
        """
        location = traffic_light.get_transform().location
        message = "Agent ran a red light {} at location (x={}, y={}, z={}) and time {}".format(
            traffic_light.id,
            round(location.x, 3),
            round(location.y, 3),
            round(location.z, 3),
            datetime.datetime.now().isoformat()
        )
        self.infractions['Red lights infractions'].append(message)
        #log_dict = {'id': traffic_light.id, 'location': location, 'time': datetime.datetime.now().isoformat()}
        #with open("violation_log.txt", "a") as file:
        #    file.write("Red light run violation \n")
        #    file.write(f"{message}\n{log_dict}\n")

    def rotate_point(self, point, angle):
        """
        rotate a given point by a given angle
        """
        x_ = math.cos(math.radians(angle)) * point.x - math.sin(math.radians(angle)) * point.y
        y_ = math.sin(math.radians(angle)) * point.x + math.cos(math.radians(angle)) * point.y
        return carla.Vector3D(x_, y_, point.z)

    def get_traffic_light_waypoints(self, traffic_light):
        """
        get area of a given traffic light
        """
        base_transform = traffic_light.get_transform()
        base_rot = base_transform.rotation.yaw
        area_loc = base_transform.transform(traffic_light.trigger_volume.location)

        # Discretize the trigger box into points
        area_ext = traffic_light.trigger_volume.extent
        x_values = np.arange(-0.9 * area_ext.x, 0.9 * area_ext.x, 1.0)  # 0.9 to avoid crossing to adjacent lanes

        area = []
        for x in x_values:
            point = self.rotate_point(carla.Vector3D(x, 0, area_ext.z), base_rot)
            point_location = area_loc + carla.Location(x=point.x, y=point.y)
            area.append(point_location)

        # Get the waypoints of these points, removing duplicates
        ini_wps = []
        for pt in area:
            wpx = self._map.get_waypoint(pt)
            # As x_values are arranged in order, only the last one has to be checked
            if not ini_wps or ini_wps[-1].road_id != wpx.road_id or ini_wps[-1].lane_id != wpx.lane_id:
                ini_wps.append(wpx)

        # Advance them until the intersection
        wps = []
        for wpx in ini_wps:
            while not wpx.is_intersection:
                next_wp = wpx.next(0.5)[0]
                if next_wp and not next_wp.is_intersection:
                    wpx = next_wp
                else:
                    break
            wps.append(wpx)

        return area_loc, wps


class CountOffRoadViolation:
    def __init__(self, actor, map):
        self.actor = actor
        self._map = map
        self._offroad_active = False
        self._count_offroad_violation = 0
        self.infractions = {
            "Off-road infractions": []
        }

    def update(self):
        current_tra = self.actor.get_transform()
        current_loc = current_tra.location
        # Calculate the vehicle's bounding box corners
        bbox_corners = self._get_bounding_box_corners(current_tra)
        # Check if the vehicle is outside of the designated driving lanes or on the sidewalk
        valid_lane_types = [carla.LaneType.Driving, carla.LaneType.Parking, carla.LaneType.Bidirectional, carla.LaneType.Shoulder]
        offroad = any(
            self._map.get_waypoint(corner, lane_type=carla.LaneType.Any).lane_type not in valid_lane_types
            for corner in bbox_corners
        )
        # Check for offroad violation
        if offroad and not self._offroad_active:
            self._offroad_active = True
            self._count_offroad_violation += 1
            self.log_offroad_violation(self.actor)
            print("CAR go off road!!!")
        elif not offroad and self._offroad_active:
            self._offroad_active = False

        #print(f"Count offroad violation: {self._count_offroad_violation}")

    def _get_bounding_box_corners(self, transform):
        """Calculate the corners of the vehicle's bounding box."""
        bbox = self.actor.bounding_box
        corners = []
        for corner in [carla.Location(x=-bbox.extent.x, y=-bbox.extent.y),
                       carla.Location(x=bbox.extent.x, y=-bbox.extent.y),
                       carla.Location(x=bbox.extent.x, y=bbox.extent.y),
                       carla.Location(x=-bbox.extent.x, y=bbox.extent.y)]:
            corners.append(transform.transform(corner))
        return corners

    def get_offroad_count(self):
        return self._count_offroad_violation

    def log_offroad_violation(self, actor):
        location = actor.get_transform().location
        message = "Agent ran go off road at location (x={}, y={}, z={}) and time {}".format(
            round(location.x, 3),
            round(location.y, 3),
            round(location.z, 3),
            datetime.datetime.now().isoformat()
        )
        self.infractions['Off-road infractions'].append(message)


class CountOnSidewalkViolation:
    def __init__(self, actor, map, current_game_time):
        self.actor = actor
        self._map = map
        self._time_on_sidewalk = 0
        self._prev_time = None
        self._onsidewalk_active = False
        self._countnumberonsidewalk = 0
        self._current_game_time = current_game_time

    def update(self):
        current_tra = self.actor.get_transform()
        current_loc = current_tra.location
        bbox_corners = self._get_bounding_box_corners(current_tra)
        on_sidewalk = any(
            self._map.get_waypoint(corner, lane_type=carla.LaneType.Any).lane_type == carla.LaneType.Sidewalk
            for corner in bbox_corners
        )

        # Update time on sidewalk
        if on_sidewalk:
            if not self._onsidewalk_active:
                self._onsidewalk_active = True
                self._countnumberonsidewalk += 1
                if self._prev_time is None:
                    self._prev_time = self._current_game_time
            else:
                curr_time = self._current_game_time
                self._time_on_sidewalk += curr_time - self._prev_time
                self._prev_time = curr_time

        else:
            self._onsidewalk_active = False
            self._prev_time = None

        print(f"self._time_on_sidewalk:{self._time_on_sidewalk}")
        print(f"self._countnumberonsidewalk:{self._countnumberonsidewalk}")

    def get_time_on_sidewalk(self):
        return self._countnumberonsidewalk

    def _get_bounding_box_corners(self, transform):
        """Calculate the corners of the vehicle's bounding box."""
        bbox = self.actor.bounding_box
        corners = []
        for corner in [carla.Location(x=-bbox.extent.x, y=-bbox.extent.y),
                       carla.Location(x=bbox.extent.x, y=-bbox.extent.y),
                       carla.Location(x=bbox.extent.x, y=bbox.extent.y),
                       carla.Location(x=-bbox.extent.x, y=bbox.extent.y)]:
            corners.append(transform.transform(carla.Location(corner)))
        return corners
