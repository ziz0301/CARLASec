#!/usr/bin/env python
#
# Copyright (c) 2018 Intel Labs.
# authors: German Ros (german.ros@intel.com)
#
# This work is licensed under the terms of the MIT license.
# For a copy, see <https://opensource.org/licenses/MIT>.
#
# This file is extracted from CARLA example automatic_control.py
#


import carla
import math
import collections
import weakref
import json
from world_setup.utils import get_actor_display_name, get_actor_category
# ==============================================================================
# -- CollisionSensor -----------------------------------------------------------
# ==============================================================================


class CollisionSensor(object):
    COLLISION_RADIUS = 5  # Two collisions that happen within this distance count as one
    MAX_ID_TIME = 5  # Two collisions with the same id that happen within this time count as one
    EPSILON = 0.1  # Collisions at lower this speed won't be counted as the actor's fault

    def __init__(self, parent_actor, hud):
        self._init_parameters(parent_actor, hud)
        self._init_collision_history()
        self._setup_collision_sensor(parent_actor)

    def _init_parameters(self, parent_actor, hud):
        self._parent = parent_actor
        self.hud = hud
        self.PENALTY_COLLISION_PEDESTRIAN = 0.5
        self.PENALTY_COLLISION_VEHICLE = 0.6
        self.PENALTY_COLLISION_STATIC = 0.65
        self.count_collision_pedestrians = 0
        self.count_collision_vehicles = 0
        self.count_collision_others = 0
        self.count_all_collisions = 0
        self.score_collision_pedestrians = 1
        self.score_collision_vehicles = 1
        self.score_collision_others = 1
        self._last_collision_time = 0
        self._collision_id = None
        self._collision_location = None

    def _init_collision_history(self):
        self.history = []
        self.full_history = {
            "Collisions with layout": [],
            "Collisions with pedestrians": [],
            "Collisions with vehicles": []
        }

    def _setup_collision_sensor(self, parent_actor):
        world = parent_actor.get_world()
        bp = world.get_blueprint_library().find('sensor.other.collision')
        self.sensor = world.spawn_actor(bp, carla.Transform(), attach_to=parent_actor)
        weak_self = weakref.ref(self)
        self.sensor.listen(lambda event: CollisionSensor._on_collision(weak_self, event))


    def get_collision_history(self):
        history = collections.defaultdict(int)
        for frame, intensity in self.history:
            history[frame] += intensity
        return history

    def get_full_collision_history(self):
        for collision_type, collisions in self.full_history.items():
            print(f"--- {collision_type} ---")
            for collision in collisions:
                print(collision)

    def count_total_collisions(self):
        total_collisions = sum(len(collisions) for collisions in self.full_history.values())
        return total_collisions

    @staticmethod
    def _on_collision(weak_self, event):
        self = weak_self()
        if not self:
            return
        #print(f"event.other_actor: {event.other_actor}")
        #print(f"event.other_actor.type_id: {event.other_actor.type_id}")
        actor_category = get_actor_category(event.other_actor.type_id)
        actor_type = get_actor_display_name(event.other_actor)
        self.hud.notification('Collision with %r' % actor_type)

        #Add the new counting, filtering same actor and within the specified distance and time threshold
        actor_location = self._parent.get_location()
        current_time = event.timestamp

        # Check for duplicate collisions based on ID and location
        if self._collision_id == event.other_actor.id:
            distance_vector = actor_location - self._collision_location
            time_diff = current_time - self._last_collision_time
            if distance_vector.length() <= self.COLLISION_RADIUS and time_diff <= self.MAX_ID_TIME:
                return

        # Update last collision details
        self._collision_id = event.other_actor.id
        self._collision_location = actor_location
        self._last_collision_time = current_time

        # If the actor speed is 0, the collision isn't its fault
        v = self._parent.get_velocity()
        parent_velocity = (3.6 * math.sqrt(v.x**2 + v.y**2 + v.z**2))
        if parent_velocity < self.EPSILON:
            return

        impulse = event.normal_impulse
        intensity = math.sqrt(impulse.x**2 + impulse.y**2 + impulse.z**2)

        # Update collision counts
        if actor_category == 'walker':
            self.score_collision_pedestrians *= self.PENALTY_COLLISION_PEDESTRIAN / intensity
            self.count_collision_pedestrians += 1
            history_key = "Collisions with pedestrians"
        elif actor_category == 'vehicle':
            self.score_collision_vehicles = self.PENALTY_COLLISION_VEHICLE / intensity
            self.count_collision_vehicles += 1
            history_key = "Collisions with vehicles"
        else:
            self.score_collision_others = self.PENALTY_COLLISION_STATIC / intensity
            self.count_collision_others += 1
            history_key = "Collisions with layout"
        self._store_collision_details(event, history_key)

    def _store_collision_details(self, event, history_key):
        # Append collision details to the history
        actor_type = event.other_actor.type_id
        actor_id = event.other_actor.id
        x, y, z = event.other_actor.get_location().x, event.other_actor.get_location().y, event.other_actor.get_location().z
        impulse = event.normal_impulse
        intensity = math.sqrt(impulse.x**2 + impulse.y**2 + impulse.z**2)
        collision_details = "Agent collided against object with type={} and id={} at (x={}, y={}, z={}) with intensity={}".format(actor_type, actor_id, x, y, z, intensity)
        self.full_history[history_key].append(collision_details)

# ==============================================================================
# -- LaneInvasionSensor --------------------------------------------------------
# ==============================================================================


class LaneInvasionSensor(object):
    """Class for lane invasion sensors"""

    def __init__(self, parent_actor, hud):
        """Constructor method"""
        self.sensor = None
        self._parent = parent_actor
        self.hud = hud
        self.count_lane_intersect = 0
        world = self._parent.get_world()
        bp = world.get_blueprint_library().find('sensor.other.lane_invasion')
        self.sensor = world.spawn_actor(bp, carla.Transform(), attach_to=self._parent)
        # We need to pass the lambda a weak reference to self to avoid circular
        # reference.
        weak_self = weakref.ref(self)
        self.sensor.listen(lambda event: LaneInvasionSensor._on_invasion(weak_self, event))

    @staticmethod
    def _on_invasion(weak_self, event):
        """On invasion method"""
        self = weak_self()
        if not self:
            return

        lane_types = set(x.type for x in event.crossed_lane_markings)
        text = ['%r' % str(x).split()[-1] for x in lane_types]
        self.hud.notification('Crossed line %s' % ' and '.join(text))
        self.count_lane_intersect += 1

    def _log_lane_deviations(self, actor):
        location = actor.get_transform().location
        message = "Agent ran go off road at location (x={}, y={}, z={}) and time {}".format(
            round(location.x, 3),
            round(location.y, 3),
            round(location.z, 3),
            datetime.datetime.now().isoformat())
        self.infractions['Off-road infractions'].append(message)
# ==============================================================================
# -- GnssSensor --------------------------------------------------------
# ==============================================================================


class GnssSensor(object):
    """ Class for GNSS sensors"""

    def __init__(self, parent_actor):
        """Constructor method"""
        self.sensor = None
        self._parent = parent_actor
        self.lat = 0.0
        self.lon = 0.0
        world = self._parent.get_world()
        blueprint = world.get_blueprint_library().find('sensor.other.gnss')
        self.sensor = world.spawn_actor(blueprint, carla.Transform(carla.Location(x=1.0, z=2.8)),
                                        attach_to=self._parent)
        # We need to pass the lambda a weak reference to
        # self to avoid circular reference.
        weak_self = weakref.ref(self)
        self.sensor.listen(lambda event: GnssSensor._on_gnss_event(weak_self, event))

    @staticmethod
    def _on_gnss_event(weak_self, event):
        """GNSS method"""
        self = weak_self()
        if not self:
            return
        self.lat = event.latitude
        self.lon = event.longitude
