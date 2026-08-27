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
from world_setup.utils import get_actor_display_name
# ==============================================================================
# -- CollisionSensor -----------------------------------------------------------
# ==============================================================================


class CollisionSensor(object):
    def __init__(self, parent_actor, hud):
        self._init_parameters(parent_actor, hud)
        self._init_collision_history()
        self._setup_collision_sensor(parent_actor)

    def _init_parameters(self, parent_actor, hud):
        self._parent = parent_actor
        self.hud = hud
        self.count_collision_pedestrians_tickbased = 0
        self.count_collision_vehicles_tickbased = 0
        self.count_collision_others_tickbased = 0
        self.count_collision_pedestrians = 0
        self.count_collision_vehicles = 0
        self.count_collision_others = 0
        self.count_all_collisions = 0
        self.frames_skip = {'walker': 5, 'vehicle': 10, 'other': 10}
        self.frames_recount = {'walker': 100, 'vehicle': 30, 'other': 20}
        self.threshold = {'walker': 300, 'vehicle': 400, 'other': 100}

    def _init_collision_history(self):
        self.history = []
        self.full_history = []

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
        with open('history.txt', 'w') as file:
            file.write(json.dumps(self.full_history, indent=4))
        return history

    def get_full_collision_history(self, filename):
        self.process_full_collision_history()
        print("Number of collisions with vehicles:", self.count_collision_vehicles)
        print("Number of collisions with pedestrians:", self.count_collision_pedestrians)
        print("Number of collisions with others:", self.count_collision_others)
        self.count_all_collisions = self.count_collision_vehicles + self.count_collision_pedestrians + self.count_collision_others
        with open(filename, 'w') as file:
            file.write(json.dumps(self.full_history, indent=4))
            file.write("\nNumber of collisions with vehicles: " + str(self.count_collision_vehicles))
            file.write("\nNumber of collisions with pedestrians: " + str(self.count_collision_pedestrians))
            file.write("\nNumber of collisions with others: " + str(self.count_collision_others))
            file.write("\nNumber of all collisions: " + str(self.count_all_collisions))
        return self.full_history

    def process_full_collision_history(self):
        self._reset_collision_counts()
        self._process_collision_data()

    def _reset_collision_counts(self):
        self.count_collision_pedestrians = 0
        self.count_collision_vehicles = 0
        self.count_collision_others = 0

    def _process_collision_data(self):
        for i in range(len(self.full_history)):
            if i < len(self.full_history) - 1:
                self._process_single_collision(i)

    def _process_single_collision(self, index):
        current_collision = self.full_history[index]
        current_actor2_type_id = current_collision["actor2_type"]
        actor_category = current_actor2_type_id.split('.')[0]
        #Match the actor_category with the parameters
        if 'vehicle' in actor_category:
            actor_category = 'vehicle'
        elif 'walker' in actor_category:
            actor_category = 'walker'
        else:
            actor_category = 'other'

        if index >= self.frames_skip[actor_category]:
            prev_collision = self.full_history[index - self.frames_skip[actor_category]]
            impulse_change = self.calculate_impulse_change(current_collision["impulse"], prev_collision["impulse"])

            if impulse_change > self.threshold[actor_category]:
                self.increment_collision_count(actor_category)
                index += self.frames_recount[actor_category] - 1

    def calculate_impulse_change(self, current_impulse, previous_impulse):
        current_magnitude = math.sqrt(sum(i**2 for i in current_impulse.values()))
        previous_magnitude = math.sqrt(sum(i**2 for i in previous_impulse.values()))
        return abs(current_magnitude - previous_magnitude)

    def increment_collision_count(self, collision_type):
        if collision_type == 'pedestrian':
            self.count_collision_pedestrians += 1
        elif collision_type == 'vehicle':
            self.count_collision_vehicles += 1
        else:
            self.count_collision_others += 1

    @staticmethod
    def _on_collision(weak_self, event):
        self = weak_self()
        if not self:
            return
        actor_category = get_actor_category(event.other_actor)
        actor_type = get_actor_display_name(event.other_actor)
        self.hud.notification('Collision with %r' % actor_type)
        #Test the old counting way
        if actor_category == 'walker':
            self.count_collision_pedestrians_tickbased += 1
        elif actor_category == 'vehicle':
            self.count_collision_vehicles_tickbased += 1
        else:
            self.count_collision_others_tickbased += 1

        self._store_collision_details(event)

    def _store_collision_details(self, event):
        # Append collision details to the history
        impulse = event.normal_impulse
        intensity = math.sqrt(impulse.x**2 + impulse.y**2 + impulse.z**2)
        self.history.append((event.frame, intensity))

        collision_details = {
            "frame": event.frame,
            "impulse": {"x": impulse.x, "y": impulse.y, "z": impulse.z},
            "intensity" : intensity,
            "actor1_id": self._parent.id,
            "actor1_type": self._parent.type_id,
            "actor2_id": event.other_actor.id,
            "actor2_type": event.other_actor.type_id
        }
        self.full_history.append(collision_details)
        self._manage_history_size()
        print(f"Actor 2: {event.other_actor.type_id}")
        print(f"Save to full_history")

    def _manage_history_size(self):
        # Manage the size of the history buffers
        if len(self.history) > 4000:
            self.history.pop(0)
        if len(self.full_history) > 4000:
            self.full_history.pop(0)

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
