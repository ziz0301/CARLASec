# world.py
import carla
import random
import sys

from world_setup.sensors import CollisionSensor, LaneInvasionSensor, GnssSensor
from world_setup.camera_manager import CameraManager
from world_setup.utils import set_weather, get_actor_display_name, get_actor_blueprints, find_spawn_point


# ==============================================================================
# -- World ---------------------------------------------------------------
# ==============================================================================

class World(object):
    """ Class representing the surrounding environment """

    def __init__(self, carla_world, hud, args):
        """Constructor method"""
        self._args = args
        self.world = carla_world
        try:
            self.map = self.world.get_map()
        except RuntimeError as error:
            print('RuntimeError: {}'.format(error))
            print('  The server could not send the OpenDRIVE (.xodr) file:')
            print('  Make sure it exists, has the same name of your town, and is correct.')
            sys.exit(1)
        self.hud = hud
        self.player = None
        self.collision_sensor = None
        self.lane_invasion_sensor = None
        self.gnss_sensor = None
        self.camera_manager = None
        self._weather = args.weather
        self._actor_filter = args.filter
        self._actor_generation = args.generation
        self.start_pos = None
        self.end_pos = None
        self.restart(args)
        self.world.on_tick(hud.on_world_tick)
        self.doors_are_open = False
        self.recording_enabled = False
        self.recording_start = 0
        self.number_of_vehicles = None
        self.number_of_walkers = None


    def restart(self, args):
        """Restart the world"""
        # Keep same camera config if the camera manager exists.
        cam_index = self.camera_manager.index if self.camera_manager is not None else 0
        cam_pos_id = self.camera_manager.transform_index if self.camera_manager is not None else 0

        # Set the weather based on user-defined preferences.
        set_weather(self.world,self._weather)

        # Get a random blueprint.
        blueprint_list = get_actor_blueprints(self.world, self._actor_filter, self._actor_generation)
        if not blueprint_list:
            raise ValueError("Couldn't find any blueprints with the specified filters")
        blueprint = random.choice(blueprint_list)
        blueprint.set_attribute('role_name', 'hero')
        if blueprint.has_attribute('color'):
            color = random.choice(blueprint.get_attribute('color').recommended_values)
            blueprint.set_attribute('color', color)

        # Spawn the player.
        if self.player is not None:
            spawn_point = self.player.get_transform()
            spawn_point.location.z += 2.0
            spawn_point.rotation.roll = 0.0
            spawn_point.rotation.pitch = 0.0
            self.destroy()
            self.player = self.world.try_spawn_actor(blueprint, spawn_point)
            self.modify_vehicle_physics(self.player)
        while self.player is None:
            if not self.map.get_spawn_points():
                print('There are no spawn points available in your map/town.')
                print('Please add some Vehicle Spawn Point to your UE4 scene.')
                sys.exit(1)
            '''
            spawn_points = self.map.get_spawn_points()
            spawn_point = random.choice(spawn_points) if spawn_points else carla.Transform()
            self.player = self.world.try_spawn_actor(blueprint, spawn_point)
            self.modify_vehicle_physics(self.player)
            '''
            if args.spawnpos:
                self_pos = args.spawnpos
                start_pos, end_pos = [int(index) for index in args.spawnpos.split(',')]
                #print(f"Start_pos: {start_pos} and end_pos: {end_pos}")
                start_location = find_spawn_point(self.world, start_pos)
                #print(f"Location of start_pos {start_pos}: {start_location}")
                end_location = find_spawn_point(self.world, end_pos)

                self.start_pos = start_location
                self.end_pos = end_location

                if start_location is None:
                    print("Start point not found.")
                    sys.exit(1)
                if end_location is None:
                    print("End point not found.")
                    sys.exit(1)

                self.player = self.world.try_spawn_actor(blueprint, start_location)
                self.modify_vehicle_physics(self.player)
            else:
                spawn_points = self.map.get_spawn_points()
                #spawn_point =find_spawn_point(self.world, 146)
                spawn_point = random.choice(spawn_points) if spawn_points else carla.Transform()
                self.start_pos = spawn_point
                self.player = self.world.try_spawn_actor(blueprint, spawn_point)
                self.modify_vehicle_physics(self.player)


        if self._args.sync:
            self.world.tick()
        else:
            self.world.wait_for_tick()

        # Set up the sensors.
        self.collision_sensor = CollisionSensor(self.player, self.hud)
        self.lane_invasion_sensor = LaneInvasionSensor(self.player, self.hud)
        self.gnss_sensor = GnssSensor(self.player)
        self.camera_manager = CameraManager(self.player, self.hud)
        self.camera_manager.transform_index = cam_pos_id
        self.camera_manager.set_sensor(cam_index, notify=False)
        actor_type = get_actor_display_name(self.player)
        self.hud.notification(actor_type)
        world = self.player.get_world()



    def modify_vehicle_physics(self, actor):
        #If actor is not a vehicle, we cannot use the physics control
        try:
            physics_control = actor.get_physics_control()
            physics_control.use_sweep_wheel_collision = True
            actor.apply_physics_control(physics_control)
        except Exception:
            pass

    def tick(self, clock):
        """Method for every tick"""
        self.hud.tick(self, clock)

    def render(self, display):
        """Render world"""
        self.camera_manager.render(display)
        self.hud.render(display)

    def destroy_sensors(self):
        """Destroy sensors"""
        self.camera_manager.sensor.destroy()
        self.camera_manager.sensor = None
        self.camera_manager.index = None

    def destroy(self):
        """Destroys all actors"""
        actors = [
            self.camera_manager.sensor,
            self.collision_sensor.sensor,
            self.lane_invasion_sensor.sensor,
            self.gnss_sensor.sensor,
            self.player]
        for actor in actors:
            if actor is not None:
                actor.destroy()
