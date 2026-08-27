import re
import carla

#def set_weather(world, weather_type):
 #   available_weather = [x for x in dir(carla.WeatherParameters) if re.match('[A-Z].+', x)]
#    presets = {x: getattr(carla.WeatherParameters, x) for x in available_weather}
#    weather_parameters = presets.get(weather_type, carla.WeatherParameters.Default)
#    world.set_weather(weather_parameters)
 #   if weather_type not in presets or weather_type == 'Default':
 #       print(f"Invalid or default weather type '{weather_type}' provided. Setting to default weather.")
 #   else:
 #       print(f"Weather set to '{weather_type}'.")
        
        
def set_weather(world, weather_name):
    weather_name = weather_name.lower()
    if weather_name == "default":
        weather = carla.WeatherParameters.ClearNoon
    elif weather_name == "night":
        weather = carla.WeatherParameters(
            cloudiness=10.0,
            precipitation=0.0,
            sun_altitude_angle=-10.0,
            fog_density=0.0
        )
    elif weather_name == "rainynight":
        weather = carla.WeatherParameters(
            cloudiness=90.0,
            precipitation=80.0,
            sun_altitude_angle=-15.0,
            fog_density=10.0,
            wetness=80.0
        )
    else:
        print(f"[WARNING] Unknown weather '{weather_name}', using default.")
        weather = carla.WeatherParameters.ClearNoon

    world.set_weather(weather)


def get_actor_display_name(actor, truncate=250):
    """Method to get actor display name"""
    name = ' '.join(actor.type_id.replace('_', '.').title().split('.')[1:])
    return (name[:truncate - 1] + u'\u2026') if len(name) > truncate else name

def get_actor_category(type_id):
    parts = type_id.split('.')
    return parts[0] if parts else None


def get_actor_blueprints(world, filter, generation):
    bps = world.get_blueprint_library().filter(filter)
    #[print(x.get_attribute('generation')) for x in bps]
    if generation.lower() == "all":
        return bps
    if len(bps) == 1:
        return bps
    try:
        int_generation = int(generation)
        # Check if generation is in available generations
        if int_generation in [1, 2, 3]:
            bps = [x for x in bps if int(x.get_attribute('generation')) == int_generation]
            return bps
        else:
            print("Warning! Actor Generation is not valid. No actor will be spawned.")
            return []
    except:
        print("Warning! Actor Generation is not valid. No actor will be spawned.")
        return []

def get_vehicle_and_walker_count(world):
    vehicles = world.get_actors().filter('vehicle.*')
    walkers = world.get_actors().filter('walker.pedestrian.*')
    vehicle_count = len(vehicles)
    walkers_count = len(walkers)
    return {'number_of_vehicles': vehicle_count, 'number_of_walkers': walker_count}

def get_vehicle_locations(world):
    vehicles = world.get_actors().filter('vehicle.*')
    vehicle_info = [f"There are {len(vehicles)} vehicles in the world"]
    for vehicle in vehicles:
        location = vehicle.get_transform().location
        vehicle_info.append(f"Vehicle ID {vehicle.id} is at location: x={location.x}, y={location.y}, z={location.z}")
    return vehicle_info

def get_walker_locations(world):
    walkers = world.get_actors().filter('walker.pedestrian.*')
    walker_info = [f"There are {len(walkers)} walkers in the world"]
    for walker in walkers:
        location = walker.get_transform().location
        walker_info.append(f"Walker ID {walker.id} is at location: x={location.x}, y={location.y}, z={location.z}")
    return walker_info

def get_vehicle_and_walker_info(world):
    vehicle_info = get_vehicle_locations(world)
    walker_info = get_walker_locations(world)
    location_info = {
        "Vehicle_info": vehicle_info,
        "Walker_info": walker_info
    }
    return location_info



def find_spawn_point(world, spawn_point):
    spawn_points = world.get_map().get_spawn_points()
    spawn_point_dict = {i + 1: sp for i, sp in enumerate(spawn_points)}
    return spawn_point_dict.get(spawn_point)


def destroy_all_vehicles(world):
    vehicles = world.get_actors().filter('vehicle.*')
    for vehicle in vehicles:
        print(f"Destroying vehicle ID {vehicle.id}")
        vehicle.destroy()

def destroy_all_walkers(world):
    walkers = world.get_actors().filter('walker.pedestrian.*')
    for walker in walkers:
        print(f"Destroying walker ID {walker.id}")
        walker.destroy()

def confirm_and_destroy_vehicles(world):
    user_input = input("Do you want to destroy all vehicles? [Y/n]: ").lower()
    if user_input in ['y', 'yes', '']:
        destroy_all_vehicles(world)
    else:
        print("Operation cancelled.")

def confirm_and_destroy_walkers(world):
    user_input = input("Do you want to destroy all walkers? [Y/n]: ").lower()
    if user_input in ['y', 'yes', '']:
        destroy_all_walkers(world)
    else:
        print("Operation cancelled.")
