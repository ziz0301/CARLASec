import carla

def get_vehicle_locations(world):
    vehicles = world.get_actors().filter('vehicle.*')
    print(f"Number of vehicles in the simulation: {len(vehicles)}")
    for vehicle in vehicles:
        location = vehicle.get_transform().location
        print(f"Vehicle ID {vehicle.id} is at location: x={location.x}, y={location.y}, z={location.z}")

def get_walker_locations(world):
    walkers = world.get_actors().filter('walker.pedestrian.*')
    print(f"Number of walkers in the simulation: {len(walkers)}")
    for walker in walkers:
        location = walker.get_transform().location
        print(f"Walker ID {walker.id} is at location: x={location.x}, y={location.y}, z={location.z}")

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


# Connect to the CARLA simulator (running on localhost and the default port 2000)
client = carla.Client('192.168.160.1', 2000)
client.set_timeout(10.0)

# Get the world currently running in the simulation
world = client.get_world()



get_walker_locations(world)
destroy_all_walkers(world)
get_vehicle_locations(world)
destroy_all_vehicles(world)

#get_vehicle_locations(world)
#confirm_and_destroy_vehicles(world)
#get_walker_locations(world)
#confirm_and_destroy_walkers(world)
