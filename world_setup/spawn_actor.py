import random
import carla

def spawn_random_vehicles(world, traffic_manager, number_of_vehicles, blueprints, spawn_points):
    vehicles_list = []

    if number_of_vehicles < len(spawn_points):
        random.shuffle(spawn_points)
    else:
        number_of_vehicles = len(spawn_points)

    batch = []
    for n, transform in enumerate(spawn_points):
        if n >= number_of_vehicles:
            break
        blueprint = random.choice(blueprints)
        if blueprint.has_attribute('color'):
            color = random.choice(blueprint.get_attribute('color').recommended_values)
            blueprint.set_attribute('color', color)
        blueprint.set_attribute('role_name', 'autopilot')

        batch.append(carla.command.SpawnActor(blueprint, transform)
                     .then(carla.command.SetAutopilot(carla.command.FutureActor, True, traffic_manager.get_port())))

    for response in client.apply_batch_sync(batch, True):
        if response.error:
            logging.error(response.error)
        else:
            vehicles_list.append(response.actor_id)

    return vehicles_list

def spawn_random_walkers(world, number_of_walkers, blueprintsWalkers):
    walkers_list = []
    all_id = []

    spawn_points = []
    for _ in range(number_of_walkers):
        spawn_point = carla.Transform()
        loc = world.get_random_location_from_navigation()
        if loc is not None:
            spawn_point.location = loc
            spawn_points.append(spawn_point)

    batch = []
    for spawn_point in spawn_points:
        walker_bp = random.choice(blueprintsWalkers)
        if walker_bp.has_attribute('is_invincible'):
            walker_bp.set_attribute('is_invincible', 'false')
        batch.append(carla.command.SpawnActor(walker_bp, spawn_point))

    results = client.apply_batch_sync(batch, True)
    for result in results:
        if result.error:
            logging.error(result.error)
        else:
            walkers_list.append({"id": result.actor_id})
            all_id.append(result.actor_id)

    # Spawn walker controllers
    batch = []
    walker_controller_bp = world.get_blueprint_library().find('controller.ai.walker')
    for walker_id in all_id:
        batch.append(carla.command.SpawnActor(walker_controller_bp, carla.Transform(), walker_id))

    results = client.apply_batch_sync(batch, True)
    for i, result in enumerate(results):
        if result.error:
            logging.error(result.error)
        else:
            walkers_list[i]["con"] = result.actor_id
            all_id.append(result.actor_id)

    return walkers_list, all_id

# Usage example
# Assuming you have a CARLA world and traffic_manager already set up and your args populated
vehicles_list = spawn_random_vehicles(world, traffic_manager, args.number_of_vehicles, blueprints, spawn_points)
walkers_list, all_id = spawn_random_walkers(world, args.number_of_walkers, blueprintsWalkers)
