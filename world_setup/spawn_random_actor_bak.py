import random
import carla

def spawn_random_vehicles(world, traffic_manager, number_of_vehicles, vehicle_filter, safe=False):
    SpawnActor = carla.command.SpawnActor
    SetAutopilot = carla.command.SetAutopilot
    FutureActor = carla.command.FutureActor

    blueprints = world.get_blueprint_library().filter(vehicle_filter)
    if safe:
        blueprints = [x for x in blueprints if x.get_attribute('base_type') == 'car']
    blueprints = sorted(blueprints, key=lambda bp: bp.id)

    spawn_points = world.get_map().get_spawn_points()
    number_of_spawn_points = len(spawn_points)

    if number_of_vehicles < number_of_spawn_points:
        random.shuffle(spawn_points)
    elif number_of_vehicles > number_of_spawn_points:
        logging.warning(
            'Requested %d vehicles, but could only find %d spawn points',
            number_of_vehicles, number_of_spawn_points)
        number_of_vehicles = number_of_spawn_points

    batch = []
    for transform in spawn_points[:number_of_vehicles]:
        blueprint = random.choice(blueprints)
        if blueprint.has_attribute('color'):
            color = random.choice(blueprint.get_attribute('color').recommended_values)
            blueprint.set_attribute('color', color)
        batch.append(SpawnActor(blueprint, transform)
                     .then(SetAutopilot(FutureActor, True, traffic_manager.get_port())))

    responses = world.apply_batch_sync(batch, True)
    vehicle_ids = [response.actor_id for response in responses if not response.error]
    return vehicle_ids


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
