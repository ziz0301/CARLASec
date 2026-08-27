import sys, os, carla, pygame, math, random, numpy as np, time
try: sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/carla')
except: pass
from agents.navigation.basic_agent import BasicAgent

# ==============================
# RSS PARAMETERS
# ==============================
RHO=1.0
A_MAX_ACCEL=2.5
A_MIN_BRAKE=4.0
A_MAX_BRAKE=8.0
A_MIN_BRAKE_CORRECT=4.0

A_LAT_MAX_ACCEL = 1.5
A_LAT_MIN_BRAKE = 2.0
MU = 0.5

# ==============================
# SAFE DISTANCES
# ==============================
def safe_distance_same(vr,vf):
    v_rho=vr+RHO*A_MAX_ACCEL
    return max(vr*RHO+0.5*A_MAX_ACCEL*RHO**2+(v_rho**2)/(2*A_MIN_BRAKE)-(vf**2)/(2*A_MAX_BRAKE),0)

def safe_distance_opposite(v1,v2):
    v1_rho=v1+RHO*A_MAX_ACCEL
    v2_rho=abs(v2)+RHO*A_MAX_ACCEL
    return (v1+v1_rho)/2*RHO + (v1_rho**2)/(2*A_MIN_BRAKE_CORRECT) + \
           (abs(v2)+v2_rho)/2*RHO + (v2_rho**2)/(2*A_MIN_BRAKE)

def safe_lateral_distance(v1, v2):
    v1_rho = v1 + RHO * A_LAT_MAX_ACCEL
    v2_rho = v2 - RHO * A_LAT_MAX_ACCEL
    term = ( (v1 + v1_rho)/2 * RHO + (v1_rho**2)/(2*A_LAT_MIN_BRAKE)
           - ( (v2 + v2_rho)/2 * RHO - (v2_rho**2)/(2*A_LAT_MIN_BRAKE) ) )
    return MU + max(term, 0)

# ==============================
# LANE COORDS
# ==============================
def get_lane_coords(world, vehicle):
    wp=world.get_map().get_waypoint(vehicle.get_location(), project_to_road=True)

    loc=vehicle.get_location()
    center=wp.transform.location

    Y=wp.s
    right=wp.transform.get_right_vector()
    forward=wp.transform.get_forward_vector()

    rel=loc-center
    alpha=(rel.x*right.x+rel.y*right.y+rel.z*right.z)/wp.lane_width

    vel=vehicle.get_velocity()
    v_long=vel.x*forward.x+vel.y*forward.y+vel.z*forward.z
    v_lat = vel.x*right.x+vel.y*right.y+vel.z*right.z

    return wp, Y, alpha, v_long, v_lat

# ==============================
# FIND TARGET VEHICLE
# ==============================
def find_relevant_vehicle(world, ego, vehicles):
    wp_e,Y_e,alpha_e,v_e_long,v_e_lat=get_lane_coords(world,ego)

    min_dist=float('inf')
    target=None

    for v in vehicles:
        if v.id==ego.id: continue
        wp_v,Y_v,alpha_v,v_v_long,v_v_lat=get_lane_coords(world,v)

        if wp_v.road_id!=wp_e.road_id: continue

        dist=Y_v-Y_e

        if v_e_long*v_v_long>=0:
            if dist<=0: continue
        else:
            dist=abs(dist)

        if dist<min_dist:
            min_dist=dist
            target=(v,dist,v_v_long,v_v_lat,alpha_v)

    return target, v_e_long, v_e_lat, alpha_e

# ==============================
# MAIN
# ==============================
def main():
    pygame.init()
    display=pygame.display.set_mode((1280,720))
    font=pygame.font.SysFont("Arial",18)

    client=carla.Client("localhost",2000)
    client.set_timeout(10.0)
    world=client.get_world()
    bp_lib=world.get_blueprint_library()

    spawn_points=world.get_map().get_spawn_points()
    ego=world.spawn_actor(bp_lib.filter("vehicle.tesla.model3")[0],random.choice(spawn_points))

    agent=BasicAgent(ego,target_speed=30)
    agent.set_destination(random.choice(spawn_points).location)

    clock=pygame.time.Clock()

    # ===== RSS STATE =====
    t_long_b = None
    t_lat_b = None

    try:
        while True:
            world.tick()
            clock.tick(30)

            now = time.time()

            control = agent.run_step()

            vehicles=world.get_actors().filter("vehicle.*")

            target_data, v_e_long, v_e_lat, alpha_e = find_relevant_vehicle(world,ego,vehicles)

            if target_data:
                target,dist,v_t_long,v_t_lat,alpha_t = target_data

                # ===== SAFE DISTANCE =====
                same_direction=(v_e_long*v_t_long>=0)

                if same_direction:
                    d_safe_long=safe_distance_same(v_e_long,v_t_long)
                else:
                    d_safe_long=safe_distance_opposite(v_e_long,v_t_long)

                long_danger = dist < d_safe_long

                lateral_dist = abs(alpha_e - alpha_t)
                d_safe_lat = safe_lateral_distance(v_e_lat, v_t_lat)
                lat_danger = lateral_dist < d_safe_lat

                # ===== TRACK t_b =====
                if long_danger:
                    if t_long_b is None:
                        t_long_b = now
                else:
                    t_long_b = None

                if lat_danger:
                    if t_lat_b is None:
                        t_lat_b = now
                else:
                    t_lat_b = None

                # ===== RESPONSE =====
                # Decide dominant danger (Section 3.5 simplified)
                if long_danger and lat_danger:
                    use_long = True   # prioritize braking
                elif long_danger:
                    use_long = True
                elif lat_danger:
                    use_long = False
                else:
                    use_long = None

                # ===== APPLY RESPONSE =====
                if use_long is True:
                    if t_long_b is not None:
                        dt = now - t_long_b

                        if dt < RHO:
                            # reaction phase
                            control.throttle = min(control.throttle, 0.2)
                        else:
                            # braking phase
                            control.throttle = 0.0
                            control.brake = max(control.brake, 0.6)

                elif use_long is False:
                    if t_lat_b is not None:
                        dt = now - t_lat_b

                        if dt < RHO:
                            # allow limited steering
                            control.steer *= 0.5
                        else:
                            # cancel lateral movement
                            control.steer = 0.0

                ego.apply_control(control)

            else:
                ego.apply_control(control)

    finally:
        ego.destroy()
        pygame.quit()

if __name__=="__main__":
    main()