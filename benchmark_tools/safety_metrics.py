#!/usr/bin/env python

# This code is made to calculate the safety metrics of the carla vehicle on baseline scenario and under attack
# - Counting instances when the vehicle violates stop signs.
# - Counting instances when the vehicle violates red light traffic signals.
# - Counting instances when the vehicle goes off the road.
# These counts are used to formulate safety metrics for the vehicles.
# Author: ziz0301 - Mail: ziz0301@gmail.com
# This code is part of CARLASec, a PhD research project on cybersecurity and safety evaluation for autonomous vehicles.

import carla
import math

class SafetyMetrics:
    #Define the infraction penalty
    PENALTY_COLLISION_PEDESTRIAN = 0.50
    PENALTY_COLLISION_VEHICLE = 0.60
    PENALTY_COLLISION_STATIC = 0.65
    PENALTY_TRAFFIC_LIGHT = 0.70
    PENALTY_OFFROAD = 0.75
    PENALTY_STOP = 0.80
    PENALTY_DOOROPEN = 0.90



    def __init__(self):
        # Distance tracking
        self.total_distance_meters = 0
        self.previous_location = None
        # Event tracking
        self.traffic_light_violations = 0
        self.percentage_collision = 0.0
        self.percentage_lane_invasions = 0.0
        self.percentage_light_violation = 0.0
        # Distance tracker
        self.total_distance_meters = 0
        self.previous_location = None

        self.door_total_distance = 0
        self.door_previous_location = 0


    def get_data_location(self, filename, vehicle_locationx, vehicle_locationy):
        filenamet = f"{filename}_location.txt"       
        with open(filenamet, 'a') as file:
            file.write(f"{filename},{vehicle_locationx},{vehicle_locationy} \n")

    def get_data_rotation(self, filename, vehicle_rotation):
        filenamet = f"{filename}_rotation.txt"       
        with open(filenamet, 'a') as file:
            file.write(f"{filename},{vehicle_rotation} \n")

    def get_data_velocity(self, filename, vehicle_velocity):
        filenamet = f"{filename}_velocity.txt" 
        with open(filenamet, 'a') as file:
            file.write(f"{filename},{vehicle_velocity} \n")
            
    def log_door_status(self, filename, status):
        filenamet = f"{filename}_door.txt"
        with open(filenamet, 'a') as file:
            file.write(f"{filename},{status}\n")
            
            
    def get_data_light(self, filename, light_status):
        filenamet = f"{filename}_light.txt" 
        with open(filenamet, 'a') as file:
            file.write(f"{filename},{light_status} \n")


    def door_update_distance(self, current_location):
        """Update the total distance based on the current location of the vehicle."""
        if self.door_previous_location is not None:
            distance = self._calculate_distance(self.door_previous_location, current_location)
            self.door_total_distance += distance
            # print(f"Total Distance Meters: {self.total_distance_meters}")
        self.door_previous_location = current_location


    def update_distance(self, current_location):
        """Update the total distance based on the current location of the vehicle."""
        if self.previous_location is not None:
            distance = self._calculate_distance(self.previous_location, current_location)
            self.total_distance_meters += distance
            # print(f"Total Distance Meters: {self.total_distance_meters}")
        self.previous_location = current_location

    @staticmethod
    def _calculate_distance(loc1, loc2):
        """Calculate the Euclidean distance between two CARLA locations."""
        return math.sqrt((loc2.x - loc1.x)**2 + (loc2.y - loc1.y)**2 + (loc2.z - loc1.z)**2)


    def get_total_distance_km(self):
        """Get the total distance traveled in kilometers."""
        return self.total_distance_meters / 1000



    def is_car_blocked(self, distances, threshold):
        same_distance_count = 0
        for i in range(1, len(distances)):
            if distances[i] - distances[i - 1] < 5:
                same_distance_count += 1
                #print(f"distance[i]: {distances[i]}")
                #print(f"distance[i-1]: {distances[i-1]}")
                #print(f"same_distance_count: {same_distance_count}")
                if same_distance_count >= threshold:
                    return True  # Car is considered blocked
            else:
                same_distance_count = 0  # Reset count if the distance changes
        return False

    def calculate_percentage_traffic_light_violations(self, count):
        if self.total_distance_meters > 0:
            self.percentage_light_violation = (count / (self.total_distance_meters / 1000)) * 100
        else:
            self.percentage_light_violation = 0.0
        return self.percentage_light_violation

    def calculate_percentage_lane_invasion(self, count):
        if self.total_distance_meters > 0:
            self.percentage_lane_invasions = (count / (self.total_distance_meters / 1000)) * 100
        else:
            self.percentage_lane_invasions = 0.0
        return self.percentage_lane_invasions

    def calculate_percentage_collision(self, count):
        if self.total_distance_meters > 0:
            self.percentage_collision = (count / (self.total_distance_meters / 1000)) * 100
        else:
            self.percentage_collision = 0.0
        return self.percentage_collision

    def calculate_average_speed(self, distance, time):
        average_speed_kmh = 0
        if time == 0:
            average_speed_kmh = 0
        else:
            average_speed_ms = distance / time
            average_speed_kmh = average_speed_ms * 3.6
        return average_speed_kmh


    def log_safety_per_tick(
        self,
        filename,
        route_completion,
        count_collision_pedestrians,
        count_collision_vehicles,
        count_collision_others,
        score_collision_pedestrians,
        score_collision_vehicles,
        score_collision_others,
        count_red_light_violation,
        count_stop_sign_violation,
        count_off_road,
        door_open
    ):
        """
        Log safety metrics and penalties for each simulation tick into a file.
        Includes collision types, penalty scores, and infractions.
        """
        filepath = f"{filename}_safety_metric_tick.txt"
        line = f"{route_completion:.2f}," \
               f"{count_collision_pedestrians},{score_collision_pedestrians:.2f}," \
               f"{count_collision_vehicles},{score_collision_vehicles:.2f}," \
               f"{count_collision_others},{score_collision_others:.2f}," \
               f"{count_red_light_violation}," \
               f"{count_stop_sign_violation}," \
               f"{count_off_road}," \
               f"{door_open}\n"

        with open(filepath, 'a') as file:
            file.write(line)



    def safety_analysis(self, result):
        # Initialize safety_analyse dictionary
        self.safety_analyse = {
            'Filename': result['filename'],
            'Driving_score': None,
            'Route_completion': None,
            'Infraction_penalty': None,
            'Collisions_pedestrians': None,
            'Collisions_vehicles': None,
            'Collisions_layout': None,
            'Score_collisions_pedestrians': None,
            'Score_collisions_vehicles': None,
            'Score_collisions_layout': None,
            'Red_light_infractions': None,
            'Stop_sign_infractions': None,
            'Offroad_infractions': None,
            'Door_open': None,
            'Duration': result['total_time_run'],
            'Fully_complete': result['fully_completed']

        }

        # Normalizing infractions per meter
        if result['total_metre_run'] == 0:
            return
        else:
            self.safety_analyse['Route_completion'] = result['total_metre_run']/229.25
            self.safety_analyse['Collisions_pedestrians'] = result['count_collision_pedestrians']
            self.safety_analyse['Collisions_vehicles'] = result['count_collision_vehicles']
            self.safety_analyse['Collisions_layout'] = result['count_collision_others']
            self.safety_analyse['Red_light_infractions'] = result['count_red_light_violation']
            self.safety_analyse['Stop_sign_infractions'] = result['count_stop_sign_violation']
            self.safety_analyse['Offroad_infractions'] = result['count_off_road']
            self.safety_analyse['Collisions_layout'] = result['count_collision_others']
            self.safety_analyse['Score_collisions_pedestrians'] = result['score_collision_pedestrians']
            self.safety_analyse['Score_collisions_vehicles'] = result['score_collision_vehicles']
            self.safety_analyse['Score_collisions_layout'] = result['score_collision_others']
            self.safety_analyse['Door_open'] = result['door_open']

            #self.safety_analyse['Collisions_pedestrians'] = result['count_collision_pedestrians'] / result['total_metre_run']
            #self.safety_analyse['Collisions_vehicles'] = result['count_collision_vehicles'] / result['total_metre_run']
            #self.safety_analyse['Collisions_layout'] = result['count_collision_others'] / result['total_metre_run']
            #self.safety_analyse['Red_light_infractions'] = result['count_red_light_violation'] / result['total_metre_run']
            #self.safety_analyse['Stop_sign_infractions'] = result['count_stop_sign_violation'] / result['total_metre_run']
            #self.safety_analyse['Offroad_infractions'] = result['count_off_road'] / result['total_metre_run']

            # Calculate infraction penalty
            score_penalty = 1.0
            score_penalty *= result['score_collision_others']
            score_penalty *= result['score_collision_pedestrians']
            score_penalty *= result['score_collision_vehicles']
            for _ in range(result['count_red_light_violation']):
                score_penalty *= self.PENALTY_TRAFFIC_LIGHT
            for _ in range(result['count_stop_sign_violation']):
                score_penalty *= self.PENALTY_STOP
            for _ in range(result['door_open']):
                score_penalty *= self.PENALTY_DOOROPEN
            for _ in range(result['count_off_road']):
                score_penalty *= self.PENALTY_OFFROAD
            '''
            for _ in range(result['count_collision_pedestrians']):
                score_penalty *= self.PENALTY_COLLISION_PEDESTRIAN
            for _ in range(result['count_collision_vehicles']):
                score_penalty *= self.PENALTY_COLLISION_VEHICLE
            for _ in range(result['count_collision_others']):
                score_penalty *= self.PENALTY_COLLISION_STATIC
            for _ in range(result['count_red_light_violation']):
                score_penalty *= self.PENALTY_TRAFFIC_LIGHT
            for _ in range(result['count_stop_sign_violation']):
                score_penalty *= self.PENALTY_STOP
            '''
            self.safety_analyse['Infraction_penalty'] = score_penalty

            # Calculate driving score
            self.safety_analyse['Route_completion'] = 1.0 if result['fully_completed'] else self.safety_analyse['Route_completion']
            self.safety_analyse['Driving_score'] = score_penalty * self.safety_analyse['Route_completion'] * 100

            # Return the filled safety_analyse dictionary
            return self.safety_analyse
