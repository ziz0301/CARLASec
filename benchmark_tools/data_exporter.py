import csv
import os
import subprocess


class DataExporter:
    def __init__(self, base_name='benign', file_directory='./'):
        self.base_name = base_name
        self.file_directory = file_directory

        self.results = {
            'filename': None,
            'weather': None,
            'number_of_vehicles': None,
            'number_of_walker': None,
            'ego_vehicle': None,
            'start_positon': None,
            'destination_position': None,
            'fully_completed': None,
            'total_time_run': None,
            'total_metre_run': None,
            'average_speed': None,
            'count_collision_others': None,
            'count_collision_pedestrians': None,
            'count_collision_vehicles': None,
            'count_off_road': None,
            'count_red_light_violation': None,
            'count_stop_sign_violation':None,
        }
        self.infractions = {
            "Collisions with layout": [],
            "Collisions with pedestrians": [],
            "Collisions with vehicles": [],
            "Red lights infractions": [],
            "Stop sign infractions": [],
            "Off-road infractions": []
        }


    def write_results_data(self, data, loop_number):
        file_name = f"{self.base_name}_{loop_number:02d}_result_data.csv"
        self._write_csv(data, file_name, self.results_headers)

    def write_explanation_data(self, explanation, loop_number):
        file_name = f"{self.base_name}_{loop_number:02d}_result_explain.txt"
        file_path = os.path.join(self.file_directory, file_name)

        with open(file_path, 'w') as file:
            file.write(explanation)

        print(f"Explanation data exported to {file_path}")

    def run_candump(self, filename):
        command = f"candump -t a kcan,ptcan | awk '{{ print strftime(\"%Y-%m-%d %H:%M:%S\"), $3, $6, $7, $8, $9, $10, $11, \"Normal\", \"N/A\" }}' > {file_name}"
        subprocess.run(command, shell=True, check=True)



    def track_infraction(infraction_type, details):
        if infraction_type in infractions:
            infractions[infraction_type].append(details)
        else:
            print(f"Unknown infraction type: {infraction_type}")

    def export_simplistic_result(self, filename, analyse, result, infractions):
        filename = f"{filename}_simplistic_result.txt"
        filepath = os.path.join(self.file_directory, filename)
        print(f"Running Information is export to {filename}")
        with open(filepath, 'w') as file:
            file.write(f"ALL INFORMATION ON THE RUN {filename}\n")
            file.write("------------------- ANALYSE ------------------\n")
            for key, value in analyse.items():
                file.write(f'{key}: {value}\n')

            file.write("--------------- FULL INFORMATION -------------\n")
            for key, value in result.items():
                file.write(f'{key}: {value}\n')

            file.write("\n--------- INFRACTION INFORMATION -----------\n")
            for infraction_type, instances in infractions.items():
                file.write(f"{infraction_type}:\n")
                if instances:
                    for instance in instances:
                        file.write(f" - {instance}\n")


    def export_detailed_result(self, filename, analyse, result, infractions, record_collision, all_locations, record_info, collision_history):
        filename = f"{filename}_detailed_result.txt"
        filepath = os.path.join(self.file_directory, filename)
        print(f"Running Information is export to {filename}")
        with open(filepath, 'w') as file:
            file.write(f"ALL INFORMATION ON THE RUN {filename}\n")
            file.write("------------------- ANALYSE ------------------\n")
            for key, value in analyse.items():
                file.write(f'{key}: {value}\n')

            file.write("--------------- FULL INFORMATION -------------\n")
            for key, value in result.items():
                file.write(f'{key}: {value}\n')

            file.write("\n--------- INFRACTION INFORMATION -----------\n")
            for infraction_type, instances in infractions.items():
                file.write(f"{infraction_type}:\n")
                if instances:
                    for instance in instances:
                        file.write(f" - {instance}\n")

            file.write("\n------------ RECORD COLLISION --------------\n")
            file.write(f"{record_collision}")

            file.write("\n------ VEHICLES AND WALKERS LOCATION -------\n")
            file.write(f"{all_locations}")

            file.write("\n----------- RECORD INFOMATION --------------\n")
            file.write(f"{record_info}")

            file.write("\n----------- COLLISION HISTORY --------------\n")
            file.write(f"{collision_history}")


    def _write_csv(self, data, file_name, headers):
        file_path = os.path.join(self.file_directory, file_name)

        with open(file_path, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            writer.writerows(data)

        print(f"CSV data exported to {file_path}")
