# CARLASec

**CARLASec** is an extension of the **CARLA autonomous driving simulator** designed to support cybersecurity research on autonomous and connected vehicles.
The framework enables the simulation of automotive cyberattacks via an emulated in-vehicle network that uses **Controller Area Network (CAN)** and **Unified Diagnostic Services (UDS)** messages.

CARLASec extends the original CARLA simulator by incorporating:

* Emulated CAN bus communication using Linux SocketCAN
* CAN message transmission, sniffing, and manipulation
* Unified Diagnostic Services (UDS) message injection
* Manual and automated automotive cyberattacks
* Intrusion Detection System (IDS) integration
* Safety-oriented vehicle response to detected cyberattacks
* Vehicle safety evaluation under cyberattacks
* Camera/perception degradation and attack experiments

The framework is intended primarily for cybersecurity and safety research involving autonomous vehicles.

---
## Installation

Detailed installation instructions are available in the CARLASec installation guide:
**CARLASec Installation Guide:**
https://nervous-pleasure-bc6.notion.site/CARLASec-Installing-700f139d60f4428a93500b65cbe41fb5?source=copy_link

> **Note:** The installation guide is hosted on Notion. The link is safe to open and contains the detailed environment setup instructions.

Before running the examples below, please make sure that CARLA, CARLASec, the virtual CAN interfaces (`vcan0` and `kcan4`), and all required dependencies are configured according to the installation guide.

---

# Usage
The following examples demonstrate several common ways to run CARLASec.

## 1. Clean the CARLA World
To remove existing vehicles and pedestrians from the CARLA world:

```bash
python test_location.py
```

This can be useful before starting a new experiment to ensure that objects left from a previous simulation do not interfere with the new run.
---

## 2. Display Available Spawn Points
To display all available vehicle spawn points and their corresponding location numbers:

```bash
python no_render1.py --show-spawn-points
```
The spawn-point numbers shown by this command can then be supplied to the `--spawnpos` argument when starting a vehicle.
For example:

```bash
python client_run.py --spawnpos 5,46
```
In this example, `5,46` represents the selected spawn positions used by the simulation.
---

## 3. Run a Vehicle Normally
To run a vehicle without activating attack functionality:
```bash
python client_run.py --spawnpos 5,46
```
You can select different spawn positions based on the output produced by:
```bash
python no_render1.py --show-spawn-points
```
---

## 4. Run a Vehicle and Sniff CAN Traffic
Start the vehicle with CAN sniffing enabled:

```bash
python client_run.py --spawnpos 5,46 --sniff
```
Then, in another terminal, monitor CAN traffic using:

```bash
candump vcan0
```
This allows you to observe the CAN messages generated during vehicle operation.
---

## 5. Run a Vehicle with Automated Attacks
To start the vehicle with automated cyberattacks:

```bash
python client_run.py --spawnpos 5,46 --attacker
```
The attack payloads and attack configuration used by the automated attacker are defined in:

```text
ids_attacker2.sh
```
You can also modify the individual CAN/UDS attack payloads directly in `ids_attacker2.sh` to create or evaluate different attack scenarios.
The attack type can be selected by modifying the `ATTACK_TYPE` variable.
For example:
```bash
ATTACK_TYPE=1
```
Select an attack type from the available attack definitions (currently numbered **1–8**).
To randomly select an attack type, use:

```bash
ATTACK_TYPE=$(rand_between 1 8)
```

---

## 6. Run a Vehicle with Manual Attacks
First, start the vehicle normally:

```bash
python client_run.py --spawnpos 5,46
```
Then open another terminal and inject CAN or UDS attack messages manually.
Additional example payloads are provided in:

```text
Attack payload.txt
```
### Example: Throttle Manipulation
A CAN message can be repeatedly injected to manipulate the vehicle's throttle:
```bash
while true; do
    cansend vcan0 000001A0#5508010100000012
done
```
The relevant payload bytes can be modified to change the injected throttle value and therefore influence the vehicle's acceleration/speed.

### Example: Steering Manipulation
A CAN message can also be injected to manipulate the steering command:
```bash
while true; do
    cansend vcan0 000000C4#5FFFFFFF0000003A
done
```
The relevant payload bytes can be modified to represent different steering-angle commands.

### Example: Door Control via UDS
```bash
while true; do
    cansend vcan0 7E0#053101020364
done
```

### Example: UDS Routine Control — Brake
```bash
cansend vcan0 7E0#053101020550
```

### Example: UDS Routine Control — Throttle
```bash
cansend vcan0 7E0#05310201A964
```
To observe the injected and generated CAN messages, open another terminal and run:
```bash
candump vcan0
```
---

## 7. Run a Vehicle with IDS and Attack Injection
CARLASec can integrate an Intrusion Detection System (IDS) to monitor CAN traffic during vehicle operation and evaluate whether injected attacks are correctly detected.
For this experiment, three components are run together:
* **`client_run.py`** runs the CARLA vehicle and the CARLASec in-vehicle network environment, including normal vehicle operation and attack injection.
* **`ids_server_with_sniffer.py`** forwards CAN messages to the virtual CAN bus (`vcan0`) and simultaneously records the transmitted messages. Importantly, it preserves the ground-truth labels associated with the messages (e.g., benign or attack, attack type, and attack ID) in `ids_can_sniff_log.csv`. These labels can later be compared with the IDS detection results to evaluate detection accuracy.
* **`ids_runtime.py`** independently monitors the CAN traffic on `vcan0` and applies the implemented IDS mechanisms. Detected anomalies are recorded in `ids_alert_log.csv`, and IDS alerts are also sent to the vehicle.
The three components therefore have different roles: **the vehicle generates the experiment traffic, the server/sniffer provides the labelled ground-truth CAN traffic, and the runtime IDS performs the actual detection**. Running them together allows the IDS output to be compared against the known attack labels and supports evaluation of whether attacks were correctly detected.

Use at least **three terminal windows**.
### Terminal 1 — Start the CAN Server and Ground-Truth Sniffer
From the `/response` directory:
```bash
python ids_server_with_sniffer.py
```
This forwards CAN messages to `vcan0` while recording the CAN traffic and its ground-truth labels for later IDS evaluation.

### Terminal 2 — Start the Runtime IDS
From the `/response` directory:
```bash
python ids_runtime.py
```
The runtime IDS independently monitors `vcan0`, detects suspicious CAN behaviour, records generated alerts, and sends IDS alerts to the vehicle.

### Terminal 3 — Start the Vehicle and Attack
For an automated attack:
```bash
python client_run.py --spawnpos 5,46 --attacker
```
Alternatively, start the vehicle normally:
```bash
python client_run.py --spawnpos 5,46
```
and inject attack messages manually as described in **Section 6**.

---

## 8. Run a Vehicle with IDS and Attack Response
CARLASec also supports a state-based safety-response framework in which IDS alerts trigger appropriate vehicle safety actions.
This experiment uses the same three-component setup described in **Section 7**. The CAN server/sniffer continues to provide the labelled ground-truth traffic, while the runtime IDS monitors `vcan0` and generates IDS alerts. The main difference is that `client_run_response.py` replaces `client_run.py`.

Unlike the standard client, **`client_run_response.py` integrates the `RSSStateResponse` mechanism**, which receives IDS alerts and uses the current response state and RSS-based safety information to modify the vehicle control when necessary. It also records response states and related information for later evaluation.

The complete experiment follows:
Vehicle and attack → labelled CAN traffic → IDS detection → vehicle safety response

Again, use at least three terminal windows.
### Terminal 1 — Start the CAN Server and Ground-Truth Sniffer
From the `/response` directory:
```bash
python ids_server_with_sniffer.py
```

### Terminal 2 — Start the Runtime IDS
From the `/response` directory:
```bash
python ids_runtime.py
```

### Terminal 3 — Start the Response-Enabled Vehicle
For an automated attack experiment:
```bash
python client_run_response.py --spawnpos 5,46 --attacker
```
For manual attack injection:
```bash
python client_run_response.py --spawnpos 5,46
```
Then, inject the attack messages from another terminal as described in **Section 6**.

---

## 9. Camera and Perception Attack Experiments
Camera and perception experiments are located under the:
```text
/camera
```
directory.

CARLASec+ includes a perception-based driving agent that combines:
* RGB camera input for lane perception,
* YOLOv8 for vehicle and pedestrian detection,
* CARLA's `BasicAgent` for global route guidance,
* PID-based speed control, and
* camera degradation functions for perception attack experiments.

Two versions of the driving agent are provided. Only one of these scripts needs to be executed for an experiment.

Both scripts also contain configurable camera degradation functions supporting: Gaussian blur, darkening, Gaussian noise, salt-and-pepper noise, and brightness flicker.
The attack type, activation time, and duration can be configured directly in the script. 

These degradation effects are applied to the RGB camera stream before lane perception and YOLO-based object detection, enabling evaluation of how degraded visual information affects vehicle trajectory, obstacle detection, collisions, and overall driving safety.
### Fixed Hybrid Controller
```bash
python autopilotrun5.py
```
`autopilotrun5.py` implements the fixed hybrid steering strategy used in the CARLASec+ experiments. The final steering command combines 80% vision-based steering and 20% CARLA planner steering:
This configuration prioritises camera-based perception while retaining limited global route guidance from CARLA's route planner.

### Adaptive Hybrid Controller
```bash
python cameradegration.py
```
`cameradegration.py` provides an alternative adaptive version of the hybrid controller. Instead of maintaining a fixed 80/20 ratio, the contribution of the CARLA planner increases when stronger planner steering is required, such as on curved or complex road sections.
The vision contribution varies from approximately **85% on relatively straight sections to 30% during strong turns**, allowing the planner to provide greater route guidance when necessary.


---

# CAN Traffic Monitoring
During experiments, CAN traffic can be monitored using Linux SocketCAN tools.
For example:
```bash
candump vcan0
```
or 
```bash
candump kcan4
```
---
## Citation

If you use CARLASec in academic research, please acknowledge the CARLA simulator and cite our CARLASec research publications:

```bibtex
@inproceedings{nguyen2024ausse,
  author    = {Nhung H. Nguyen and Jin-Hee Cho and Terrence J. Moore and Seunghyun Yoon and Hyuk Lim and Frederica Nelson and Guangdong Bai and Dan Dongseong Kim},
  title     = {AuSSE: A Novel Framework for Security and Safety Evaluation for Autonomous Vehicles},
  booktitle = {2024 54th Annual IEEE/IFIP International Conference on Dependable Systems and Networks - Supplemental Volume (DSN-S)},
  pages     = {1--5},
  year      = {2024},
  doi       = {10.1109/DSN-S60304.2024.00012}
}
```

---
# Research Use 
CARLASec is a **research and simulation framework** intended for cybersecurity research, autonomous vehicle security evaluation, safety analysis, and education in controlled environments.
The CAN and UDS attack examples provided in this repository are only designed for the CARLASec/CARLA simulation environment.

Users should verify the configuration of their CARLA version, SocketCAN interfaces, Python environment, and CARLASec dependencies before running experiments.
