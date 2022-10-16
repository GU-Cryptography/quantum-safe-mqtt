# quantum-safe-mqtt

## Author
Raven Townsend, rto45@uclive.ac.nz

## Project Background

This repository contains code relevant to my final year project for my Bachelor of Software Engineering (Honours) carried out in 2022. 

### Project Abstract

MQTT is a common communication protocol used in the Internet of Things. The protocol provides no security, and current proposals to add security do not consider the future risk of post-quantum attacks. This is a severe risk, as MQTT is often used in conjunction with private data and critical systems, such as locks, video cameras and sensors so security breaches could have a significant impact. 
The purpose of this project is to investigate potential ways of adding post-quantum-safe authentication security to MQTT.

### Research Questions

1. What algorithm could be used to add quantum-safe authentication to MQTT in a signature-based scheme?
2. What algorithm could be used to add quantum-safe authentication to MQTT in a KEM-based scheme?
3. What are the consequences in terms of adding quantum-safe authentication through either method in terms of bandwidth, storage, and connection speed?

### Results

Through academic research, CRYSTALS-Dilithium was determined as an appropriate signatuer algorithm and CRYSTALS-Kyber was determined as an appropriate KEM algorithm. In order to compare these algorithms (as per Research Question 3), proof-of-concept implementations of secure MQTT are provided in this repository. The implementations are not intended to be functional, rather to compare the authentication handshake between the two methods and insecure MQTT. Therefore, they implement only the handshake of MQTT, with no additional options (i.e. the most basic implementation of MQTT).

## Usage

### Installation

Clone the repository with the command:

`$ git clone https://github.com/raven-townsend-nz/quantum-safe-mqtt.git`

Install the pqcrypto library (used for implementations of Dilithium and Kyber):

`$ pip install pqcrypto`

### Running experiments

The repo contains three key packages: `insdecure_mqtt`, `kem`, and `signature_based`. 
- The `insecure_mqtt` module contains a skeleton implementation of MQTT with a standard handshake, with no security or additional options. 
- The `signature_based` module contains a skeleton implementation of MQTT with signature based handshake.
- The `kem` module contains a skeleton implementation of MQTT with KEM based handshake based on the paper: https://eprint.iacr.org/2020/534.pdf

Each package contains a `broker` and `client` directory. These must be run separately, e.g. different machines, VMs, or terminal windows. To test particular security architecture (e.g. `kem`), the following steps should be followed:

In the relevant package, edit the `broker/config_files/config.json` and `client/config_files/config.json` to include the correct IP addresses and port numbers. Edit 'environment.py` in the root directory, to contain the correct location of the cloned repo on your device.

On the broker:

`$ cd kem/broker` (or the relevant package you wish to test)

`$ python3 main.py`

On the client:

`$ cd kem/client` (or the relevant package you wish to test)

`$ python3 main.py`

The client will record results into the `kem/results` directory. It will include `bandwidth.csv` and `times.csv` result files. 
- `bandwidth.csv` contains the number of bytes of each message sent, along with the message name.
- `times.csv` contains the time (in seconds) that each handshake took to complete the authentication handshake. By default it will run the handshake 100 times, but this can be changed in the `client/main.py` file.



