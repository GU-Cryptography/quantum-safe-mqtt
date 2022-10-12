import time
import csv

import insecure_mqtt.security_level as security_level
from mqtt_client import MqttClient
from environment import home_path


def connect_x_times(client, num_experiments, results_name):
    """Test MQTT connect time with a given broker configuration a given number of times and record results in the
       given lists"""
    packet_size_list = []
    connect_time_list = []
    for i in range(num_experiments):
        start = time.time()
        client.connect()
        end = time.time()
        connect_time_list.append(end - start)
        packet_size_list.append(i)

    # write results
    with open(home_path + 'insecure_mqtt/results/' + results_name + '.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['Packet Size', 'Connect Time'])
        for i in range(num_experiments):
            writer.writerow([packet_size_list[i], connect_time_list[i]])


def main():
    client = MqttClient(security_level.NONE)
    connect_x_times(client, 100, 'NONE')


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
