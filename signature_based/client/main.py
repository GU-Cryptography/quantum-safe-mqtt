import time
import csv

from mqtt_client import MqttClient
from environment import home_path


def connect_x_times(client, num_experiments):
    """Test MQTT connect time with KEMTLS security a given number of times and record results in the
       given lists"""
    connect_time_list = []
    for i in range(num_experiments):
        client.clear_results_file()
        start = time.time()
        client.signature_client_hello()
        end = time.time()
        connect_time_list.append(end - start)
    client.results_file.close()

    # write results
    with open(home_path + 'signature_based/results/time.csv', 'w') as f:
        f.truncate(0)  # clear previous experiment results
        writer = csv.writer(f)
        writer.writerow(['Run Num', 'Connect Time'])
        for i in range(num_experiments):
            writer.writerow([i, connect_time_list[i]])


def main():
    client = MqttClient()
    connect_x_times(client, 100)


main()
