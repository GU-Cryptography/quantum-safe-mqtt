import time
import csv

from mqtt_client import MqttClient


def connect_x_times(client, num_experiments):
    """Test MQTT connect time with KEMTLS security a given number of times and record results in the
       given lists"""
    connect_time_list = []
    for i in range(num_experiments):
        client.results_file.truncate(0)  # clear bandwidth results (no need to store for each run, as they don't change)
        start = time.time()
        client.kemtls_client_hello()
        end = time.time()
        connect_time_list.append(end - start)
    client.results_file.close()

    # write results
    with open('kem/results/time.csv', 'w') as f:
        f.truncate(0)  # clear previous experiment results
        writer = csv.writer(f)
        writer.writerow(['Run Num', 'Connect Time'])
        for i in range(num_experiments):
            writer.writerow([i, connect_time_list[i]])


def main():
    client = MqttClient()
    connect_x_times(client, 100)


main()
# Press the green button in the gutter to run the script.
# if __name__ == '__main__':
#     main()
