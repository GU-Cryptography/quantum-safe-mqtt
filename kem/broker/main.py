from mqtt_broker import MqttBroker


def main():
    broker = MqttBroker()
    broker.monitor()


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
