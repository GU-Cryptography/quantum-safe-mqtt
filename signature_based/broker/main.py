from mqtt_broker import MqttBroker


def main():
    broker = MqttBroker()
    # try:
    broker.monitor()
    # except Exception as error:
    #     print(error)
    #     for sock in broker.socket_list:
    #         sock.close()


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
