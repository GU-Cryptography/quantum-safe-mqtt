from mqtt_broker import MqttBroker
import x509.security_level as security_level


def main():
    broker = MqttBroker(security_level.POST_QUANTUM)
    broker.monitor()


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
