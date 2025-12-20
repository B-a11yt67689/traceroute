# traceroute

Учебная реализация `traceroute` на Python с анализом маршрута.

## Что делает

Программа отправляет UDP-пакеты с увеличивающимся значением TTL и принимает ICMP-ответы от маршрутизаторов по пути к целевому хосту.  
Для каждого хопа выводится IP/hostname и время отклика.

Дополнительно:

* помечает хопы с большим временем ответа как `HIGH_RTT`;
* пытается обнаруживать циклы маршрутизации (`LOOP?`), если один и тот же IP встречается несколько раз подряд.

## Запуск

Из корня репозитория:

```bash
python traceroute.py <host>
## Testing

The utility requires raw sockets and network access.

Manual tests:
sudo python3 traceroute.py -n 5 1.1.1.1 icmp
sudo python3 traceroute.py -n 5 -p 443 1.1.1.1 tcp
sudo python3 traceroute.py -n 5 -p 53 1.1.1.1 udp
sudo python3 traceroute.py -v -r 1.1.1.1 icmp
sudo python3 traceroute.py --debug -n 3 1.1.1.1 icmp