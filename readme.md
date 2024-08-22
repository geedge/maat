<h1 align="left">
  <img src="./docs/imgs/logo.png" height="60px" alt="maat logo"/>
</h1>

**Maat is a unified description framework for network flow processing configuration**

## Name origin
Maat was the goddness of harmony, justice, and truth in ancient Egypt. Her feather served as the measure that determined whether the souls of the departed would successfully reach the paradise of the afterlife. We use this meaning metaphorically to indicate whether the scanning hits an effective rule or not, which is the core function of Maat.

## Why should I use Maat?
Please imagine the following scenario:
* S1：The user adds 10 security deny policies and expects that if the traffic matches any of the 10 configured policies, the traffic should be denied. If the number of policies grows to 1,000, 10,000 or more, and at the same time different policies require different actions such as asllow, monitor, etc.

* S2：The user has pre-stored a large amount of IP geolocation information in a table and expects to quickly retrieve the geolocation information of a given IP address.

The above are two typical usage scenarios of Maat, one is the scanning scenario, and the other is the callback scenario. In addition, Maat also provides detailed path information and statistical information for hit policies, and more advanced features are waiting for you to explore, try it!

## Getting Started
Read [getting started](./docs/getting_started.md) for building steps and play with [examples](./examples/).

## More details

* [Overview](./docs/overview.md)

* [Terminology](./docs/terminology.md)

* [Maat table](./docs/maat_table.md)

* [Configuration management](./docs/configuration_management.md)

* [Object hierarchy](./docs/object_hierarchy.md)

* [Logical combinations](./docs/logical_combinations.md)

* [Thread model](./docs/thread_model.md)

* [Monitor tools](./docs/monitor_tools.md)

* [API reference](./docs/api_reference.md)

* [Performance](./docs/overview.md#6-performance)