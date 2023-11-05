## ACN Programming Assignment 3

### Part 1: Learning Switch and Hub Controller

#### Question 1
Conduct 3 pings for each case. Report the latency values. Explain the observed latency differences between the Hub Controller and Learning Switch. Also, explain differences (if any) observed between h2 and h5 for both controller types.

- **Figure 1 HUB ping results with latency:**
  ![Insert Hub ping results here](https://github.com/iitKD/ACN_assignment3/blob/main/img/hub_pingresult.png)
- **Learning switch ping results with latency:**
  ![Insert Learning switch ping results here](https://github.com/iitKD/ACN_assignment3/blob/main/img/lswitch_pingresults.png)

**Answer:**
The learning switch saves port mappings based on the source and destination of packets, allowing it to learn where to send a packet for a given source and destination. This reduces the time it takes to find the destination of packets in subsequent pings, resulting in lower latency values as the number of pings increases.
While using Hub, there is no stored data for mapping source and destination ports of a packet. Therefore, for every ping, the destination address of the packet has to be resolved using ARP signals. This results in increased latency for every subsequent packet, as it does not decrease significantly.

#### Question 2
Run a throughput test between h1 and h5. Report the observed values. Explain the differences between the Hub Controller and Learning Switch.

- **Throughput between H1 and H5 in HUB:**
    ![Insert throughput values for Hub Controller here](https://github.com/iitKD/ACN_assignment3/blob/main/img/hunthpt_h1h5.png)
- **Throughput between H1 and H5 in Learning Switch:**
    ![Insert throughput values for Learning Switch here](https://github.com/iitKD/ACN_assignment3/blob/main/img/thpt_h1_h5ls.png)

**Answer:**
The difference in throughput between the learning switch and the hub is due to the learning switch storing the port mapping while the hub has to resolve the destination address each time, leading to decreased throughput.

#### Question 3
Run `pingall` in both cases and report the installed rules on switches.

- **Pingall HUB and Switch rules:**
    ![Insert installed rules for Hub Controller here](https://github.com/iitKD/ACN_assignment3/blob/main/img/hub_pingall.png)
- **Pingall Learning switch and rules on learning switches:**
    ![Insert installed rules for Learning Switch here](https://github.com/iitKD/ACN_assignment3/blob/main/img/LS_pingall.png)

### Part 2: Firewall

#### Question 1
Run `pingall` and report the results.

- **Ping reachability for every host:**
    - ![Insert ping reachability results here](https://github.com/iitKD/ACN_assignment3/blob/main/img/firewall1.png)
- **Packet drop messages from the Controller:**
    - ![Insert packet drop messages here](https://github.com/iitKD/ACN_assignment3/blob/main/img/firewall3.png)

#### Question 2
Report the installed rules on both switches. Can you think of ways to minimize the number of firewall rules on the switch?

- **Rules installed on the switches:**
    - ![Insert installed firewall rules here](https://github.com/iitKD/ACN_assignment3/blob/main/img/firewall2.png)

**Answer:**
When managing a firewall, it is more efficient to use CIDR notation for IP addresses when creating rules instead of making separate rules for individual IP addresses or services. This will help to better manage the firewall. Group the hosts that need to be blocked together and add a rule for the group instead of creating separate rules for each host.

#### Question 3
Suppose the network operator intends to implement firewall policies in real time. How can she ensure that the pre-existing rules do not interfere with the firewall policy?

**Answer:**
- Prioritize the rules: The dynamic rules can be given a lower priority, and the preexisting rules higher so that if in case of conflicting rules, the preexisting rules will be implemented, or vice versa.
- Keep track of conflicting rules: Whenever some conflict arises, track it to avoid similar conflicts in the future.

### Part 3: Load Balancer

#### Question 1
Have the three hosts (H1, H2, and H3) ping the virtual IP and report the installed rule on the switches.

- **Ping results for H1, H2, and H3 to virtual IP:**
    - ![Insert ping results to virtual IP here](https://github.com/iitKD/ACN_assignment3/blob/main/img/LB1.png)
- **Controller output:**
    - ![Insert controller output here](https://github.com/iitKD/ACN_assignment3/blob/main/img/LB2.png)
- **Installed rules:**
    - ![Insert installed rules for load balancing here](https://github.com/iitKD/ACN_assignment3/blob/main/img/LB3.png)

#### Question 2
If you were to implement a load balancing policy that considers the load on these servers, what additional steps would you take?

**Answer:**
A load balancer for H4 and H5 would require a feedback mechanism to monitor server health and performance. Additional steps may include:
- Periodically checking the health of H4 and H5.
- Updating flow rules to direct traffic away from overloaded or unresponsive servers.
- Using historical data of server utilization for informed load balancing decisions.
- Implementing geolocation-based load balancing for reduced latency.

