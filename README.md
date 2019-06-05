# KaminskyAttack
Implementation of the Kaminsky attack to remote DNS as described in the [SEED Lab](https://seedsecuritylabs.org/Labs_16.04/Networking/DNS_Remote/)

## Description of the Kaminsky Attack
In the Kaminsky attack, attackers will be able to continuously attack a DNS server on a domain name, without the need for waiting, so attacks can succeed within a very short period of time. In this task, we will try this attack method.
In few words, the attacker sends to the remote DNS some queries for a certain domain; such queries will trigger the Victim DNS Server to perform requests to other servers in order to resolve the request. For such reason, the attacker will forge some replies, spoofing the authoritative answers and trying to guessing the correct transaction ID of the DNS query. Once such well-forged packet is accepted by the Victim DNS, this latter will insert in its cache the resolution for the request, pointing to the attacker DNS server, instead to the real one. 

## Lab environment
The lab environment needs three seperate machines, including 
- a computer for the victim user
- a DNS server 
- the attacker’s machine

              VM 1 (Attacker)     VM 2 (Victim DNS)            VM 3 (User)
              10.0.2.6                10.0.2.15                  10.0.2.7                      
                |                         |                         |
                |_________________________|_________________________|
                |                 Virtual Switch                    |
                |___________________________________________________|
                
 ### VM configuration
 For the correct configuration of the VM follow the instruction written in the [description of the lab](https://seedsecuritylabs.org/Labs_16.04/PDF/DNS_Remote.pdf).

__________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________
## Instruction for compiling the code
To compile type in the attacker's console:
 
 `gcc -lcap spoofdns.c -o spoofdns`
 
## Instruction for running the attack
Type in the attacker's machine:
`sudo ./spoofdns ATTACKERS_IP VICTIM_DNS_IP`

Note: This sample program uses the IP addresses for my environment and for the request for the "example.com" domain, so you should adjust it for your case and recompile the code.



