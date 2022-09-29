# Active Directory

## Initial Attack Vectors

#### LLMNR Poisoning

**L**ink **L**ocal **M**ulticast **N**ame **R**esolution (**LLMNR**) is based on the **D**omain **N**ame **S**ystem (**DNS**) packet format.  It allows both IPv4 and IPv6 hosts to perform name resolution for hosts on the same local link.

A common flaw is that the service utilise a user's username and NTLM hash when responded to, thus enabling LLMNR Poisoning.

## Kerberos

#### Golden Ticket Attack

The Golden Ticket attack gives an attacker complete access to the entire domain.  It involves gaining elevated access to a domain controller, at which point the attacker can dump the password hash for the KRBTGT account, thus creating the golden ticket.

The attacker can then authenticate as any user and access anything on the network.

#### Silver Ticket Attack

The Silver Ticket attack is a forged authentication ticket which gives the attacker access to a particular service.