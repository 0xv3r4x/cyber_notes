# Active Directory

## What is Active Directory?

- **Active Directory** (AD) is a directory service developed my Microsoft to manage Windows domain networks
- It stores information relating to objects, such as computers, users, printers, etc.
	- Very similar to a phone book but for Windows
- Authenticates using Kerberos tickets
	- Non-Windows devices, such as Linux machines or firewalls, can also authenticate to Active Directory via RADIUS or LDAP
- Active Directory allows you to use one username and password to log into any machine on a network

## Why Active Directory?

- AD is the most commonly used identity management service in the world
	- 95% of Fortune 1000 companies implement the service in their networks [Source](https://techcommunity.microsoft.com/t5/Enterprise-Mobility-Security/Success-with-Enterprise-Mobility-Itentity/ba-p/246813)
- Can be exploited without ever attacking patchable exploits
	- Instead, we abuse features, trusts, components, and much more
	- Commonly, the external network is secured, but the internal network has little to no security policies in place

# Physical Active Directory Components

## Domain Controllers

A **domain controller** (DC) is a server with the Active Directory Domain Services (AD DS) server roles installed that has been specifically promoted to a domain controller.

Domain controllers:
- Host a copy of the AD DS directory store
	- Holds a list of all computers, users, printers, etc. on the domain
- Provides authentication and authorisation services
- Replicates updates to other domain controllers in the domain and forest
- Allow administrative access to manage user accounts and network resources
	- Can add users, other systems, policies, etc.

The domain controller is vital to the function of a enterprise environment. If a domain controller is compromised, the entire internal network may also be completely taken over - depending on how many domain controllers exist within the network.

## AD DS Data Store

The AD DS **data store** contains the database files and processes that store and manage directory information for users, services, and applications.

The AD DS data store:
- Consists of the `Ntds.dit` file
	- When you compromise a DC, you want to grab this file
	- Contains password hashes for all users on the domain
- Is stored by default in the `%SystemRoot%\NTDS` folder on all domain controllers
- Is accessible only through the domain controller processes and protocols

# Logical Active Directory Components

## AD DS Schema

The AD DS **schema**:
- Defines every type of object that can be stored in the directory
	- Similar to a rule book or blueprint
- Enforces rules regarding object creation and configuration

| Object Types | Function | Example |
| - | - | - |
| Class Object | What object can be created in the directory | User; Computer |
| Attribute Object | Information that can be attached to an object | Display name |

## Domains

**Domains** are used to group and manage objects in an organisation.

Domains are:
- An administrative boundary for applying policies to groups of objects
- A replication boundary for replicating data between domain controllers
- An authentication and authorisation boundary that provides a way to limit the scope of access to resources

For example, a small business may only have one domain, but a larger organisations may have several.

## Trees

A domain **tree** is a hierarchy of domains in AD DS.

All domains in the tree:
- Share a contiguous namespace with the parent doain
- Can have additional child domains
- By default create a two-way transitive trust with other domains

For example, a parent domain `contoso.com` may have additional child domains, `na.contoso.com` and `emea.contoso.com`.

## Forests

A **forest** is a collection of one or more domain trees.

Forests:
- Share a common schema
- Share a common configuration partition
- Share a common global catalog to enable searching
- Enable trusts betwewn all domains in the forest
- Share the Enterprise Admins and Schema Admins groups

## Organisational Units (OUs)

Within Active Directory, there are **Organisational Units** (OUs) which are containers that are comprised of userse, groups, computers, and other OUs.

Organisational Units are used to:
- Represent your organisation hierarchically and logically
- Manage a collection of objects in a consistent way
- Delegate permissions to administer groups of objects
- Apply policies

## Trusts

**Trusts** provide a mechanism for users to gain access to resources in another domain.

| Type of Trusts | Description | Diagram |
| - | - | - |
| Directional | The trust direction flows from the *trusting* domain to the *trusted* domain | ![[directive_trust.png]] |
| Transitive | The trust relationship is *extended* beyond a two-domain trust to include other trusted domains | ![[transitive_trust.png]] |

- All domains in a forest trust all other domains in the forest
- Trusts can extend outside the forest

## Objects

**Objects** are contained within the Organisational Units (OUs).

| Object | Description |
| - | - |
| User | Enables network resource access for a user |
| InetOrgPerson | Similar to a user account; Used for compatibility with other directory services |
| Contacts | Used primarily to assign email addresses to external users; Does not enable network access |
| Groups | Used to simplify the administration of access control |
| Computers | Enables authentication and auditing of computer access to resources |
| Printers | Used to simplify the process of locating and connecting to printers |
| Shared folders | Enables users to search for shared folders based on properties |

## Kerberos

Kerberos is the default mechanism for authentication within Active Directory environments.  It utilises strong cryptography and third-party ticket granting to authenticate users.

#### Components

**S**ervice **P**rincipal **N**ame (**SPN**):
- identifier given to a service instance
- associates a service instance to a domain service account

**P**rivilege **A**ttribute **C**ertificate (**PAC**):
- contains relevant user information
- sent to the KDC with the TGT to be signed in order to validate the user

T**icket **G**ranting **T**icket (**TGT**):
- authentication ticket used to request service tickets from TGS

**A**uthentication **S**ervice (**AS**):
- authenticates the client

**T**icket **G**ranting **S**ervice (**TGS**):
- provides tickets and TGTs to client systems
- contain a client ID, client network address, ticket validity period, and TGS session key

**K**ey **D**istribution **C**enter (**KDC**):
- database of keys used in the authentication process
- consists of AS and TGS


#### Process

General authentication process:

1. Client requests a **T**icket **G**ranting **T**icket (**TGT**) from the **K**ey **D**istribution **C**enter (**KDC**)
2. The KDC verifes the credentials and sends back an encrypted TGT and session key
3. The TGT is encrypted using the **T**icket **G**ranting **S**ervice (**TGS**) secret key
4. The client stores the TGT and when it expires, the local session manager will request another TGT

When requesting access to a service:

1. Client sends current TGT to TGS with the **S**ervice **P**rincipal **N**ame of the resource they want to access
2. The KDC verifies the TGT of the user and the user has access to the service
3. TGS sends a valid session key for the service to the client
4. Client forwards the session key to the service to prove the user has access, and the service grants access