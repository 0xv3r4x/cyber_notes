# Splunk 2

*Part of the Blue Primer series. This room is based on version 2 of the Boss of the Soc (BOTS) competition by Splunk.*

Background:

Assume persona of Alice Bluebird, an anlyst who successfully assisted Wayne Enterprises and was recommended to Grace Hoppy at Frothly (a beer company) to assist them with recent issues

###### 100 Series Questions

Entering the following into the search bar:

```
index="botsv2" amber
```

Taking `botsv2` as the data source, and using the phrase "amber" to filter out the events in Splunk.  

The IP address of Amber's machine will be visible in the PAN (Palo Alto Networks) traffic:

```
index="botsv2" sourcetype="pan:traffic" amber
```

Once executed, the "Interesting fields" side-bar contained a `src_ip` field, which shows Amber's IP:

![[ambers_ip_address.png]]

We can then build the following command which will filter the HTTP traffic associated with `10.0.2.101`.

```
index="botsv2" 10.0.2.101 sourcetype="stream:http"
```

As there were still a lot of events, we can remove the duplicated for the `site` field and print out only the `site` information:

```
index="botsv2" sourcetype="stream:http" 10.0.2.101
| Dedup site
| Table site
```

We can then add the "`*beer*`" parameter to reduce the fields to only show sites relating to the Frothly company:

```
index="botsv2" sourcetype="stream:http" src_ip="10.0.2.101" *beer*
| Dedup site
| Table site
```

![[amber_visited_domain.png]]

Amber found the contact info through an image file on the website.  We can therefore use the following query to find the `uri_path` of the image:

```
index="botsv2" sourcetype="stream:http" src_ip="10.0.2.101" www.berkbeer.com
| Table uri_path
```

![[ceoberk_uri_path.png]]

She then sent them an email, so we can filter for `stream:smtp` traffic with `amber`:

```
index="botsv2" sourcetype="stream:smtp" amber
```

![[ceo_contact_info.png]]

![[attach_filename.png]]

-----

###### Task 1 - Deploy

1. Deployed the virtual machine and connected to the website found at `10.10.67.38:8000`.

```
No answer needed
```

###### Task - Dive into the Data

1. I'm ready to get hunting with Splunk

```
No answer needed
```

###### Task 3 - 100 Series Questions

1. Amber Turing was hoping for Frothly to be acquired by a potential competitor which fell through, but visited their website to find contact information for their executive team. What is the website domain she visited?

```
www.berkbeer.com
```

2. Amber found the executive contact information and sent him an email. What image file displayed the executive's contact information?

```
/images/ceoberk.png
```

3. What is the CEO's name? Provide the first and last name.

```
Martin Berk
```

4. What is the CEO's email address?

```
mberk@berkbeer.com
```

5. After the initial contact with their CEO, Amber contacted another employee at this competitor. What is that employee's email address?

```
hbernhard@berkbeer.com
```

6. What is the name of the file attachment that amber sent to a contact at the competitor?

```
Saccharomyces_cerevisiae_patent.docx
```

7. What is Amber's personal email address?

```

```

###### Task 4 - 200 Series Questions

###### Task 5 - 300 Series Questions

###### Task 5 - 400 Series Questions

###### Task 7 - Conclusion