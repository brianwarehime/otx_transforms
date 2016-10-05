# otx_transforms
Transforms for the AlienVault OTX service

First things first, you'll need to grab them from my [Github](https://github.com/brianwarehime/otx_transforms). Once you grab the .mtz file, you'll open up Maltego, and then click on Import, then Import Configuration, then select the .mtz file you just downloaded from GitHub. You'll also need to download the Python file otx.py from GitHub into a place on your machine, something like /Users/Brian/Maltego or wherever you prefer.

Once imported, you'll need to edit each one (a pain I know...) so it points to where the Python file you downloaded is located. To do this, open up "Manage Transforms" under the "Transforms" menu in the menubar. A window will pop like the screenshot below, in that window, you'll need to change the "Command Line" to wherever Python is, this will be different if you're using Windows. You'll also need to change the "Working Directory" to wherever the Python file otx.py is stored.

![transforms](http://i.imgur.com/LTJb3pg.png)

To make things easier on people, these transforms can possibly be moved to a TDS server, so you don't need to do modify all the transforms, however, I didn't want to stand this up if a lot of people are using it, and it'll end up costing me a bunch of money to host the server. Also, some people would rather do things in-house, rather than having their queries going through a middle-man.

After you have the transforms set up, you'll need to add your API key to the otx.py file in order to make the queries to AlienVault. Getting an API key is a painless process and just requires you to make an account in the OTX website. You'll need to edit Line 11 in the otx.py file with your key to use these transforms.

Alright, good to go now, and we can start using these guys...

Let's start by throwing out a IP Address we grabbed from malwaredomainlist.com, 213.145.225.170. 

![ip](http://i.imgur.com/VG77ADu.png)

Pretty boring right now, so, let's start adding some basic context around this indicator. Right-click on the IP and then select the "OTX - Get ASN/Geo Data" to run the transform that pulls the geographic and ASN data from AlienVault OTX.

![transforms](http://i.imgur.com/Zie4dTg.png)

Once you run the transform, you get a new Location entity that contains the ASN and Country associated with that IP Address. 

![geo](http://i.imgur.com/j1Vgthn.png)

Alright, let's dig a little deeper. The next transform available to us is "OTX - Get Associated Malware". Running this will create Malware entities in your graph, that are hashes associated with the given entity.

![malware](http://i.imgur.com/DU3hb7u.png)

In the above image, we can see two hashes that are associated with this IP Address. Before digging into the hashes, let's see what else we can figure out about this IP Address...

Let's right-click on the IP Address and choose "OTX - Get Passive DNS". This will query OTX and return any domains that this IP has resolved to in the past. You'll also notice that the link between the IP and the hashes as well as any other links (excluding ASN/Geo data), will show the date that the link was seen. For instance, the dates in the links below show the date that the domains were seen resolving to that IP Address.

![passivedns](http://i.imgur.com/msVpixJ.png)

Alright, next for the IP Address is seeing what other "Pulses" were related to this indicator. Pulses are a collection or group of indicators that users of OTX can submit to group related indicators together. If we right-click and select the "OTX - Get Related Pulses", we'll see a new entity type called "Pulse" be displayed for related indicators.

![pulses](http://i.imgur.com/23M8Q3z.png)

You'll see in the bottom of the image above, the little green alien with the title being the Pulse name "MalwareDomainList", which is where we grabbed the initial indicator from.

Lastly for this indicator is related URL's. This consists of any URL's seen for any of the domains that this IP resolved to in the past. Right click on the indicator and select "Get Related URL's" to get started.

![urls](http://i.imgur.com/fRNncQ5.png)

That's it for this type of indicator. You can use most of the above transforms for other indicator types as well, such as Domains, Hostnames, URL's and Hashes, so try it out on all of them. Next, I want to cover some other transforms that are available for certain entity types, first up is Hashes.

If you right-click on a hash, you'll have the new transform "OTX - Get File Analysis" available to you. Clicking on this will create a new entity with the MD5 hash of the file you selected. If you then click on "Type Actions" when you right-click, and then "Open all URLs" you can then open a new page in your browser to the analysis of the file hash.

![analysis](http://i.imgur.com/avE7XYD.png)

Last thing to cover is viewing indicators associated with a particular pulse. If we right-click on the pulse entity, we can use the new transform "OTX - Get Related Indicators" to return any indicators associated with this pulse. There is a small bug currently, where if the indicator type isn't one supported by Maltego, it will display the default chess icon. I'll work on making sure all that can be supported by Maltego, are supported.

![pulse](http://i.imgur.com/LvnEiCc.png)

Alright, well, that should cover everything. For questions, feel free to email me at brian@nullsecure.org or post any issues/bugs to the Github page.
