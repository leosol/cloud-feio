# Cloud-*Feio* (Ugly - in portuguese) 

Cloud-*Feio* is a tool which aims to help in the identification of a virtual host final IP address. It is capable of searching virtual hosts that respond HTTP requests, HTTPS requests with Server Name Identification (SNI) and HTTPS with with the Host header (without SNI). This tool might be used to **find hosts behind cloudflare** (you have to have at least an idea of which networks the host might be under).

### Basic usage

Please, for better results, consider replacing the network and the expected string for **actual files**. Consider also the **dump certs** option.

```
  python cloud-feio.py example.com '192.168.200.0/24' 'some known and expected string'
```
### Thanks

There has been many contributions of these guys: [jpclaudino](https://github.com/jpclaudino), [jassis](https://github.com/Kirlianz), [kraftdenker](https://github.com/kraftdenker). 

### Pictures

 - Cloud-Feio generates a scan folder. 
 - Matches are the ones with score greater than zero. The score is incrementead whenever an expected line is captured in the response. 
 - Consider activating the save certs option (disabled by default).
 
![Log](/pictures/cloud-feio.JPG)

### Usage
<pre>
usage: cloud-feio.py [-h]
                     domain networks expected-txt [follow-redir] [timeout]
                     [url-resource] [workers] [collect-certs]

Find Vhost in many lans

positional arguments:
  domain         Domain name (www.example.com).
  networks       A file with a list of networks or a single network
                 (192.168.1.0/24)
  expected-txt   Texts that actually exists in the expected response.
  follow-redir   {0,1} Follow redirects (defaults to 1 - yes)
  timeout        Timeout (defaults to 30s)
  url-resource   Extra part of the URL - defaults to / (slash)
  workers        Max open requests at a single time (defaults to 250)
  collect-certs  {0,1} Collect certs (defaults to 0 - no)
</pre>

### Instalation

```
git clone && pip install (improve this)
```

### Usage Examples

 - Try using files instead of a single network. Do the same for the expected strings. Each line in FILE1 must be a network and each line in FILE2 must be a valid and expected string if the host responds.

```
python cloud-feio.py FILE1 FILE2
```

 - You can also use this full command format (args are positional). 

```
#"1 30 '/index.html' 250 1" means: 
#Follow Redirects, 
#Timeout is 30s, 
#'/index.html' can be any URL path or resource
#Max requests at the same time is 250
#1 (the last argument) means *dump certs* (takes extra time)
```

```
python cloud-feio.py example.com networks.txt texts.txt 1 30 '/index.html' 250 1
```


