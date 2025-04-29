# The Single Packet Shovel

All resources here are related to the research originally presented at [BSides Exeter 2025](https://bsidesexeter.co.uk/). 

Recording: comming soon...

Write-up: comming soon...

Abstract:

Despite HTTP Request Tunnelling's resurgence in recent years with the advent of [HTTP/2 Desync Attacks](https://portswigger.net/research/http2#h2desync), its much bolder big brother HTTP Request Smuggling has stolen the limelight, leaving cases of desync-powered tunnelling buried for all but the most dedicated tunnelling enthusiasts. 

In this paper I will reveal the discovery of wide-spread cases of request tunnelling in applications powered by popular servers including IIS, Azure Front Door and AWS' Application Load Balancer including the creation of a novel detection technique that combined the recently popularised "Single-Packet Attack" with our ever-trusty HTTP desync techniques. 

Throughout the journey I will also explore the complexities of navigating security research for the first time, drawing parallels from the advice given in [so you want to be a web security researcher](https://portswigger.net/research/so-you-want-to-be-a-web-security-researcher) and illuminate the ease through which existing tooling from industry leading researchers can be adapted in order to rapidly test your own ideas even with a rudimentary understanding of programming.

---

|Resource|Description|
|-|-|
|sp&#x2011;tunnel.py|A [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder) script to aid in exploitation. It will repeat the single-packet attack until it recieves a tunnelled response| 
|single&#x2011;packet&#x2011;tunneller/|Burp extension used during the research. Also supports guessing internal headers using [param-miner](https://github.com/PortSwigger/param-miner) logic + single-packet attack. To build just run `./gradlew build`|
|slides.pdf|The slides from my presentation at [BSides Exeter 2025](https://bsidesexeter.co.uk/)|


