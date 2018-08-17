# posh

This is a repository of my powershell script modules.  These are things I didn't write for work, in fact I'm not sure how useful they are other than as learning excercises.

## get-dnsoverhttp-mt

Key points of this:

* Using DNS over HTTP, invoke-webrequest with json
* Supprting google and cloudflare
* Multi-threading and optimizations
* CAA Statistics for Alexa top 1M

## Using DNS over HTTP

This started as a script I wrote to test DNS over HTTP, to experiment with Cloudflare's 1.1.1.1 service, which provides a DNS over HTTP interface.  I expanded it to support Google's interface, which is essentially the same except google supports more features (subnet, dnssec checkign disable, "ANY" type queries).

* Cloudflare was initially not escaping CAA records (fixed by first wednesday)
* Google's escaping seems incorrect, results in (malformed) records not returning correctly.

## Google and Cloudflare API differences

Mostly both are the same, but there are some subtle differences.  My script defaults to cloudflare, but you can choose google with the -google switch, or by asking a question that cloudflare wouldn't answer.

Field | Required? | Description | Example
--- | --- | --- | ---
name | Required | Query Name | example.com
type | Required | Query Type (either a numeric value or text) | AAAA
cd* | default: false | The CD (checking disabled) bit. | false
edns_client_subnet* | default: empty | The edns0-client-subnet option. | 192.0.2.0/24
random_padding* | string, ignored | The value of this parameter is ignored. | XmkMw~o_mgP2pf.gpw-Oi5dK

* Parameters with an asterisk are only supported by google.
* Cloudflare does not allow queries using the "ANY" type, to reduce DNS amplification DDoS attacks.  They are an author on a draft RFC to standardize [refusing ANY](https://tools.ietf.org/html/draft-ietf-dnsop-refuse-any-06) which seems to be a good idea.
* Google returns the responding server.
* Google lets you request a specific EDNS client subnet, which might be useful for testing CDNs, etc.  Cloudflare sees this as a privacy risk, my script defaults to 0.0.0.0/32 if you don't specify so there is equal privacy.

[Cloudflare documentation](https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/)

[Google Documentation](https://developers.google.com/speed/public-dns/docs/dns-over-https)

### Bugs

* Cloudflare initially had a bug where CAA record answers were not escaped, which meant they were returned as invalid JSON.  They fixed that by the Wednesday after release.
* Google has a similar escaping issue, they escape only the outermost quotes.  This returns valid JSON, but the answer ends up differnt than what is actually in DNS in cases where the CAA is malformed.  Google accepted the [bug](https://issuetracker.google.com/issues/78002839) but no fix was made.  ¯\\_(ツ)_/¯

Dig:

    bunnyears.com.          299     IN      CAA     0 issue "\"letsencrypt.org\""

Cloudflare:

    bunnyears.com.  257 300 0 issue "\"letsencrypt.org\""

Google:

    bunnyears.com.  257 299 0 issue ""letsencrypt.org""

## Multi-threading and optimizations

One use case I decided on was to do batch queries for CAA records using the Alexa top 1M data set.  This quickly proved to be too slow, but I had been wanting to test mult-threading for a while.  While there are good scripts like invoke-async, I decided to use a jobs pattern from Ryan's [Get-Blog](http://www.get-blog.com/?p=189) and incorporate it directly in my script for customization.  In pounding the script with 50k shards of the top 1m, I found some important optimizations to powershell and the script.  Initially it would take over 18 minutes per shard, with optimizations it takes me between 55-65 seconds, so about 900 queries a second.

1. Appending to an array creates a new array, so the "$Jobs += $Job" line is expensive.
2. Increased the outbound HTTP [connection limit](https://social.technet.microsoft.com/wiki/contents/articles/29863.powershell-rest-api-invoke-restmethod-gotcha.aspx)
3. out-null is expensive, instead use "$null = foo" rather than "foo | out-null"
4. I renamed a $iss for clarity.
5. foreach-object is faster than where-object, and without progress the disposal loop can be refactored.
6. Progress display slows things down especially invoke-webrequest.  I put it behind a switch (-Progress) and cleaned up the logic to reduce work.
7. Customized powershell.exe.config for "server" garbage collection.  My home PC has 32GB of RAM so this might not be for everyone.

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe.config:

        <?xml version="1.0" encoding="utf-8" ?>
        <configuration>
            <runtime>
                <gcServer enabled="true"/>
                <Thread_UseAllCpuGroups enabled="true"/>
                <GCCpuGroup enabled="true"/>  
            </runtime>
        </configuration>

## Usage

        import-module .\get-dnsoverhttp-mt.ps1
        Set-Alias doh resolve-dnsnameoverhttp
        doh www.example.com
        get-content biglistofdomains.txt | doh -type CAA -google

I tried to make the parameters a superset of the builtin resolve-dnsname cmdlet.

    NAME
        resolve-dnsnameoverhttp

    SYNTAX
        resolve-dnsnameoverhttp [-Name] <string> [[-Type] <string> {ANY | X | A | AAAA
        | AFSDB | APL | CAA | CDNSKEY | CDS | CERT | CNAME | DHCID | DLV | DNAME |
        DNSKEY | DS | HIP | IPSECKEY | KEY | KX | LOC | MX | NAPTR | NS | NSEC |
        NSEC3 | NSEC3PARAM | OPENPGPKEY | PTR | RP | RRSIG | SIG | SOA | SRV |
        SSHFP | TA | TKEY | TLSA | TSIG | TXT | URI}] [-Subnet <string>]
        [-DnssecCd] [-Google] [-Progress] [-Showall] [-MaxThreads <Object>] [-SleepTimer
        <Object>] [-MaxResultTime <Object>]  [<CommonParameters>]

## Results

* Google DNS is about 20% faster for me.
* Only about 5800 out of the Alexa1M domains have CAA records - 0.5%
* Aout the same number out of the Chromium HSTS preload have CAA, but out of 50000, that's about 10%.
