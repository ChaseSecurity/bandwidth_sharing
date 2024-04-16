$TTL    5
@   IN  SOA example.nameserver. example.gmail.com. (
                  2     ; Serial
             604800     ; Refresh
              86400     ; Retry
            2419200     ; Expire
             604800 )   ; Negative Cache TTL
;
@ 86400 IN  NS  example.nameserver.
@ 86400 IN  NS  example.nameserver.
@   IN  A 129.79.242.46
@   IN  AAAA 2001:18e8:2:1080:224:e8ff:fe30:a14
*.example.com. IN A 129.79.242.46
*.example.com. IN AAAA 2001:18e8:2:1080:224:e8ff:fe30:a14
