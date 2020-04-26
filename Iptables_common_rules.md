sudo iptables -L --line-numbers

// Default policy to drop
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP

// Accept any related or established connections
sudo iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -I OUTPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

// Allow traffic on loopback interface
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

// Allow DHCP request
sudo iptables -A OUTPUT -o [iface] -p udp --dport 67:68 --sport 67:68 -j ACCEPT

// Allow outbound email (if email client)
sudo iptables -A OUTPUT -i [iface] -p tcp -m tcp --dport 25 -m state --state NEW -j ACCEPT

// Allow outbound dns lookups
sudo iptables -A OUTPUT -o [iface] -p udp -m state --state NEW --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -o [iface] -p tcp -m state --state NEW --dport 53 -j ACCEPT

// Allow outbound ping requests
sudo iptables -A OUTPUT -o [iface] -p icmp -j ACCEPT

// Allow outbound NTP requests
sudo iptables -A OUTPUT -o [iface] -p udp --dport 123 --sport 123 -j ACCEPT

// Allow outbound HTTP
sudo iptables -A OUTPUT -o [iface] -p tcp -m tcp --dport 80 -m state --state NEW -j ACCEPT
sudo iptables -A OUTPUT -o [iface] -p tcp -m tcp --dport 443 -m state --state NEW -j ACCEPT