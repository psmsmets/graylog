# pfSense graylog configuration


```
rule "Parse pfSense DHCPD logs"
when
  has_field("message") && get_field("application_name") == "dhcpd"
then
  let m = to_string(get_field("message"));
  let extractedData = grok("%{DATA:dhcpd_type} on %{IPV4:client_ip} to %{DATA:client_mac} (%{DATA:client_name}) via %{DATA:dhcpd_route}", m);
  set_fields(extractedData);
end
```
