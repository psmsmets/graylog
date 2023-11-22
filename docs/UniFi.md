# UniFi graylog configuration

## Inputs

Create a local input named `UniFi Network Application` of type `Syslog UDP` and port `5140`.

Add a static field:
* **name** = `syslog_source`
* **value** = `UniFi Network Application`

This field will be used to isolate all messages from the default stream.

## Streams

Create a separate stream for the UniFi controller.
Don't forget to start the stream (play button).

### Create stream

* **Title** = `UniFi Network Application`
* **Description** = `Ubiquity Access Point logs`
* Thick the box to remove matches from ‘Default Stream’

### Stream rules

Add a stream rule: _syslog_source_ **must** match exactly _UniFi Network Application_

* **Field** = `syslog_source`
* **Type** = `match exactly`
* **Value** = `UniFi Network Application`

## Grok patterns

| Name           | Pattern                                          |
| -------------- | ------------------------------------------------ |
| UBNT_DEVICENAME| `([a-zA-Z0-9_-]+)`                               |
| UBNT_HOSTNAME  | `([a-zA-Z0-9-]+)`                                |
| UBNT_ID        | `(([A-Fa-f0-9]{2}){6})`                          |
| UBNT_VERSION   | `((?:[0-9]+).(?:[0-9]+).(?:[0-9]+)\+(?:[0-9]+))` |


## Pipelines

Create a pipeline named `UniFi Network Application` linked to the stream `UniFi Network Application` existing of four stages.


### Stage 0

Messages satisfying **all rules** in this stage, will continue to the next stage.

```
rule "Flatten json and parse"
// From sample data : https://randomuser.me/api/
// Api input path: *
when
    true
then
    let sJson = to_string($message.message);
    let sJson = regex_replace(
        pattern: "^\\[|\\]$",
        value: sJson,
        replacement: ""
        );
    let rsJson = flatten_json(to_string(sJson), "flatten");
    set_fields(to_map(rsJson));
    //remove_field("message");
end
```

### Stage 0.5 (optional)

Drop irrelevant messages from a UDM Pro/SE related to DNS (no rule) and firewall (drop and log new).

Messages satisfying **none or more rules** in this stage, will continue to the next stage.

```
rule "Drop messages with drop and log new"
when
  has_field("message") && contains(to_string($message.message), "drop and Log New")
then
    drop_message();
end
```

```
rule "Drop messages with no rule description"
when
  has_field("message") && contains(to_string($message.message), "no rule description")
then
    drop_message();
end
```

### Stage 1

Messages satisfying **none or more rules** in this stage, will continue to the next stage.

```
rule "Parse Ubiquity access point logs"
when
  true
then
  let m = to_string(get_field("message"));
  let extractedData = grok("%{UBNT_HOSTNAME:ap_hostname} %{UBNT_ID:ap_device_id},%{UBNT_DEVICENAME:ap_device_name}-%{UBNT_VERSION:ap_firmware_version}:%{GREEDYDATA:message}", m);
  set_fields(extractedData);
  remove_field("syslog_source");
end
```

```
rule "Parse BSSID mac address from logs"
when
  true
then
  let m = to_string(get_field("message"));
  let extractedData = grok("bssid=%{MAC:bssid}", m);
  set_fields(extractedData);
end
```

```
rule "Parse STA mac address from logs"
when
  true
then
  let m = to_string(get_field("message"));
  let extractedData = grok("sta=%{MAC:bssid}", m);
  set_fields(extractedData);
end
```

### Stage 2

There are no further stages in this pipeline. 
Once rules in this stage are applied, the pipeline will have finished processing.

```
rule "Parse any MAC address out of message field"
when
  has_field("message")
then
  let m = regex("([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})", to_string($message.message));
  
  // It's NULL if there was no match and will simply not be set internally by Graylog.
  set_field("mac_address", m["0"]);
end
```
