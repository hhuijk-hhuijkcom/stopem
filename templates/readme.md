# Steam Client Pattern TOMLs

Automatically published by steam-monitor. Do not edit by hand.

## Latest Steam client versions

The version number is the client build's Unix timestamp; the Updated column shows it in UTC.

| Version | Channel | Updated (UTC) | steamclient64.dll | SteamUI.dll | IPC |
| --- | --- | --- | --- | --- | --- |
{% for build in versions | object:"array" | sort:"desc" %}
| {{ build[0] }} | {% if build[1]["channel"] == "beta" %}Beta{% else %}Stable{% endif %} | {{ build[0] | date:("YYYY-MM-DD HH:mm:ss [UTC]", "X") }} | {% if build[1]["steamclient64.dll"] %}[{{ build[1]["steamclient64.dll"] | slice:(0, 12) }}](pattern/steamclient/{{ build[1]["steamclient64.dll"] }}.toml){% else %}-{% endif %} | {% if build[1]["SteamUI.dll"] %}[{{ build[1]["SteamUI.dll"] | slice:(0, 12) }}](pattern/steamui/{{ build[1]["SteamUI.dll"] }}.toml){% else %}-{% endif %} | {% if build[1]["steamclient64.dll"] %}[{{ build[1]["steamclient64.dll"] | slice:(0, 12) }}](ipc/steamclient/{{ build[1]["steamclient64.dll"] }}.toml){% else %}-{% endif %} |
{% endfor %}

Pipeline docs: [docs/pipeline.md](docs/pipeline.md).
