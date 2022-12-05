rule plist_lolbins_strings {
  meta:
    version = "1.0"
    description = "Checks plist files for lolbins usage."
    author = "Martin Jaan Leesment"
    creation_date = "2022-10-14"
    classification = "TLP:WHITE"
  strings:
    $a = "/bin/"
    $b = "bash"
    $c = "curl"
    $d = "mktemp"
    $e = "osascript"
condition:
    any of them
}

rule plist_creation {
  meta:
    version = "1.0"
    description = "Checks for plist creation by a Mach-O"
    author = "Martin Jaan Leesment"
    creation_date = "2022-11-07"
    classification = "TLP:WHITE"
  strings:
    $plist = /\/Library\/*.plist"/
  condition:
    $plist
}

rule hidden_launch_items {
  meta:
    version = "1.0"
    description = "Checks for hidden launch item creation"
    author = "Martin Jaan Leesment"
    creation_date = "2022-11-07"
    classification = "TLP:WHITE"
  strings:
    $launch_daemons = "/Library/LaunchDaemons/"
    $launch_agents = "/Library/LaunchAgents/"
    $reg = /\.com\.[a-zA-Z0-9]+\.plist/
   condition:
    ($launch_daemons and $reg) or ($launch_agents or $reg)
}

