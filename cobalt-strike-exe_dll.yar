rule artifact_beacon {
   meta:
      description = "from files artifact.exe, beacon.exe"
      date = "2021-04-09"
   strings:
      $s = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii
   condition:
      $s
}
