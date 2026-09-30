const ciscoMarkers = [
  /^\s*hostname\s+\S+/im,
  /^\s*interface\s+(?:GigabitEthernet|FastEthernet|TenGigabitEthernet)\S*/im,
  /^\s*aaa\s+new-model\s*$/im,
  /^\s*ip\s+ssh\s+version\s+\d+\s*$/im,
  /^\s*ip\s+ssh\s+time-out\s+\d+\s*$/im,
  /^\s*line\s+vty\b/im,
  /^\s*transport\s+input\s+(?:ssh|telnet|all)\b/im,
  /^\s*version\s+\S+/im,
];

export function isClearlyCiscoConfiguration(configuration: string): boolean {
  return ciscoMarkers.filter(marker => marker.test(configuration)).length >= 2;
}
