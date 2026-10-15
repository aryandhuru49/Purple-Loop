# Hunt: inventory of every process that opened LSASS, by access mask.
#
# Plenty of legitimate processes touch lsass.exe, almost always with low rights
# such as 0x1000. Building a baseline of (process, access mask) pairs makes the
# odd ones obvious: PowerShell with 0x1010 (Mimikatz-style read) or rundll32 with
# 0x1fffff (comsvcs MiniDump) stand out next to routine svchost 0x1000 handles.
# The detection rule keys on known-bad masks; this hunt shows everything, so masks
# the rule doesn't list yet are still visible.

@Engine("duckdb");

LsassAccess(process:, access:) :-
  logs(EventID: 10, SourceImage: process, TargetImage: target, GrantedAccess: access),
  Like(Lower(target), "%lsass.exe");

Hunt(process:, access:, times? += 1) distinct :- LsassAccess(process:, access:);
