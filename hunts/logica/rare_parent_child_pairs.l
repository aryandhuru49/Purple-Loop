# Hunt: rare parent -> child process pairs.
#
# Attackers chain processes in ways normal software rarely does (wscript.exe ->
# powershell.exe, mshta.exe -> powershell.exe, services.exe -> cmd.exe). Counting how
# often each parent/child pair occurs and keeping the rare ones is a classic, rule-free
# way to find execution chains no signature covers yet.
#
# Both Sysmon event 1 and Security event 4688 record process creation, with different
# field names; two rules for the same predicate act as a UNION.

@Engine("duckdb");

# Paths are lower-cased: Windows paths are case-insensitive, and the two event
# sources spell the same path differently (C:\windows vs C:\Windows).
ProcessStart(parent: Lower(parent), child: Lower(child)) :-
  logs(EventID: 1, ParentImage: parent, Image: child);
ProcessStart(parent: Lower(parent), child: Lower(child)) :-
  logs(EventID: 4688, ParentProcessName: parent, NewProcessName: child);

PairCount(parent:, child:) += 1 :- ProcessStart(parent:, child:);

# A pair seen at most twice counts as rare. Each process start is usually logged
# twice (Sysmon 1 + Security 4688), so 2 still means "happened once".
Hunt(parent:, child:, seen:) :-
  PairCount(parent:, child:) = seen,
  seen <= 2;
