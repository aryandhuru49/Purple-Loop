# Hunt: accounts requesting service tickets for many different services.
#
# Kerberoasting shows up as one account asking a domain controller for tickets to
# many distinct services, usually with RC4 (0x17) encryption. This hunt ranks every
# requesting account by how many distinct services it touched and how many of those
# tickets were RC4, so an analyst can spot the outlier without a fixed threshold.

@Engine("duckdb");

Ticket(account:, service:, encryption:) :-
  logs(EventID: 4769, TargetUserName: account, ServiceName: service,
       TicketEncryptionType: encryption);

Hunt(account:,
     distinct_services? Count= service,
     rc4_tickets? += (if encryption == "0x17" then 1 else 0),
     total_tickets? += 1) distinct :-
  Ticket(account:, service:, encryption:);
