--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Minimal IP address/network parsing and matching (P2).
--
--  This unit is deliberately standalone: it depends on nothing else
--  in the crate (no Engine, no Limits) so a future external library
--  can replace these two files without touching the core, the
--  boundary, the tests or the proof. Engine and Boundary may only
--  use this spec; no dotted-quad, hextet, prefix or masking logic
--  may live anywhere else (see DESIGN.md "Library seams" for the
--  replacement contract).
--
--  Total and fail-closed: malformed input yields Length 0, never an
--  exception. Where the Sigma specification is silent, decisions
--  follow DESIGN.md: host bits are masked (lenient); everything
--  ambiguous (leading-zero octets, zone IDs, multiple "::") is
--  rejected.
package Sigma_Verdict.IP with SPARK_Mode is

   subtype Octet is Natural range 0 .. 255;

   Max_IP_Bytes : constant := 16;

   type Byte_Array is array (0 .. Max_IP_Bytes - 1) of Octet;

   --  Length 0 = malformed; 4 = IPv4; 16 = IPv6.
   type IP_Address is record
      Length : Natural range 0 .. Max_IP_Bytes := 0;
      Bytes  : Byte_Array := [others => 0];
   end record;

   function Parse_Address (Text : String) return IP_Address;

   --  Base.Length 0 = malformed. Prefix is bounded by the version:
   --  0 .. 32 (v4), 0 .. 128 (v6). A bare address without "/" takes
   --  the full prefix, like Python's ip_network.
   type IP_Network is record
      Base   : IP_Address;
      Prefix : Natural := 0;
   end record;

   --  Mask_Host selects the documented lenient behaviour: host bits
   --  beyond Prefix are masked off when True, and invalidate the
   --  network (Length 0) when False.
   function Parse_Network
     (Text : String; Mask_Host : Boolean := True) return IP_Network;

   --  True iff Addr lies inside Net. Invalid networks never contain;
   --  invalid addresses are never contained. IPv4 sides are compared
   --  in IPv6 space as ::ffff:0:0/96, so v4/v6 rules and events mix
   --  exactly (a v4 /p is ::ffff:a.b.c.d/(96+p)).
   function Contains (Net : IP_Network; Addr : IP_Address) return Boolean;

end Sigma_Verdict.IP;
