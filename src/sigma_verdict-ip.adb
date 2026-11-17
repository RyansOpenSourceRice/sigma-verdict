--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

package body Sigma_Verdict.IP with SPARK_Mode is

   function Is_Digit (C : Character) return Boolean is
     (C in '0' .. '9');

   function Is_Hex (C : Character) return Boolean is
     (C in '0' .. '9' or else C in 'a' .. 'f' or else C in 'A' .. 'F');

   function Hex_Digit (C : Character) return Natural is
     (case C is
        when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
        when 'a' .. 'f' => Character'Pos (C) - Character'Pos ('a') + 10,
        when 'A' .. 'F' => Character'Pos (C) - Character'Pos ('A') + 10,
        when others     => 0)
   with Pre => Is_Hex (C);

   Powers : constant array (1 .. 7) of Natural :=
     [2, 4, 8, 16, 32, 64, 128];

   ------------------
   --  IPv4 parsing --
   ------------------

   --  Strict dotted quad: four 0..255 parts, no empty parts, no
   --  leading zeros (the octal trap fails closed).
   function Parse_V4 (Text : String) return IP_Address is
      R          : IP_Address;
      Part       : Natural := 0;
      Digit_Count     : Natural := 0;
      First_Zero : Boolean := False;
      Count      : Natural := 0;
   begin
      if Text'Length = 0 or else Text'Length > 15 then
         return R;
      end if;
      for I in Text'Range loop
         pragma Loop_Invariant (Part <= 255);
         pragma Loop_Invariant (Count <= 4);
         if Text (I) = '.' then
            if Digit_Count = 0 or else Count >= 4 then
               return R;
            end if;
            R.Bytes (Count) := Part;
            Count := Count + 1;
            Part := 0;
            Digit_Count := 0;
            First_Zero := False;
         elsif Is_Digit (Text (I)) then
            --  Explicit cap instead of an invariant: at most three
            --  significant digits can precede a >255 rejection.
            if Digit_Count > 3 then
               return R;
            end if;
            if Digit_Count >= 1 and then First_Zero then
               return R;
            end if;
            Part := Part * 10
              + (Character'Pos (Text (I)) - Character'Pos ('0'));
            if Part > 255 then
               return R;
            end if;
            if Digit_Count = 0 and then Text (I) = '0' then
               First_Zero := True;
            end if;
            Digit_Count := Digit_Count + 1;
         else
            return R;
         end if;
      end loop;
      if Count /= 3 or else Digit_Count = 0 then
         return R;
      end if;
      R.Bytes (3) := Part;
      R.Length := 4;
      return R;
   end Parse_V4;

   ------------------
   --  IPv6 parsing --
   ------------------

   type Hextet is range 0 .. 65535;

   type Word_Array is array (0 .. 7) of Hextet;

   --  Parses Text (First .. Last) as ":"-separated hextets appended at
   --  Words (Count ..). Empty range is Ok with no words (the "::"
   --  sides). The last group may be an embedded IPv4 tail when
   --  Allow_V4 (it counts as two hextets and must be terminal).
   procedure Parse_V6_Part
     (Text     : String;
      First    : Natural;
      Last     : Natural;
      Start    : Natural;
      Words    : in out Word_Array;
      Count    : out Natural;
      Allow_V4 : Boolean;
      Ok       : out Boolean)
   with Pre => First >= Text'First
     and then Last <= Text'Last
     and then Start <= 8,
     Post => Count >= Start and then Count <= 8
   is
      V      : Natural := 0;
      Digit_Count : Natural := 0;
   begin
      Ok := True;
      Count := Start;
      if First > Last then
         return;
      end if;
      for J in First .. Last loop
         pragma Loop_Invariant (V <= 65535);
         pragma Loop_Invariant (Digit_Count <= 4);
         pragma Loop_Invariant (Count >= Start);
         pragma Loop_Invariant (Count <= 8);
         if Text (J) = ':' then
            if Digit_Count = 0 or else Count > 7 then
               Ok := False;
               return;
            end if;
            Words (Count) := Hextet (V);
            Count := Count + 1;
            V := 0;
            Digit_Count := 0;
         elsif Text (J) = '.' then
            if not Allow_V4 then
               Ok := False;
               return;
            end if;
            --  The embedded IPv4 tail starts at its group, i.e.
            --  after the previous ':' (or at First): scan back to
            --  it so "ffff:10.0.0.1" parses "10.0.0.1", not ".0.0.1".
            declare
               GS : Natural := J;
            begin
               while GS > First and then Text (GS - 1) /= ':' loop
                  pragma Loop_Invariant (GS > First);
                  pragma Loop_Invariant (GS <= J);
                  pragma Loop_Variant (Decreases => GS);
                  GS := GS - 1;
               end loop;
               declare
                  T : constant IP_Address := Parse_V4 (Text (GS .. Last));
               begin
                  if T.Length /= 4 or else Count > 6 then
                     Ok := False;
                     return;
                  end if;
                  Words (Count) :=
                    Hextet
                      (Natural (T.Bytes (0)) * 256
                       + Natural (T.Bytes (1)));
                  Words (Count + 1) :=
                    Hextet
                      (Natural (T.Bytes (2)) * 256
                       + Natural (T.Bytes (3)));
                  Count := Count + 2;
               end;
            end;
            return;
         elsif Is_Hex (Text (J)) then
            if Digit_Count >= 4 then
               Ok := False;
               return;
            end if;
            V := V * 16 + Hex_Digit (Text (J));
            if V > 65535 then
               Ok := False;
               return;
            end if;
            Digit_Count := Digit_Count + 1;
         else
            Ok := False;
            return;
         end if;
      end loop;
      if Digit_Count = 0 or else Count > 7 then
         Ok := False;
         return;
      end if;
      Words (Count) := Hextet (V);
      Count := Count + 1;
   end Parse_V6_Part;

   function Parse_V6 (Text : String) return IP_Address is
      R            : IP_Address;
      Words        : Word_Array := [others => 0];
      LC           : Natural := 0;
      RC           : Natural := 0;
      TR           : Natural;
      Double_At    : Natural := Text'First;
      Double_Count : Natural := 0;
      Base_Idx     : Natural;
      Ok           : Boolean;
   begin
      if Text'Length < 2 or else Text'Length > 45 then
         return R;
      end if;
      for I in Text'First .. Text'Last - 1 loop
         pragma Loop_Invariant (Double_At >= Text'First);
         pragma Loop_Invariant (Double_At <= Text'Last);
         if Text (I) = ':' and then Text (I + 1) = ':' then
            --  Explicit cap: "::" pairs cannot outnumber the
            --  characters (length is already bounded above).
            if Double_Count >= Text'Length then
               return R;
            end if;
            Double_Count := Double_Count + 1;
            Double_At := I;
         end if;
         if Text (I) = '%' or else Text (Text'Last) = '%' then
            return R;
         end if;
      end loop;
      if Double_Count > 1 then
         return R;
      end if;
      if Double_Count = 0 then
         Parse_V6_Part (Text, Text'First, Text'Last, 0, Words, LC,
                        True, Ok);
         if not Ok or else LC /= 8 then
            return R;
         end if;
         for K in 0 .. 7 loop
            R.Bytes (2 * K) := Octet (Words (K) / 256);
            R.Bytes (2 * K + 1) := Octet (Words (K) mod 256);
         end loop;
      else
         Parse_V6_Part (Text, Text'First, Double_At - 1, 0, Words, LC,
                        False, Ok);
         if not Ok then
            return R;
         end if;
         if Double_At >= Text'Last - 1 then
            TR := 0;
         else
            RC := LC;
            Parse_V6_Part (Text, Double_At + 2, Text'Last, LC, Words, RC,
                           True, Ok);
            if not Ok then
               return R;
            end if;
            TR := RC - LC;
         end if;
         if LC + TR > 7 then
            return R;
         end if;
         for K in 0 .. LC - 1 loop
            pragma Loop_Invariant (LC <= 7);
            R.Bytes (2 * K) := Octet (Words (K) / 256);
            R.Bytes (2 * K + 1) := Octet (Words (K) mod 256);
         end loop;
         Base_Idx := 16 - 2 * TR;
         for K in 0 .. TR - 1 loop
            pragma Loop_Invariant (LC + TR <= 7);
            pragma Loop_Invariant (Base_Idx = 16 - 2 * TR);
            R.Bytes (Base_Idx + 2 * K) := Octet (Words (LC + K) / 256);
            R.Bytes (Base_Idx + 2 * K + 1) :=
              Octet (Words (LC + K) mod 256);
         end loop;
      end if;
      R.Length := 16;
      return R;
   end Parse_V6;

   function Parse_Address (Text : String) return IP_Address is
      Has_Colon : Boolean := False;
      Has_Dot   : Boolean := False;
   begin
      for I in Text'Range loop
         if Text (I) = ':' then
            Has_Colon := True;
         elsif Text (I) = '.' then
            Has_Dot := True;
         end if;
      end loop;
      if Has_Colon then
         return Parse_V6 (Text);
      elsif Has_Dot then
         return Parse_V4 (Text);
      end if;
      return (Length => 0, Bytes => [others => 0]);
   end Parse_Address;

   ------------------
   --  Networks --
   ------------------

   procedure Parse_Prefix
     (Text  : String;
      Value : out Natural;
      Ok    : out Boolean)
   is
   begin
      Value := 0;
      Ok := True;
      if Text'Length = 0 or else Text'Length > 3 then
         Ok := False;
         return;
      end if;
      for I in Text'Range loop
         pragma Loop_Invariant (Value <= 129);
         if not Is_Digit (Text (I)) then
            Ok := False;
            return;
         end if;
         if Value > 12 then
            Ok := False;
            return;
         end if;
         Value := Value * 10
           + (Character'Pos (Text (I)) - Character'Pos ('0'));
      end loop;
      if Value > 128 then
         Ok := False;
      end if;
   end Parse_Prefix;

   function Parse_Network
     (Text : String; Mask_Host : Boolean := True) return IP_Network
   is
      R           : IP_Network;
      Slash_At    : Natural := 0;
      Slash_Count : Natural := 0;
      B           : IP_Address;
      Prefix      : Natural := 0;
      Pref_Ok     : Boolean;
      Full        : Natural;
      Remainder         : Natural;
   begin
      if Text'Length = 0 then
         return R;
      end if;
      for I in Text'Range loop
         if Text (I) = '/' then
            --  Explicit cap like the "::" scan: slashes cannot
            --  outnumber the characters.
            if Slash_Count >= Text'Length then
               return R;
            end if;
            Slash_Count := Slash_Count + 1;
            Slash_At := I;
         end if;
      end loop;
      if Slash_Count > 1 then
         return R;
      end if;
      if Slash_Count = 1 then
         if Slash_At = Text'First or else Slash_At = Text'Last then
            return R;
         end if;
         if Slash_At < Text'First or else Slash_At > Text'Last then
            --  Defensive: unreachable when Slash_Count = 1 (the scan
            --  assigns both together), but states the bounds the
            --  slices below need.
            return R;
         end if;
         B := Parse_Address (Text (Text'First .. Slash_At - 1));
         Parse_Prefix (Text (Slash_At + 1 .. Text'Last), Prefix, Pref_Ok);
         if not Pref_Ok then
            return R;
         end if;
      else
         B := Parse_Address (Text);
         Prefix := (if B.Length = 4 then 32 elsif B.Length = 16 then 128
                    else 0);
      end if;
      if B.Length = 4 then
         if Prefix > 32 then
            return R;
         end if;
      elsif B.Length = 16 then
         if Prefix > 128 then
            return R;
         end if;
      else
         return R;
      end if;
      Full := Prefix / 8;
      Remainder := Prefix mod 8;
      if Mask_Host then
         for I in Full .. Max_IP_Bytes - 1 loop
            B.Bytes (I) := 0;
         end loop;
         if Remainder /= 0 then
            if Full > 15 then
               return R;
            end if;
            B.Bytes (Full) :=
              (B.Bytes (Full) / Powers (8 - Remainder)) * Powers (8 - Remainder);
         end if;
      else
         if Remainder = 0 then
            for I in Full .. Max_IP_Bytes - 1 loop
               if B.Bytes (I) /= 0 then
                  return R;
               end if;
            end loop;
         else
            if Full > 15 then
               return R;
            end if;
            for I in Full + 1 .. Max_IP_Bytes - 1 loop
               if B.Bytes (I) /= 0 then
                  return R;
               end if;
            end loop;
            if B.Bytes (Full) mod Powers (8 - Remainder) /= 0 then
               return R;
            end if;
         end if;
      end if;
      R.Base := B;
      R.Prefix := Prefix;
      return R;
   end Parse_Network;

   function Contains (Net : IP_Network; Addr : IP_Address) return Boolean is
      NB   : Byte_Array := [others => 0];
      AB   : Byte_Array := [others => 0];
      P    : Natural := 0;
      Full : Natural;
      Remainder  : Natural;
   begin
      if Net.Base.Length = 0 or else Addr.Length = 0 then
         return False;
      end if;
      if Net.Base.Length = 4 then
         if Net.Prefix > 32 then
            return False;
         end if;
         NB (10) := 255;
         NB (11) := 255;
         NB (12 .. 15) := Net.Base.Bytes (0 .. 3);
         P := 96 + Net.Prefix;
      elsif Net.Base.Length = 16 then
         if Net.Prefix > 128 then
            return False;
         end if;
         NB := Net.Base.Bytes;
         P := Net.Prefix;
      else
         return False;
      end if;
      if Addr.Length = 4 then
         AB (10) := 255;
         AB (11) := 255;
         AB (12 .. 15) := Addr.Bytes (0 .. 3);
      elsif Addr.Length = 16 then
         AB := Addr.Bytes;
      else
         return False;
      end if;
      if P > 128 then
         return False;
      end if;
      Full := P / 8;
      Remainder := P mod 8;
      for I in 0 .. Full - 1 loop
         pragma Loop_Invariant (Full <= 16);
         if NB (I) /= AB (I) then
            return False;
         end if;
      end loop;
      if Remainder /= 0 then
         if Full > 15 then
            return False;
         end if;
         if NB (Full) / Powers (8 - Remainder)
           /= AB (Full) / Powers (8 - Remainder)
         then
            return False;
         end if;
      end if;
      return True;
   end Contains;

end Sigma_Verdict.IP;
