--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

package body Sigma_Verdict.Engine with SPARK_Mode is

   package IP renames Sigma_Verdict.IP;

   ------------------
   --  Constructors --
   ------------------

   function To_Field_Name (S : String) return Field_Result is
      R : Field_Result;
   begin
      if S'Length > Max_Field_Length then
         return R;
      end if;
      R.Ok := True;
      R.Value.Length := S'Length;
      for I in 1 .. S'Length loop
         pragma Loop_Invariant (R.Value.Length = S'Length);
         R.Value.Data (I) := S (S'First + (I - 1));
      end loop;
      return R;
   end To_Field_Name;

   function To_Value_Text (S : String) return Value_Result is
      R : Value_Result;
   begin
      if S'Length > Max_Value_Length then
         return R;
      end if;
      R.Ok := True;
      R.Value.Length := S'Length;
      for I in 1 .. S'Length loop
         pragma Loop_Invariant (R.Value.Length = S'Length);
         R.Value.Data (I) := S (S'First + (I - 1));
      end loop;
      return R;
   end To_Value_Text;

   function To_Event_Text (S : String) return Event_Text_Result is
      R : Event_Text_Result;
   begin
      if S'Length > Max_Event_Value_Length then
         return R;
      end if;
      R.Ok := True;
      R.Value.Length := S'Length;
      for I in 1 .. S'Length loop
         pragma Loop_Invariant (R.Value.Length = S'Length);
         R.Value.Data (I) := S (S'First + (I - 1));
      end loop;
      return R;
   end To_Event_Text;

   function To_Pattern (S : String) return Pattern_Result is
      R : Pattern_Result;
   begin
      if S'Length > Max_Pattern_Length then
         return R;
      end if;
      R.Ok := True;
      R.Value.Length := S'Length;
      for I in 1 .. S'Length loop
         pragma Loop_Invariant (R.Value.Length = S'Length);
         R.Value.Data (I) := S (S'First + (I - 1));
      end loop;
      return R;
   end To_Pattern;

   function To_View_Text (S : String) return View_Result is
      R : View_Result;
   begin
      if S'Length > Max_View_Length then
         return R;
      end if;
      R.Ok := True;
      R.Value.Length := S'Length;
      for I in 1 .. S'Length loop
         pragma Loop_Invariant (R.Value.Length = S'Length);
         R.Value.Data (I) := S (S'First + (I - 1));
      end loop;
      return R;
   end To_View_Text;

   function Image_Of (F : Field_Name) return String is
     (F.Data (1 .. F.Length));

   -----------------
   --  Modifiers --
   -----------------

   function Same_Word (A, B : String) return Boolean is
     (A'Length = B'Length
      and then (for all I in 0 .. A'Length - 1 =>
                  A (A'First + I) = B (B'First + I)));

   function Parse_Modifier (Token : String) return Modifier_Kind is
   begin
      if Same_Word (Token, "contains") then
         return Mod_Contains;
      elsif Same_Word (Token, "startswith") then
         return Mod_Startswith;
      elsif Same_Word (Token, "endswith") then
         return Mod_Endswith;
      elsif Same_Word (Token, "re") then
         return Mod_Re;
      elsif Same_Word (Token, "re+i") or else Same_Word (Token, "i") then
         return Mod_Re_I;
      elsif Same_Word (Token, "re+m") or else Same_Word (Token, "m") then
         return Mod_Re_M;
      elsif Same_Word (Token, "re+s") or else Same_Word (Token, "s") then
         return Mod_Re_S;
      elsif Same_Word (Token, "windash") then
         return Mod_Windash;
      elsif Same_Word (Token, "wide") then
         return Mod_Wide;
      --  Canonical pySigma 2.1.0 tokens only: "utf16le" is not one
      --  (LE is spelled "wide"), so it falls through to Mod_Unknown.
      elsif Same_Word (Token, "utf16be") then
         return Mod_UTF16BE;
      elsif Same_Word (Token, "utf16") then
         return Mod_UTF16;
      elsif Same_Word (Token, "base64") then
         return Mod_Base64;
      elsif Same_Word (Token, "base64offset") then
         return Mod_Base64Offset;
      elsif Same_Word (Token, "cased") then
         return Mod_Cased;
      elsif Same_Word (Token, "all") then
         return Mod_All;
      elsif Same_Word (Token, "exists") then
         return Mod_Exists;
      elsif Same_Word (Token, "fieldref") then
         return Mod_Fieldref;
      elsif Same_Word (Token, "expand") then
         return Mod_Expand;
      elsif Same_Word (Token, "gt") then
         return Mod_GT;
      elsif Same_Word (Token, "gte") then
         return Mod_GTE;
      elsif Same_Word (Token, "lt") then
         return Mod_LT;
      elsif Same_Word (Token, "lte") then
         return Mod_LTE;
      elsif Same_Word (Token, "cidr") then
         return Mod_CIDR;
      else
         return Mod_Unknown;
      end if;
   end Parse_Modifier;

   procedure Add_Modifier
     (Set : in out Modifier_Set; M : in Modifier_Kind; Ok : out Boolean)
   is
   begin
      if Set.Count >= Max_Modifiers_Per_Field then
         Ok := False;
         return;
      end if;
      Set.Count := Set.Count + 1;
      Set.Items (Set.Count) := M;
      Ok := True;
   end Add_Modifier;

   function Has_Modifier
     (Set : Modifier_Set; M : Modifier_Kind) return Boolean
   is
   begin
      for I in 1 .. Set.Count loop
         pragma Loop_Invariant (Set.Count <= Max_Modifiers_Per_Field);
         if Set.Items (I) = M then
            return True;
         end if;
      end loop;
      return False;
   end Has_Modifier;

   function Has_View_Modifier
     (Set : Modifier_Set) return Boolean
   is
   begin
      for I in 1 .. Set.Count loop
         pragma Loop_Invariant (Set.Count <= Max_Modifiers_Per_Field);
         if Set.Items (I) in Mod_Windash | Mod_Wide | Mod_UTF16LE
           | Mod_UTF16BE | Mod_UTF16 | Mod_Base64 | Mod_Base64Offset
         then
            return True;
         end if;
      end loop;
      return False;
   end Has_View_Modifier;

   function View_Token (Set : Modifier_Set) return Modifier_Kind is
   begin
      for I in 1 .. Set.Count loop
         pragma Loop_Invariant (Set.Count <= Max_Modifiers_Per_Field);
         if Set.Items (I) in Mod_Windash | Mod_Wide | Mod_UTF16LE
           | Mod_UTF16BE | Mod_UTF16 | Mod_Base64 | Mod_Base64Offset
         then
            return Set.Items (I);
         end if;
      end loop;
      return Mod_None;
   end View_Token;

   function Comparison_Of (Set : Modifier_Set) return Modifier_Kind is
   begin
      for I in 1 .. Set.Count loop
         pragma Loop_Invariant (Set.Count <= Max_Modifiers_Per_Field);
         if Set.Items (I) in Mod_GT | Mod_GTE | Mod_LT | Mod_LTE then
            return Set.Items (I);
         end if;
      end loop;
      return Mod_None;
   end Comparison_Of;

    function Has_Re_Modifier
      (Set : Modifier_Set) return Boolean
    is
    begin
       for I in 1 .. Set.Count loop
          pragma Loop_Invariant (Set.Count <= Max_Modifiers_Per_Field);
          if Set.Items (I) in Mod_Re | Mod_Re_I | Mod_Re_M | Mod_Re_S then
             return True;
          end if;
       end loop;
       return False;
    end Has_Re_Modifier;

    function Has_Pattern_Modifier
      (Set : Modifier_Set) return Boolean
    is
    begin
       for I in 1 .. Set.Count loop
          pragma Loop_Invariant (Set.Count <= Max_Modifiers_Per_Field);
          if Set.Items (I) in Mod_Re | Mod_Re_I | Mod_Re_M | Mod_Re_S
            | Mod_Wildcard
          then
             return True;
          end if;
       end loop;
       return False;
    end Has_Pattern_Modifier;

    function Chain_Supported (Set : Modifier_Set) return Boolean is
       Seen_Matcher : Boolean := False;
       Seen_View    : Boolean := False;
       Seen_Cmp     : Boolean := False;
       Seen_CIDR    : Boolean := False;
       Seen_Re      : Boolean := False;
       Seen_Re_I    : Boolean := False;
       Seen_Re_M    : Boolean := False;
       Seen_Re_S    : Boolean := False;
       Seen_Wild    : Boolean := False;
       Seen_Cased   : Boolean := False;
    begin
       for I in 1 .. Set.Count loop
          pragma Loop_Invariant (Set.Count <= Max_Modifiers_Per_Field);
          if Is_Supported_Modifier (Set.Items (I)) then
             --  At most one anchor matcher per chain; several would
             --  silently shadow each other, so the chain fails closed.
             --  One anchor composes with one pattern source (P3a).
             if Seen_Matcher or Seen_Cmp or Seen_CIDR then
                return False;
             end if;
             Seen_Matcher := True;
          elsif Set.Items (I) in Mod_GT | Mod_GTE | Mod_LT | Mod_LTE then
             if Seen_Matcher or Seen_Cmp or Seen_CIDR
               or Seen_Re or Seen_Re_I or Seen_Re_M or Seen_Re_S
               or Seen_Wild
             then
                return False;
             end if;
             Seen_Cmp := True;
          elsif Set.Items (I) = Mod_CIDR then
             if Seen_Matcher or Seen_Cmp or Seen_CIDR
               or Seen_Re or Seen_Re_I or Seen_Re_M or Seen_Re_S
               or Seen_Wild
             then
                return False;
             end if;
             Seen_CIDR := True;
          elsif Set.Items (I) = Mod_Re then
             if Seen_Re or Seen_Wild or Seen_View
               or Seen_Cmp or Seen_CIDR
             then
                return False;
             end if;
             Seen_Re := True;
          elsif Set.Items (I) = Mod_Re_I then
             if Seen_Re_I or Seen_Wild or Seen_View
               or Seen_Cmp or Seen_CIDR
             then
                return False;
             end if;
             Seen_Re_I := True;
          elsif Set.Items (I) = Mod_Re_M then
             if Seen_Re_M or Seen_Wild or Seen_View
               or Seen_Cmp or Seen_CIDR
             then
                return False;
             end if;
             Seen_Re_M := True;
          elsif Set.Items (I) = Mod_Re_S then
             if Seen_Re_S or Seen_Wild or Seen_View
               or Seen_Cmp or Seen_CIDR
             then
                return False;
             end if;
             Seen_Re_S := True;
          elsif Set.Items (I) = Mod_Wildcard then
             if Seen_Wild or Seen_Re or Seen_Re_I or Seen_Re_M
               or Seen_Re_S or Seen_View or Seen_Cmp or Seen_CIDR
             then
                return False;
             end if;
             Seen_Wild := True;
          elsif Set.Items (I) in Mod_Windash | Mod_Wide | Mod_UTF16LE
            | Mod_UTF16BE | Mod_UTF16 | Mod_Base64 | Mod_Base64Offset
          then
             --  At most one view derivation per chain; mixing views
             --  would stack encodings the core does not model. Views
             --  never ride with comparisons, CIDR, or patterns.
             if Seen_View or Seen_Cmp or Seen_CIDR
               or Seen_Re or Seen_Re_I or Seen_Re_M or Seen_Re_S
               or Seen_Wild
             then
                return False;
             end if;
             Seen_View := True;
          elsif Set.Items (I) = Mod_Cased then
             Seen_Cased := True;
             if Seen_Cmp or Seen_CIDR then
                --  Comparisons and CIDR admit only `all`: cased is
                --  string-only. (Checked here because cased now has
                --  its own branch; order after cmp/cidr still refuses
                --  exactly as before.)
                return False;
             end if;
          elsif Set.Items (I) not in Mod_All | Mod_Exists then
             return False;
          elsif (Seen_Cmp or Seen_CIDR)
            and then Set.Items (I) /= Mod_All
          then
             --  Comparisons and CIDR admit only `all`: cased is
             --  string-only, exists stands alone.
             return False;
          end if;
       end loop;
       if Seen_Cased and then Seen_Re_I then
          --  `cased` (case-sensitive) contradicts `re|i`
          --  (case-insensitive): refuse rather than guess which wins.
          return False;
       end if;
       return True;
    end Chain_Supported;

   ----------------
   --  Matching --
   ----------------

   function Fold (C : Character; Sensitive : Boolean) return Character is
     (if (not Sensitive) and then C in 'A' .. 'Z'
      then Character'Val (Character'Pos (C) + 32)
      else C);

   function Equal_Folded
     (A, B : String; Sensitive : Boolean) return Boolean
   is
     (A'Length = B'Length
      and then (for all I in 0 .. A'Length - 1 =>
                  Fold (A (A'First + I), Sensitive) =
                    Fold (B (B'First + I), Sensitive)));

   function Same_Bytes (A, B : String) return Boolean is
     (A'Length = B'Length
      and then (for all I in 0 .. A'Length - 1 =>
                  A (A'First + I) = B (B'First + I)));

   function Field_Equal (A, B : Field_Name) return Boolean is
     (A.Length = B.Length
      and then Same_Bytes (A.Data (1 .. A.Length), B.Data (1 .. B.Length)));

   function Contains_At
     (Haystack, Needle : String; Sensitive : Boolean) return Boolean
   is
      Match : Boolean;
   begin
      if Needle'Length = 0 then
         return True;
      end if;
      if Needle'Length > Haystack'Length then
         return False;
      end if;
      for Start in 0 .. Haystack'Length - Needle'Length loop
         Match := True;
         for K in 0 .. Needle'Length - 1 loop
            pragma Loop_Invariant (Start <= Haystack'Length - Needle'Length);
            pragma Loop_Invariant (K <= Needle'Length - 1);
            if Fold (Haystack (Haystack'First + Start + K), Sensitive) /=
              Fold (Needle (Needle'First + K), Sensitive)
            then
               Match := False;
               exit;
            end if;
         end loop;
         if Match then
            return True;
         end if;
         pragma Loop_Invariant (Needle'Length <= Haystack'Length);
      end loop;
      return False;
   end Contains_At;

   function Starts_With_At
     (Haystack, Needle : String; Sensitive : Boolean) return Boolean
   is
   begin
      if Needle'Length = 0 then
         return True;
      end if;
      if Needle'Length > Haystack'Length then
         return False;
      end if;
      for K in 0 .. Needle'Length - 1 loop
         pragma Loop_Invariant (Needle'Length <= Haystack'Length);
         if Fold (Haystack (Haystack'First + K), Sensitive) /=
           Fold (Needle (Needle'First + K), Sensitive)
         then
            return False;
         end if;
      end loop;
      return True;
   end Starts_With_At;

   function Ends_With_At
     (Haystack, Needle : String; Sensitive : Boolean) return Boolean
   is
   begin
      if Needle'Length = 0 then
         return True;
      end if;
      if Needle'Length > Haystack'Length then
         return False;
      end if;
      --  Offset is elaborated only after the guards above, so the
      --  subtraction cannot underflow (fail-closed, no exception).
      declare
         Offset : constant Natural := Haystack'Length - Needle'Length;
      begin
         for K in 0 .. Needle'Length - 1 loop
            pragma Loop_Invariant (Offset = Haystack'Length - Needle'Length);
            pragma Loop_Invariant (Offset + K <= Haystack'Length);
            if Fold (Haystack (Haystack'First + Offset + K), Sensitive) /=
              Fold (Needle (Needle'First + K), Sensitive)
            then
               return False;
            end if;
         end loop;
         return True;
      end;
   end Ends_With_At;

   --  windash (P1b): a placeholder in the needle matches one of the
   --  pySigma 5-way class — ASCII '-'/'/' or the UTF-8 bytes of
   --  U+2013/U+2014/U+2015. Placeholder positions are 1-based over the
   --  needle and arrive from the boundary, which mirrors the pySigma
   --  rule (a '-'/'/' whose next character is a word character and
   --  which is first or follows a non-word character).
   function Is_Dash_At
     (Dashes : Dash_Pos_Array; N : Dash_Count; Pos : Positive) return Boolean
   is
   begin
      for I in 1 .. N loop
         pragma Loop_Invariant (N <= Max_Dash_Places);
         if Dashes (I) = Pos then
            return True;
         end if;
      end loop;
      return False;
   end Is_Dash_At;

   --  Tries to consume all of N starting at H (Start 0-based).
   --  Matched reports whether the whole needle was consumed; Stop
   --  holds the consumed haystack byte count either way.
   type Consume_Result is record
      Matched : Boolean := False;
      Stop    : Natural := 0;
   end record;

   procedure Windash_Consume
     (H : String; Start : Natural; N : String; Sensitive : Boolean;
      Dashes : Dash_Pos_Array; Dash_N : Dash_Count;
      Result : out Consume_Result)
   is
      HC     : Natural := Start;
      NP_Off : Natural := 0;
   begin
      while NP_Off < N'Length loop
         pragma Loop_Invariant (HC <= H'Length);
         pragma Loop_Invariant (NP_Off <= N'Length);
         pragma Loop_Variant (Increases => NP_Off);
         --  NP_Off is a 0-based offset so every bound is static: the
         --  live index N'First + NP_Off stays inside N'First ..
         --  N'Last exactly like the proven linear matchers.
         --  NP_Off advances only below N'Length - 1, HC by 1 only
         --  below H'Length, and HC by 3 only below H'Length - 3
         --  (H'Length >= 3 checked first, so no underflow).
         if Is_Dash_At (Dashes, Dash_N, NP_Off + 1) then
            if HC < H'Length
              and then (H (H'First + HC) = '-'
                        or else H (H'First + HC) = '/')
            then
               HC := HC + 1;
            elsif H'Length >= 3
              and then HC <= H'Length - 3
              and then H (H'First + HC) = Character'Val (16#E2#)
              and then H (H'First + HC + 1) = Character'Val (16#80#)
              and then H (H'First + HC + 2) in Character'Val (16#93#)
                | Character'Val (16#94#) | Character'Val (16#95#)
            then
               HC := HC + 3;
            else
               Result := (Matched => False, Stop => HC);
               return;
            end if;
         else
            if HC < H'Length
              and then Fold (H (H'First + HC), Sensitive)
                       = Fold (N (N'First + NP_Off), Sensitive)
            then
               HC := HC + 1;
            else
               Result := (Matched => False, Stop => HC);
               return;
            end if;
         end if;
         exit when NP_Off = N'Length - 1;
         NP_Off := NP_Off + 1;
      end loop;
      Result := (Matched => True, Stop => HC);
   end Windash_Consume;

   function Windash_Contains_At
     (Haystack, Needle : String; Sensitive : Boolean;
      Dashes : Dash_Pos_Array; Dash_N : Dash_Count) return Boolean
   is
      R : Consume_Result;
   begin
      if Needle'Length = 0 then
         return True;
      end if;
      for S in 0 .. Haystack'Length loop
         Windash_Consume
           (Haystack, S, Needle, Sensitive, Dashes, Dash_N, R);
         if R.Matched then
            return True;
         end if;
      end loop;
      return False;
   end Windash_Contains_At;

   function Windash_Starts_With_At
     (Haystack, Needle : String; Sensitive : Boolean;
      Dashes : Dash_Pos_Array; Dash_N : Dash_Count) return Boolean
   is
      R : Consume_Result;
   begin
      Windash_Consume (Haystack, 0, Needle, Sensitive, Dashes, Dash_N, R);
      return R.Matched;
   end Windash_Starts_With_At;

   function Windash_Ends_With_At
     (Haystack, Needle : String; Sensitive : Boolean;
      Dashes : Dash_Pos_Array; Dash_N : Dash_Count) return Boolean
   is
      R : Consume_Result;
   begin
      if Needle'Length = 0 then
         return True;
      end if;
      for S in 0 .. Haystack'Length loop
         Windash_Consume
           (Haystack, S, Needle, Sensitive, Dashes, Dash_N, R);
         if R.Matched and then R.Stop = Haystack'Length then
            return True;
         end if;
      end loop;
      return False;
   end Windash_Ends_With_At;

   function Windash_Equal
     (Haystack, Needle : String; Sensitive : Boolean;
      Dashes : Dash_Pos_Array; Dash_N : Dash_Count) return Boolean
   is
      R : Consume_Result;
   begin
      Windash_Consume (Haystack, 0, Needle, Sensitive, Dashes, Dash_N, R);
      return R.Matched and then R.Stop = Haystack'Length;
   end Windash_Equal;

   function Has_Prefix (Name, Prefix : Field_Name) return Boolean is
   begin
      if Prefix.Length = 0 then
         return True;
      end if;
      if Prefix.Length > Name.Length then
         return False;
      end if;
      return Same_Bytes
        (Name.Data (1 .. Prefix.Length), Prefix.Data (1 .. Prefix.Length));
   end Has_Prefix;

   function Find_Field
     (Event : Event_Record; Name : Field_Name) return Natural
   is
   begin
      for I in 1 .. Event.Count loop
         pragma Loop_Invariant (Event.Count <= Max_Event_Fields);
         if Field_Equal (Event.Fields (I).Name, Name) then
            return I;
         end if;
      end loop;
      return 0;
   end Find_Field;

   --  Match one expected text against one haystack under the chain's
   --  single matcher. Chain_Supported guarantees at most one matching
   --  semantic reaches here (empty means exact equality); `cased`
   --  selects case-sensitive comparison, otherwise folding applies.
   --  With Mod_Windash the stride-aware variants run instead, using
   --  the boundary-derived placeholder positions (1-based over
   --  Needle); without the flag the dash table is ignored.
   function Text_Matches
     (Haystack : String; Needle : String; Set : Modifier_Set;
      Dashes : Dash_Pos_Array; Dash_N : Dash_Count) return Boolean
   is
      Kind      : Modifier_Kind := Mod_None;
      Sensitive : constant Boolean := Has_Modifier (Set, Mod_Cased);
   begin
      for I in 1 .. Set.Count loop
         pragma Loop_Invariant (Set.Count <= Max_Modifiers_Per_Field);
         if Set.Items (I) in Mod_Contains | Mod_Startswith | Mod_Endswith then
            Kind := Set.Items (I);
         end if;
      end loop;
      if Has_Modifier (Set, Mod_Windash) then
         case Kind is
            when Mod_Contains =>
               return Windash_Contains_At
                 (Haystack, Needle, Sensitive, Dashes, Dash_N);
            when Mod_Startswith =>
               return Windash_Starts_With_At
                 (Haystack, Needle, Sensitive, Dashes, Dash_N);
            when Mod_Endswith =>
               return Windash_Ends_With_At
                 (Haystack, Needle, Sensitive, Dashes, Dash_N);
            when others =>
               return Windash_Equal
                 (Haystack, Needle, Sensitive, Dashes, Dash_N);
         end case;
      end if;
      case Kind is
         when Mod_Contains =>
            return Contains_At (Haystack, Needle, Sensitive);
         when Mod_Startswith =>
            return Starts_With_At (Haystack, Needle, Sensitive);
         when Mod_Endswith =>
            return Ends_With_At (Haystack, Needle, Sensitive);
         when others =>
            return Equal_Folded (Haystack, Needle, Sensitive);
      end case;
   end Text_Matches;

   Empty_View : constant Single_View :=
     (Has_Alt => False,
      Alt     => (Length => 0, Data => [others => ' ']),
      Dash_N  => 0,
      Dash_At => [others => 0]);

   --  One item's view is consistent when alternatives and dashes do
   --  not mix, dashes carry the windash flag, and every derived
   --  byte rides with a matching view token in the chain.
   function Single_Consistent
     (V : Single_View; Set : Modifier_Set) return Boolean
   is
   begin
      if V.Has_Alt and then V.Dash_N > 0 then
         return False;
      end if;
      if V.Dash_N > 0 and then not Has_Modifier (Set, Mod_Windash) then
         return False;
      end if;
      if V.Has_Alt and then not Has_View_Modifier (Set) then
         return False;
      end if;
      if not V.Has_Alt and then V.Dash_N = 0
        and then Has_View_Modifier (Set)
        and then View_Token (Set) /= Mod_Windash
      then
         --  A non-windash view token that derived nothing: hand-built
         --  garbage (the boundary always derives for those views).
         return False;
      end if;
      return True;
   end Single_Consistent;

   --  Boundary/loader invariant for one constraint: views parallel
   --  the text values exactly, base64offset rides alone on a single
   --  value, integers and CIDR networks never carry views, and
   --  anything else bypassed the loader and fails closed.
   function Views_Consistent (C : Field_Constraint) return Boolean is
   begin
      case C.Expected.Kind is
         when E_Int | E_Int_List | E_CIDR | E_CIDR_List =>
            return C.Views.Count = 0
              and then not C.Views.Has_Offset
              and then not Has_View_Modifier (C.Modifiers);
          when E_Pattern | E_Pattern_List =>
             --  Patterns carry their program in Expected, never views:
             --  the chain gate already refuses pattern/view mixes, so
             --  anything else bypassed the loader and fails closed.
             return C.Views.Count = 0
               and then not C.Views.Has_Offset
               and then not Has_View_Modifier (C.Modifiers);
         when E_Text =>
            if C.Views.Has_Offset then
               return C.Views.Count = 1
                 and then View_Token (C.Modifiers) = Mod_Base64Offset
                 and then not C.Views.Items (1).Has_Alt
                 and then C.Views.Items (1).Dash_N = 0;
            end if;
            if C.Views.Count > 1 then
               return False;
            end if;
            if C.Views.Count = 1 then
               return Single_Consistent (C.Views.Items (1), C.Modifiers);
            end if;
            return True;
         when E_Text_List =>
            if C.Views.Has_Offset then
               --  base64offset needs one value; lists carrying it
               --  are rejected at load, so this bypassed the loader.
               return False;
            end if;
            if C.Views.Count /= 0
              and then C.Views.Count /= C.Expected.Count
            then
               return False;
            end if;
            for I in 1 .. C.Views.Count loop
               pragma Loop_Invariant
                 (C.Views.Count <= Max_Values_Per_Sel);
               if not Single_Consistent
                 (C.Views.Items (I), C.Modifiers)
               then
                  return False;
               end if;
            end loop;
            return True;
      end case;
   end Views_Consistent;

   --  One expected value (raw needle plus its derived view) against
   --  one haystack. Alternatives are OR-linked (pySigma
   --  SigmaExpansion semantics, which stay OR even under `all`).
   function Value_Matches
     (Haystack : String; Raw : String; C : Field_Constraint;
      Idx : Positive) return Boolean
   with Pre => Idx in 1 .. Max_Values_Per_Sel
   is
   begin
      if C.Views.Has_Offset then
         for A in 1 .. Max_View_Alternatives loop
            if Text_Matches
              (Haystack,
               C.Views.Offset (A).Data (1 .. C.Views.Offset (A).Length),
               C.Modifiers, Empty_View.Dash_At, 0)
            then
               return True;
            end if;
         end loop;
         return False;
      end if;
      declare
         V : Single_View renames C.Views.Items (Idx);
      begin
         if V.Has_Alt then
            return Text_Matches
              (Haystack, V.Alt.Data (1 .. V.Alt.Length), C.Modifiers,
               Empty_View.Dash_At, 0);
         end if;
         return Text_Matches
           (Haystack, Raw, C.Modifiers, V.Dash_At, V.Dash_N);
      end;
   end Value_Matches;

   --  Numeric comparison for one expected integer. Mod_None keeps
   --  plain equality; anything except the four operators (which the
   --  chain gate guarantees) also keeps equality. Type mismatch is
   --  the caller's clean non-match, never an error.
   function Compare_Ints
     (Op : Modifier_Kind; Event_Int, Expected_Int : Integer) return Boolean
   is
   begin
      case Op is
         when Mod_GT =>
            return Event_Int > Expected_Int;
         when Mod_GTE =>
            return Event_Int >= Expected_Int;
         when Mod_LT =>
            return Event_Int < Expected_Int;
         when Mod_LTE =>
            return Event_Int <= Expected_Int;
         when others =>
            return Event_Int = Expected_Int;
      end case;
   end Compare_Ints;

   --  A stored network is valid when its length matches a version
   --  and the prefix fits. The loader guarantees this; anything
   --  else bypassed the loader and fails closed.
   function Valid_CIDR_Net (Net : IP.IP_Network) return Boolean
   is
     ((Net.Base.Length = 4 and then Net.Prefix <= 32)
      or else (Net.Base.Length = 16 and then Net.Prefix <= 128));

   --  P3a Thompson NFA Pike VM. Executes loader-built bytecode
   --  with a single left-to-right pass: every position closes the
   --  epsilon fan (explicit stack, visited-capped so the static
   --  inner bound always suffices) and then steps one character.
   --  All loops are static `for` ranges, so termination needs no
   --  fuel argument; the unreachable fallbacks (full stack,
   --  unclosable remainder) answer PV_Invalid loudly instead of
   --  mis-indexing. Invalid edges in hand-built programs are
   --  skipped, which can only remove paths and never create a
   --  match (fail-closed direction).
   type Pattern_Verdict is (PV_Match, PV_No_Match, PV_Invalid);

   function Case_Twin (C : Character) return Character is
     (if C in 'a' .. 'z' then Character'Val (Character'Pos (C) - 32)
      elsif C in 'A' .. 'Z' then Character'Val (Character'Pos (C) + 32)
      else C);
   --  ASCII case twin for folded class matching: 'b' matches [A-Z]
   --  because its twin 'B' is in range, and vice versa. Non-letters
   --  are their own twin, so exactness is preserved there.

   function Run_Pattern
     (Prog : NFA_Program; Text : String) return Pattern_Verdict
   with Pre => Valid_Program (Prog)
   is
      Len   : constant Natural := Text'Length;
      LL    : constant Long_Long_Integer :=
        Long_Long_Integer (Prog.Length) + 1;
      Inner : constant Natural :=
        (if LL > Long_Long_Integer (Natural'Last)
         then Natural'Last
         else Natural (LL));
      --  Epsilon-closure bound per text position: every push marks
      --  a distinct visited code position, so pops never exceed
      --  Length. Saturated only for absurd capacities; the loader
      --  refuses programs that cannot fit anyway.

      Visited : array (1 .. Max_Pattern_Code) of Boolean :=
        [others => False];
      In_Cur  : array (1 .. Max_Pattern_Code) of Boolean :=
        [others => False];
      In_Next : array (1 .. Max_Pattern_Code) of Boolean :=
        [others => False];
      Stack   : array (1 .. Max_Pattern_Code) of Natural :=
        [others => 0];
      Top        : Natural := 0;
      Match_Flag : Boolean := False;

      procedure Push (PC : Natural; Full : out Boolean)
      with Global => (In_Out => (Top, Stack, Visited), Input => Prog),
           Pre    => Top <= Stack'Last,
           Post   => (if not Full then Top <= Stack'Last)
       is
      begin
         Full := False;
         if PC in 1 .. Prog.Length and then not Visited (PC) then
            if Top >= Stack'Last then
               --  Unreachable: pushes are visited-capped to Length.
               Full := True;
               return;
            end if;
            Visited (PC) := True;
            Top := Top + 1;
            Stack (Top) := PC;
         end if;
      end Push;

      --  Big-endian 16-bit jump target at Loc/Loc+1 (fits Integer:
      --  at most 65535).
      function Fetched (Loc : Natural) return Natural is
        (Character'Pos (Prog.Code (Loc)) * 256
         + Character'Pos (Prog.Code (Loc + 1)))
      with Pre => Loc >= 1
        and then Long_Long_Integer (Loc) + 1
          <= Long_Long_Integer (Prog.Length);
   begin
      for P in 0 .. Len loop
         for K in 1 .. Prog.Length loop
            Visited (K) := False;
            In_Cur (K) := False;
         end loop;
         Top := 0;
         Match_Flag := False;
          --  Seed with states carried from the previous character.
          for S in 1 .. Prog.Length loop
             pragma Loop_Invariant (Top <= Stack'Last);
             if In_Next (S) then
               In_Next (S) := False;
               declare
                  Full : Boolean;
               begin
                  Push (S, Full);
                  if Full then
                     return PV_Invalid;
                  end if;
               end;
            end if;
         end loop;
         --  Seed the entry for the first position always, and for
         --  every position when the pattern is not start-anchored.
         if P = 0 or else not Prog.Anchor_Start then
            declare
               Full : Boolean;
            begin
               Push (1, Full);
               if Full then
                  return PV_Invalid;
               end if;
            end;
         end if;
          --  Epsilon closure.
          for Step in 1 .. Inner loop
             pragma Loop_Invariant (Top <= Stack'Last);
             exit when Top = 0;
            declare
               PC   : constant Natural := Stack (Top);
               PCLL : constant Long_Long_Integer :=
                 Long_Long_Integer (PC);
               --  Out-of-range slots decode as OC_Dead and match no
               --  branch below: removing edges cannot create a match.
               Op   : constant Character :=
                 (if PC in 1 .. Prog.Length then Prog.Code (PC)
                  else OC_Dead);
            begin
               Top := Top - 1;
               if Op = OC_Match then
                  Match_Flag := True;
               elsif Op = OC_Split then
                  if PCLL + 4 <= Long_Long_Integer (Prog.Length) then
                     declare
                        Full : Boolean;
                     begin
                        Push (Fetched (PC + 1), Full);
                        if Full then
                           return PV_Invalid;
                        end if;
                        Push (Fetched (PC + 3), Full);
                        if Full then
                           return PV_Invalid;
                        end if;
                     end;
                  end if;
               elsif Op = OC_Jmp then
                  if PCLL + 2 <= Long_Long_Integer (Prog.Length) then
                     declare
                        Full : Boolean;
                     begin
                        Push (Fetched (PC + 1), Full);
                        if Full then
                           return PV_Invalid;
                        end if;
                     end;
                  end if;
               elsif Op = OC_Begin then
                  if (P = 0
                      or else (Prog.Multi_Line and then P >= 1
                        and then Text (Text'First + (P - 1)) = ASCII.LF))
                    and then PCLL + 1
                      <= Long_Long_Integer (Prog.Length)
                  then
                     declare
                        Full : Boolean;
                     begin
                        Push (PC + 1, Full);
                        if Full then
                           return PV_Invalid;
                        end if;
                     end;
                  end if;
               elsif Op = OC_End then
                  if (P = Len
                      or else ((not Prog.Multi_Line)
                        and then Long_Long_Integer (P) + 1
                          = Long_Long_Integer (Len)
                        and then Len >= 1
                        and then Text (Text'First + (Len - 1)) = ASCII.LF)
                      or else (Prog.Multi_Line and then P < Len
                        and then Text (Text'First + P) = ASCII.LF))
                    and then PCLL + 1
                      <= Long_Long_Integer (Prog.Length)
                  then
                     declare
                        Full : Boolean;
                     begin
                        Push (PC + 1, Full);
                        if Full then
                           return PV_Invalid;
                        end if;
                     end;
                  end if;
               elsif Op = OC_Lit or else Op = OC_Any
                 or else Op = OC_Any_NL or else Op = OC_Cls
                 or else Op = OC_NCls
               then
                  --  Consuming state: active for the character step.
                  --  Truncated operands (hand-built) skip it, which
                  --  only removes paths.
                  if Op = OC_Any or else Op = OC_Any_NL then
                     In_Cur (PC) := True;
                  elsif Op = OC_Lit then
                     if PCLL + 1 <= Long_Long_Integer (Prog.Length) then
                        In_Cur (PC) := True;
                     end if;
                  elsif PCLL + 3 <= Long_Long_Integer (Prog.Length) then
                     In_Cur (PC) := True;
                  end if;
               end if;
               --  Unknown opcodes (hand-built) are ignored: removing
               --  edges cannot create a match.
            end;
         end loop;
         if Top /= 0 then
            --  Unreachable: pushes are visited-capped, so the static
            --  bound always drains the stack.
            return PV_Invalid;
         end if;
         if (not Prog.Anchor_End) and then Match_Flag then
            return PV_Match;
         end if;
         exit when P = Len;
         --  Character step on the next event character.
         declare
            C : constant Character := Text (Text'First + P);
         begin
            for S in 1 .. Prog.Length loop
               if In_Cur (S) then
                  declare
                     Op  : constant Character := Prog.Code (S);
                     SLL : constant Long_Long_Integer :=
                       Long_Long_Integer (S);
                     PLL : constant Long_Long_Integer :=
                       Long_Long_Integer (Prog.Length);
                  begin
                     if Op = OC_Any then
                        if C /= ASCII.LF and then SLL + 1 <= PLL then
                           In_Next (Natural (SLL + 1)) := True;
                        end if;
                     elsif Op = OC_Any_NL then
                        if SLL + 1 <= PLL then
                           In_Next (Natural (SLL + 1)) := True;
                        end if;
                     elsif Op = OC_Lit then
                        if SLL + 1 <= PLL
                          and then Fold (C, not Prog.Fold)
                            = Prog.Code (Natural (SLL + 1))
                        then
                           if SLL + 2 <= PLL then
                              In_Next (Natural (SLL + 2)) := True;
                           end if;
                        end if;
                     elsif Op = OC_Cls or else Op = OC_NCls then
                        if SLL + 3 <= PLL then
                           declare
                              Lo : constant Character :=
                                Prog.Code (Natural (SLL + 1));
                              Hi : constant Character :=
                                Prog.Code (Natural (SLL + 2));
                              Twin : constant Character := Case_Twin (C);
                              In_Range : constant Boolean :=
                                (Lo <= C and then C <= Hi)
                                or else (Prog.Fold
                                  and then Lo <= Twin and then Twin <= Hi);
                           begin
                              if (Op = OC_Cls) = In_Range then
                                 In_Next (Natural (SLL + 3)) := True;
                              end if;
                           end;
                        end if;
                     end if;
                     --  Stale In_Cur entries for epsilon states cannot
                     --  occur: only consuming states are ever flagged.
                  end;
               end if;
            end loop;
         end;
      end loop;
      if Prog.Anchor_End and then Match_Flag then
         return PV_Match;
      end if;
      return PV_No_Match;
   end Run_Pattern;

   function Match_Field
     (C : Field_Constraint; Event : Event_Record) return Eval_Result
   is
      Slot : constant Natural := Find_Field (Event, C.Field);
   begin
      --  Presence check. The boundary only ever loads sole-modifier
      --  boolean values here; anything else fails closed as defence
      --  in depth (hand-built rules bypass the loader).
      if Has_Modifier (C.Modifiers, Mod_Exists) then
         if C.Modifiers.Count /= 1 then
            return (Matched => False, Error => Error_Unsupported_Modifier);
         end if;
         case C.Expected.Kind is
            when E_Int =>
               return (Matched => (Slot /= 0) = (C.Expected.Int_Value /= 0),
                       Error   => Error_None);
            when E_Text =>
               declare
                  T : constant String :=
                    C.Expected.Single.Data (1 .. C.Expected.Single.Length);
               begin
                  if Equal_Folded (T, "true", False) then
                     return (Matched => Slot /= 0, Error => Error_None);
                  elsif Equal_Folded (T, "false", False) then
                     return (Matched => Slot = 0, Error => Error_None);
                  else
                     return (Matched => False,
                             Error   => Error_Unsupported_Modifier);
                  end if;
               end;
             when E_Int_List | E_Text_List | E_CIDR | E_CIDR_List
               | E_Pattern | E_Pattern_List =>
                return (Matched => False,
                        Error   => Error_Unsupported_Modifier);
         end case;
      end if;
      if not Chain_Supported (C.Modifiers) then
         return (Matched => False, Error => Error_Unsupported_Modifier);
      end if;
      if not Views_Consistent (C) then
         --  Views must parallel the text values exactly (loader
         --  invariant); anything else bypassed the loader.
         return (Matched => False, Error => Error_Unsupported_Modifier);
      end if;
       if Slot = 0 then
         --  Absent field: no match, no error (standard Sigma semantics).
         return (Matched => False, Error => Error_None);
      end if;
      declare
         EV : constant Event_Value := Event.Fields (Slot).Value;
         Op : constant Modifier_Kind := Comparison_Of (C.Modifiers);
      begin
         case C.Expected.Kind is
            when E_Int =>
               if EV.Kind /= V_Int then
                  return (Matched => False, Error => Error_None);
               end if;
               if Compare_Ints (Op, EV.Int_Value, C.Expected.Int_Value) then
                  return (Matched => True, Error => Error_None);
               end if;
               return (Matched => False, Error => Error_None);
            when E_Int_List =>
               if EV.Kind /= V_Int then
                  return (Matched => False, Error => Error_None);
               end if;
               if C.Expected.Int_Count = 0 then
                  --  An empty list matches nothing either way.
                  return (Matched => False, Error => Error_None);
               end if;
               if Has_Modifier (C.Modifiers, Mod_All) then
                  for I in 1 .. C.Expected.Int_Count loop
                     pragma Loop_Invariant
                       (C.Expected.Int_Count <= Max_Values_Per_Sel);
                     if not Compare_Ints
                       (Op, EV.Int_Value, C.Expected.Ints (I))
                     then
                        return (Matched => False, Error => Error_None);
                     end if;
                  end loop;
                  return (Matched => True, Error => Error_None);
               end if;
               for I in 1 .. C.Expected.Int_Count loop
                  pragma Loop_Invariant
                    (C.Expected.Int_Count <= Max_Values_Per_Sel);
                  if Compare_Ints (Op, EV.Int_Value, C.Expected.Ints (I))
                  then
                     return (Matched => True, Error => Error_None);
                  end if;
               end loop;
               return (Matched => False, Error => Error_None);
            when E_Text =>
               if EV.Kind /= V_Text then
                  return (Matched => False, Error => Error_None);
               end if;
               if Value_Matches
                 (EV.Text_Value.Data (1 .. EV.Text_Value.Length),
                  C.Expected.Single.Data (1 .. C.Expected.Single.Length),
                  C, 1)
               then
                  return (Matched => True, Error => Error_None);
               end if;
               return (Matched => False, Error => Error_None);
            when E_Text_List =>
               if EV.Kind /= V_Text then
                  return (Matched => False, Error => Error_None);
               end if;
               if C.Expected.Count = 0 then
                  --  An empty list matches nothing either way.
                  return (Matched => False, Error => Error_None);
               end if;
               if Has_Modifier (C.Modifiers, Mod_All) then
                  for I in 1 .. C.Expected.Count loop
                     pragma Loop_Invariant
                       (C.Expected.Count <= Max_Values_Per_Sel);
                     if not Value_Matches
                       (EV.Text_Value.Data (1 .. EV.Text_Value.Length),
                        C.Expected.Items (I).Data
                          (1 .. C.Expected.Items (I).Length),
                        C, I)
                     then
                        return (Matched => False, Error => Error_None);
                     end if;
                  end loop;
                  return (Matched => True, Error => Error_None);
               end if;
               for I in 1 .. C.Expected.Count loop
                  pragma Loop_Invariant
                    (C.Expected.Count <= Max_Values_Per_Sel);
                  if Value_Matches
                    (EV.Text_Value.Data (1 .. EV.Text_Value.Length),
                     C.Expected.Items (I).Data
                       (1 .. C.Expected.Items (I).Length),
                     C, I)
                  then
                     return (Matched => True, Error => Error_None);
                  end if;
               end loop;
               return (Matched => False, Error => Error_None);
             when E_Pattern =>
                if EV.Kind /= V_Text then
                   return (Matched => False, Error => Error_None);
                end if;
                if not Valid_Program (C.Expected.Prog) then
                   --  Hand-built rule bypassing the loader.
                   return (Matched => False,
                           Error   => Error_Invalid_Rule);
                end if;
                case Run_Pattern
                  (C.Expected.Prog,
                   EV.Text_Value.Data (1 .. EV.Text_Value.Length))
                is
                   when PV_Match =>
                      return (Matched => True, Error => Error_None);
                   when PV_No_Match =>
                      return (Matched => False, Error => Error_None);
                   when PV_Invalid =>
                      return (Matched => False,
                              Error   => Error_Invalid_Rule);
                end case;
             when E_Pattern_List =>
                if EV.Kind /= V_Text then
                   return (Matched => False, Error => Error_None);
                end if;
                if C.Expected.Pat_Count = 0 then
                   --  An empty list matches nothing either way.
                   return (Matched => False, Error => Error_None);
                end if;
                if Has_Modifier (C.Modifiers, Mod_All) then
                   for I in 1 .. C.Expected.Pat_Count loop
                      pragma Loop_Invariant
                        (C.Expected.Pat_Count <= Max_Values_Per_Sel);
                      if not Valid_Program (C.Expected.Pat_Progs (I)) then
                         return (Matched => False,
                                 Error   => Error_Invalid_Rule);
                      end if;
                      case Run_Pattern
                        (C.Expected.Pat_Progs (I),
                         EV.Text_Value.Data (1 .. EV.Text_Value.Length))
                      is
                         when PV_Match =>
                            null;
                         when PV_No_Match =>
                            return (Matched => False, Error => Error_None);
                         when PV_Invalid =>
                            return (Matched => False,
                                    Error   => Error_Invalid_Rule);
                      end case;
                   end loop;
                   return (Matched => True, Error => Error_None);
                end if;
                for I in 1 .. C.Expected.Pat_Count loop
                   pragma Loop_Invariant
                     (C.Expected.Pat_Count <= Max_Values_Per_Sel);
                   if not Valid_Program (C.Expected.Pat_Progs (I)) then
                      return (Matched => False,
                              Error   => Error_Invalid_Rule);
                   end if;
                   case Run_Pattern
                     (C.Expected.Pat_Progs (I),
                      EV.Text_Value.Data (1 .. EV.Text_Value.Length))
                   is
                      when PV_Match =>
                         return (Matched => True, Error => Error_None);
                      when PV_No_Match =>
                         null;
                      when PV_Invalid =>
                         return (Matched => False,
                                 Error   => Error_Invalid_Rule);
                   end case;
                end loop;
                return (Matched => False, Error => Error_None);
            when E_CIDR =>
               if EV.Kind /= V_Text then
                  return (Matched => False, Error => Error_None);
               end if;
               if not Valid_CIDR_Net (C.Expected.Net) then
                  --  Hand-built rule bypassing the loader.
                  return (Matched => False,
                          Error => Error_Unsupported_Modifier);
               end if;
               declare
                  A : constant IP.IP_Address := IP.Parse_Address
                    (EV.Text_Value.Data (1 .. EV.Text_Value.Length));
               begin
                  if A.Length = 0 then
                     --  Malformed event data is a clean non-match:
                     --  events are untrusted input, not rules.
                     return (Matched => False, Error => Error_None);
                  end if;
                  if IP.Contains (C.Expected.Net, A) then
                     return (Matched => True, Error => Error_None);
                  end if;
               end;
               return (Matched => False, Error => Error_None);
            when E_CIDR_List =>
               if EV.Kind /= V_Text then
                  return (Matched => False, Error => Error_None);
               end if;
               if C.Expected.Net_Count = 0 then
                  --  An empty list matches nothing either way.
                  return (Matched => False, Error => Error_None);
               end if;
               declare
                  A : constant IP.IP_Address := IP.Parse_Address
                    (EV.Text_Value.Data (1 .. EV.Text_Value.Length));
               begin
                  if A.Length = 0 then
                     return (Matched => False, Error => Error_None);
                  end if;
                  if Has_Modifier (C.Modifiers, Mod_All) then
                     for I in 1 .. C.Expected.Net_Count loop
                        pragma Loop_Invariant
                          (C.Expected.Net_Count <= Max_Values_Per_Sel);
                        if not Valid_CIDR_Net (C.Expected.Nets (I)) then
                           return (Matched => False,
                                   Error => Error_Unsupported_Modifier);
                        end if;
                        if not IP.Contains (C.Expected.Nets (I), A) then
                           return (Matched => False, Error => Error_None);
                        end if;
                     end loop;
                     return (Matched => True, Error => Error_None);
                  end if;
                  for I in 1 .. C.Expected.Net_Count loop
                     pragma Loop_Invariant
                       (C.Expected.Net_Count <= Max_Values_Per_Sel);
                     if not Valid_CIDR_Net (C.Expected.Nets (I)) then
                        return (Matched => False,
                                Error => Error_Unsupported_Modifier);
                     end if;
                     if IP.Contains (C.Expected.Nets (I), A) then
                        return (Matched => True, Error => Error_None);
                     end if;
                  end loop;
                  return (Matched => False, Error => Error_None);
               end;
         end case;
      end;
   end Match_Field;

   function Match_Selection
     (Sel : Selection; Event : Event_Record) return Eval_Result
   is
   begin
      for I in 1 .. Sel.Field_Count loop
         pragma Loop_Invariant (Sel.Field_Count <= Max_Fields_Per_Sel);
         declare
            R : constant Eval_Result := Match_Field (Sel.Fields (I), Event);
         begin
            if R.Error /= Error_None then
               return R;
            end if;
            if not R.Matched then
               return (Matched => False, Error => Error_None);
            end if;
         end;
      end loop;
      --  A selection with zero fields cannot match; the boundary
      --  rejects such rules at load, this is defence in depth.
      if Sel.Field_Count = 0 then
         return (Matched => False, Error => Error_None);
      end if;
      return (Matched => True, Error => Error_None);
   end Match_Selection;

   function Eval_Node
     (Rule : Compiled_Rule; Event : Event_Record; Idx : Positive;
      Fuel : Natural)
      return Eval_Result
   with Subprogram_Variant => (Decreases => Fuel)
   is
   begin
      if Fuel = 0 then
         --  Cyclic node graph: fail closed instead of recursing forever.
         return (Matched => False, Error => Error_Invalid_Rule);
      end if;
      if Idx > Rule.Node_Count then
         return (Matched => False, Error => Error_Invalid_Rule);
      end if;
      declare
         N : constant Condition_Node := Rule.Nodes (Idx);
      begin
         case N.Kind is
            when N_Ref =>
               if N.Sel_Index > Rule.Sel_Count then
                  return (Matched => False, Error => Error_Invalid_Rule);
               end if;
               return Match_Selection (Rule.Selections (N.Sel_Index), Event);
            when N_Not =>
               declare
                  C : constant Eval_Result := Eval_Node (Rule, Event, N.Child, Fuel - 1);
               begin
                  if C.Error /= Error_None then
                     return C;
                  end if;
                  return (Matched => not C.Matched, Error => Error_None);
               end;
            when N_And =>
               declare
                  L : constant Eval_Result := Eval_Node (Rule, Event, N.Left, Fuel - 1);
                  R : constant Eval_Result := Eval_Node (Rule, Event, N.Right, Fuel - 1);
               begin
                  if L.Error /= Error_None then
                     return L;
                  end if;
                  if R.Error /= Error_None then
                     return R;
                  end if;
                  return (Matched => L.Matched and R.Matched,
                          Error   => Error_None);
               end;
            when N_Or =>
               declare
                  L : constant Eval_Result := Eval_Node (Rule, Event, N.Left, Fuel - 1);
                  R : constant Eval_Result := Eval_Node (Rule, Event, N.Right, Fuel - 1);
               begin
                  if L.Error /= Error_None then
                     return L;
                  end if;
                  if R.Error /= Error_None then
                     return R;
                  end if;
                  return (Matched => L.Matched or R.Matched,
                          Error   => Error_None);
               end;
            when N_One_Of =>
               declare
                  First_Error : Eval_Error := Error_None;
                  Saw_Error   : Boolean := False;
               begin
                  for I in 1 .. Rule.Sel_Count loop
                     pragma Loop_Invariant (Rule.Sel_Count <= Max_Selections);
                     if Has_Prefix (Rule.Selections (I).Name, N.Prefix) then
                        declare
                           R : constant Eval_Result :=
                             Match_Selection (Rule.Selections (I), Event);
                        begin
                           if R.Error /= Error_None and then not Saw_Error then
                              First_Error := R.Error;
                              Saw_Error := True;
                           end if;
                           if R.Error = Error_None and then R.Matched then
                              return (Matched => True, Error => Error_None);
                           end if;
                        end;
                     end if;
                  end loop;
                  if Saw_Error then
                     --  Fail-closed: a matching-shaped branch errored and
                     --  nothing cleanly matched.
                     return (Matched => False, Error => First_Error);
                  end if;
                  return (Matched => False, Error => Error_None);
               end;
            when N_All_Of =>
               declare
                  First_Error : Eval_Error := Error_None;
                  Saw_Error   : Boolean := False;
               begin
                  for I in 1 .. Rule.Sel_Count loop
                     pragma Loop_Invariant (Rule.Sel_Count <= Max_Selections);
                     if Has_Prefix (Rule.Selections (I).Name, N.Prefix) then
                        declare
                           R : constant Eval_Result :=
                             Match_Selection (Rule.Selections (I), Event);
                        begin
                           if R.Error /= Error_None then
                              if not Saw_Error then
                                 First_Error := R.Error;
                                 Saw_Error := True;
                              end if;
                           elsif not R.Matched then
                              return (Matched => False, Error => Error_None);
                           end if;
                        end;
                     end if;
                  end loop;
                  if Saw_Error then
                     return (Matched => False, Error => First_Error);
                  end if;
                  --  Vacuous truth over an empty prefix set, per Sigma.
                  return (Matched => True, Error => Error_None);
               end;
            when N_Near | N_Count =>
               return (Matched => False,
                       Error   => Error_Unsupported_Condition);
         end case;
      end;
   end Eval_Node;

   function Empty_Rule return Compiled_Rule is
      R : Compiled_Rule;
   begin
      R.Sel_Count := 0;
      R.Node_Count := 0;
      R.Root := 0;
      return R;
   end Empty_Rule;

   function Evaluate
     (Rule : Compiled_Rule; Event : Event_Record) return Eval_Result
   is
   begin
      if Rule.Root = 0 or else Rule.Root > Rule.Node_Count then
         return (Matched => False, Error => Error_Invalid_Rule);
      end if;
      return Eval_Node (Rule, Event, Rule.Root, Max_Condition_Nodes);
   end Evaluate;

end Sigma_Verdict.Engine;
