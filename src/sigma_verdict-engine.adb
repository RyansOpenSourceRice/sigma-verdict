--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

package body Sigma_Verdict.Engine with SPARK_Mode is

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

   function Chain_Supported (Set : Modifier_Set) return Boolean is
      Seen_Matcher : Boolean := False;
      Seen_View    : Boolean := False;
   begin
      for I in 1 .. Set.Count loop
         pragma Loop_Invariant (Set.Count <= Max_Modifiers_Per_Field);
         if Is_Supported_Modifier (Set.Items (I)) then
            --  At most one matching semantic per chain; several would
            --  silently shadow each other, so the chain fails closed.
            if Seen_Matcher then
               return False;
            end if;
            Seen_Matcher := True;
         elsif Set.Items (I) in Mod_Windash | Mod_Wide | Mod_UTF16LE
           | Mod_UTF16BE | Mod_UTF16 | Mod_Base64 | Mod_Base64Offset
         then
            --  At most one view derivation per chain; mixing views
            --  would stack encodings the core does not model.
            if Seen_View then
               return False;
            end if;
            Seen_View := True;
         elsif Set.Items (I) not in Mod_Cased | Mod_All | Mod_Exists then
            return False;
         end if;
      end loop;
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
      HC : Natural := Start;
      NP : Natural := N'First;
   begin
      if N'Length = 0 then
         Result := (Matched => True, Stop => Start);
         return;
      end if;
      while NP <= N'Last loop
         pragma Loop_Invariant (HC <= H'Length);
         pragma Loop_Invariant (NP in N'First .. N'Last);
         pragma Loop_Variant (Increases => NP);
         if Is_Dash_At (Dashes, Dash_N, NP - N'First + 1) then
            if HC < H'Length
              and then (H (H'First + HC) = '-'
                        or else H (H'First + HC) = '/')
            then
               HC := HC + 1;
               NP := NP + 1;
            elsif HC + 3 <= H'Length
              and then H (H'First + HC) = Character'Val (16#E2#)
              and then H (H'First + HC + 1) = Character'Val (16#80#)
              and then H (H'First + HC + 2) in Character'Val (16#93#)
                | Character'Val (16#94#) | Character'Val (16#95#)
            then
               HC := HC + 3;
               NP := NP + 1;
            else
               Result := (Matched => False, Stop => HC);
               return;
            end if;
         else
            if HC < H'Length
              and then Fold (H (H'First + HC), Sensitive)
                       = Fold (N (NP), Sensitive)
            then
               HC := HC + 1;
               NP := NP + 1;
            else
               Result := (Matched => False, Stop => HC);
               return;
            end if;
         end if;
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
   --  value, and anything else bypassed the loader and fails closed.
   function Views_Consistent (C : Field_Constraint) return Boolean is
   begin
      case C.Expected.Kind is
         when E_Int | E_Int_List =>
            return C.Views.Count = 0
              and then not C.Views.Has_Offset
              and then not Has_View_Modifier (C.Modifiers);
         when E_Pattern =>
            --  Rejected as Unsupported regardless of views.
            return True;
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
            when E_Int_List | E_Text_List | E_Pattern =>
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
      if C.Expected.Kind = E_Pattern then
         return (Matched => False, Error => Error_Unsupported_Modifier);
      end if;
      if Slot = 0 then
         --  Absent field: no match, no error (standard Sigma semantics).
         return (Matched => False, Error => Error_None);
      end if;
      declare
         EV : constant Event_Value := Event.Fields (Slot).Value;
      begin
         case C.Expected.Kind is
            when E_Int =>
               if EV.Kind = V_Int and then EV.Int_Value = C.Expected.Int_Value then
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
                     if EV.Int_Value /= C.Expected.Ints (I) then
                        return (Matched => False, Error => Error_None);
                     end if;
                  end loop;
                  return (Matched => True, Error => Error_None);
               end if;
               for I in 1 .. C.Expected.Int_Count loop
                  pragma Loop_Invariant
                    (C.Expected.Int_Count <= Max_Values_Per_Sel);
                  if EV.Int_Value = C.Expected.Ints (I) then
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
               return (Matched => False, Error => Error_Unsupported_Modifier);
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
