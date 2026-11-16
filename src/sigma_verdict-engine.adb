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
      elsif Same_Word (Token, "utf16le") then
         return Mod_UTF16LE;
      elsif Same_Word (Token, "utf16be") then
         return Mod_UTF16BE;
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

   function Chain_Supported (Set : Modifier_Set) return Boolean is
   begin
      for I in 1 .. Set.Count loop
         pragma Loop_Invariant (Set.Count <= Max_Modifiers_Per_Field);
         if not Is_Supported_Modifier (Set.Items (I)) then
            return False;
         end if;
      end loop;
      return True;
   end Chain_Supported;

   ----------------
   --  Matching --
   ----------------

   function Fold (C : Character) return Character is
     (if C in 'A' .. 'Z'
      then Character'Val (Character'Pos (C) + 32)
      else C);

   function Equal_Folded (A, B : String) return Boolean is
     (A'Length = B'Length
      and then (for all I in 0 .. A'Length - 1 =>
                  Fold (A (A'First + I)) = Fold (B (B'First + I))));

   function Same_Bytes (A, B : String) return Boolean is
     (A'Length = B'Length
      and then (for all I in 0 .. A'Length - 1 =>
                  A (A'First + I) = B (B'First + I)));

   function Field_Equal (A, B : Field_Name) return Boolean is
     (A.Length = B.Length
      and then Same_Bytes (A.Data (1 .. A.Length), B.Data (1 .. B.Length)));

   function Contains_At (Haystack, Needle : String) return Boolean is
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
            if Fold (Haystack (Haystack'First + Start + K)) /=
              Fold (Needle (Needle'First + K))
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

   function Starts_With_At (Haystack, Needle : String) return Boolean is
   begin
      if Needle'Length = 0 then
         return True;
      end if;
      if Needle'Length > Haystack'Length then
         return False;
      end if;
      for K in 0 .. Needle'Length - 1 loop
         pragma Loop_Invariant (Needle'Length <= Haystack'Length);
         if Fold (Haystack (Haystack'First + K)) /=
           Fold (Needle (Needle'First + K))
         then
            return False;
         end if;
      end loop;
      return True;
   end Starts_With_At;

   function Ends_With_At (Haystack, Needle : String) return Boolean is
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
            if Fold (Haystack (Haystack'First + Offset + K)) /=
              Fold (Needle (Needle'First + K))
            then
               return False;
            end if;
         end loop;
         return True;
      end;
   end Ends_With_At;

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
     (Event : Event_Record; Name : Field_Name; Loc : Natural)
   is
      S : E.Selection renames L.Rule.Selections (Sel);
   begin
      if not E.Can_Add_Field (S) then
         Fail (L, Load_Too_Many_Fields, Loc);
         return;
      end if;
      S.Field_Count := S.Field_Count + 1;
      S.Fields (S.Field_Count) := F;
   end Append_Field;

