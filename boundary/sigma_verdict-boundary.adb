--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

with Sigma_Verdict.IP;
with Sigma_Verdict.Limits;
with Yaml;
with Yaml.Parser;

use Yaml;
use Yaml.Parser;

package body Sigma_Verdict.Boundary with SPARK_Mode => Off is

   use E;

package IP renames Sigma_Verdict.IP;

   Max_Key_Length   : constant := 256;
   Max_Stack_Depth  : constant := 16;
   Max_Cond_Length  : constant := 1024;
   Max_Cond_Tokens  : constant := 64;
   Max_Token_Length : constant := 128;

   subtype Key_Buffer is String (1 .. Max_Key_Length);
   subtype Cond_Buffer is String (1 .. Max_Cond_Length);
   subtype Token_Buffer is String (1 .. Max_Token_Length);

   type Frame_Kind is (F_Root, F_Skip, F_Detection, F_Selection);

   type Frame is record
      Kind         : Frame_Kind := F_Root;
      Expects_Key  : Boolean := True;
      Ignored      : Boolean := False;
      Key_Len      : Natural := 0;
      Key          : Key_Buffer := [others => ' '];
      Sel_Index    : Natural := 0;
      --  List accumulation for `Field: [a, b]` values.
      In_List      : Boolean := False;
      List_Is_Int  : Boolean := True;
      List_Has_Int : Boolean := False;
      List_Has_Txt : Boolean := False;
      List_Count   : Natural := 0;
      List_Ints    : E.Int_Array := [others => 0];
      List_Items   : E.Value_Text_Array :=
        [others => (Length => 0,
                    Data   => [others => ' '])];
   end record;

   type Frame_Stack is array (1 .. Max_Stack_Depth) of Frame;

   type Loader is record
      Rule       : E.Compiled_Rule;
      Frames     : Frame_Stack;
      Depth      : Natural := 0;
      In_Detect  : Boolean := False;
      Error      : Load_Error := Load_Ok;
      Detail     : Natural := 0;
      Cond_Len   : Natural := 0;
      Cond       : Cond_Buffer := [others => ' '];
      Have_Cond  : Boolean := False;
   end record;

   procedure Fail (L : in out Loader; E : Load_Error; Loc : Natural := 0) is
   begin
      if L.Error = Load_Ok then
         L.Error := E;
         L.Detail := Loc;
      end if;
   end Fail;

   --  Reset an out rule without routing a whole Compiled_Rule through
   --  a function return (secondary-stack transient proportional to
   --  the view tables). Equivalent to Empty_Rule: every component
   --  already carries its empty default except the three counts.
   procedure Clear_Rule (R : out E.Compiled_Rule) is
   begin
      R := (Selections => [others => <>],
            Sel_Count  => 0,
            Nodes      => [others => <>],
            Node_Count => 0,
            Root       => 0);
   end Clear_Rule;

   procedure Copy_Key
     (L : in out Loader; Text : String; Loc : Natural)
   is
      F : Frame renames L.Frames (L.Depth);
   begin
      if Text'Length > Max_Key_Length then
         Fail (L, Load_Too_Long, Loc);
         return;
      end if;
      F.Key_Len := Text'Length;
      F.Key (1 .. Text'Length) := Text;
      F.Expects_Key := False;
   end Copy_Key;

   function Pending_Key (L : Loader) return String is
      F : Frame renames L.Frames (L.Depth);
   begin
      return F.Key (1 .. F.Key_Len);
   end Pending_Key;

   procedure Push (L : in out Loader; Kind : Frame_Kind; Loc : Natural) is
   begin
      if L.Depth >= Max_Stack_Depth then
         Fail (L, Load_Internal, Loc);
         return;
      end if;
      L.Depth := L.Depth + 1;
      L.Frames (L.Depth) :=
        (Kind => Kind, Expects_Key => True, Ignored => False,
         Key_Len => 0, Key => [others => ' '], Sel_Index => 0,
         In_List => False, List_Is_Int => True,
         List_Has_Int => False, List_Has_Txt => False,
         List_Count => 0, List_Ints => [others => 0],
         List_Items =>
           [others => (Length => 0, Data => [others => ' '])]);
   end Push;

   procedure Pop (L : in out Loader) is
   begin
      if L.Depth >= 1 then
         if L.Frames (L.Depth).Kind = F_Detection then
            L.In_Detect := False;
         end if;
         L.Depth := L.Depth - 1;
      end if;
   end Pop;

   function Fold_Char (C : Character) return Character is
     (if C in 'A' .. 'Z'
      then Character'Val (Character'Pos (C) + 32)
      else C);

   function Same_Folded (A, B : String) return Boolean is
     (A'Length = B'Length
      and then (for all I in 0 .. A'Length - 1 =>
                  Fold_Char (A (A'First + I)) =
                    Fold_Char (B (B'First + I))));

   --------------------------------
   --  View derivation (P1b) --
   --------------------------------
   --  The core matches over bytes; every byte transform lives here
   --  (auditable, SPARK off). Illegal view input is Load_Bad_Value,
   --  over-capacity derivations are Load_Too_Long, never silent loss.
   --  Semantics mirror pySigma 2.1.0 exactly (local reference clone).

   B64_Alphabet : constant String :=
     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

   function Is_Word_Char (C : Character) return Boolean is
     (C in 'A' .. 'Z' or else C in 'a' .. 'z' or else C in '0' .. '9'
      or else C = '_');
   --  ASCII approximation of the Python \w class in the pySigma
   --  windash rule (documented divergence for non-ASCII, see DESIGN).

   --  Standard base64 over raw bytes. Out_Text must hold at least
   --  4 * ((Data'Length + 2) / 3) characters.
   procedure B64_Encode
     (Data : String; Out_Text : out String; Out_Len : out Natural)
   is
      O           : Natural := 0;
      I           : Natural := Data'First;
      B0, B1, B2  : Natural;
      Have1, Have2 : Boolean;
   begin
      Out_Len := 0;
      if Data'Length = 0 then
         return;
      end if;
      I := Data'First;
      while I <= Data'Last loop
         B0 := Character'Pos (Data (I));
         Have1 := I < Data'Last;
         Have2 := Have1 and then I + 1 < Data'Last;
         B1 := (if Have1 then Character'Pos (Data (I + 1)) else 0);
         B2 := (if Have2 then Character'Pos (Data (I + 2)) else 0);
         Out_Text (O + 1) :=
           B64_Alphabet (B0 / 4 + 1);
         Out_Text (O + 2) :=
           B64_Alphabet ((B0 mod 4) * 16 + B1 / 16 + 1);
         Out_Text (O + 3) :=
           (if Have1
            then B64_Alphabet ((B1 mod 16) * 4 + B2 / 64 + 1)
            else '=');
         Out_Text (O + 4) :=
           (if Have2 then B64_Alphabet (B2 mod 64 + 1) else '=');
         O := O + 4;
         I := I + 3;
      end loop;
      Out_Len := O;
   end B64_Encode;

   --  Derive one value's single view (everything but base64offset).
   --  Fatal means L.Error was set and SV must be ignored. Callers
   --  only pass real single-view tokens here.
   procedure Derive_Single
     (L     : in out Loader;
      Token : E.Modifier_Kind;
      Raw   : String;
      Loc   : Natural;
      SV    : out E.Single_View;
      Fatal : out Boolean)
   is
   begin
      Fatal := False;
      SV.Has_Alt := False;
      SV.Dash_N := 0;
      SV.Dash_At := [others => 0];
      case Token is
         when E.Mod_Windash =>
            --  pySigma \B[-/]\b: dash/slash whose next character is a
            --  word character and which is first or follows a
            --  non-word character. Positions are 1-based over Raw.
            for I in Raw'Range loop
               if Raw (I) = '-' or else Raw (I) = '/' then
                  declare
                     Next_Word : constant Boolean :=
                       I < Raw'Last and then Is_Word_Char (Raw (I + 1));
                     Prev_OK   : constant Boolean :=
                       I = Raw'First
                       or else not Is_Word_Char (Raw (I - 1));
                  begin
                     if Next_Word and then Prev_OK then
                        if SV.Dash_N = E.Max_Dash_Places then
                           --  pySigma rejects >3 the same way.
                           Fail (L, Load_Bad_Value, Loc);
                           Fatal := True;
                           return;
                        end if;
                        SV.Dash_N := SV.Dash_N + 1;
                        SV.Dash_At (SV.Dash_N) := I - Raw'First + 1;
                     end if;
                  end;
               end if;
            end loop;
         when E.Mod_Wide | E.Mod_UTF16LE | E.Mod_UTF16BE | E.Mod_UTF16 =>
            declare
               Buf  : String (1 .. Limits.Default_View_Length);
               K    : Natural := 0;
               Need : constant Natural :=
                 2 * Raw'Length
                 + (if Token = E.Mod_UTF16 then 2 else 0);
            begin
               if Need > Buf'Length then
                  Fail (L, Load_Too_Long, Loc);
                  Fatal := True;
                  return;
               end if;
               for I in Raw'Range loop
                  if Character'Pos (Raw (I)) > 127 then
                     --  pySigma raises on non-ASCII wide input too.
                     Fail (L, Load_Bad_Value, Loc);
                     Fatal := True;
                     return;
                  end if;
               end loop;
               if Token = E.Mod_UTF16 then
                  --  UTF-16LE BOM (FF FE), like pySigma's U+FEFF.
                  Buf (1) := Character'Val (16#FF#);
                  Buf (2) := Character'Val (16#FE#);
                  K := 2;
               end if;
               for I in Raw'Range loop
                  if Token = E.Mod_UTF16BE then
                     Buf (K + 1) := Character'Val (0);
                     Buf (K + 2) := Raw (I);
                  else
                     Buf (K + 1) := Raw (I);
                     Buf (K + 2) := Character'Val (0);
                  end if;
                  K := K + 2;
               end loop;
               declare
                  R : constant E.View_Result :=
                    E.To_View_Text (Buf (1 .. K));
               begin
                  if not R.Ok then
                     Fail (L, Load_Too_Long, Loc);
                     Fatal := True;
                     return;
                  end if;
                  SV.Has_Alt := True;
                  SV.Alt := R.Value;
               end;
            end;
         when E.Mod_Base64 =>
            declare
               Buf : String (1 .. 4 * ((Raw'Length + 2) / 3));
               Len : Natural;
               R   : E.View_Result;
            begin
               B64_Encode (Raw, Buf, Len);
               R := E.To_View_Text (Buf (1 .. Len));
               if not R.Ok then
                  Fail (L, Load_Too_Long, Loc);
                  Fatal := True;
                  return;
               end if;
               SV.Has_Alt := True;
               SV.Alt := R.Value;
            end;
         when others =>
            --  base64offset has its own derivation; anything else
            --  never reaches here (callers check the token first).
            Fail (L, Load_Internal, Loc);
            Fatal := True;
            return;
      end case;
   end Derive_Single;

   --  base64offset fans one SINGLE value into three alternatives
   --  (exact pySigma 2.1.0 construction: prepend 0/1/2 spaces,
   --  encode, cut per (len + i) mod 3 with starts (0,2,3) and
   --  drops (0,3,2)). Lists with it are rejected by the caller.
   procedure Derive_Offset
     (L    : in out Loader;
      Raw  : String;
      Loc  : Natural;
      Alts : out E.Offset_Alts;
      Fatal : out Boolean)
   is
      Starts : constant array (0 .. 2) of Natural := [0, 2, 3];
      Drops  : constant array (0 .. 2) of Natural := [0, 3, 2];
   begin
      Fatal := False;
      for J in 0 .. 2 loop
         declare
            Pad  : String (1 .. J + Raw'Length);
            Enc  : String (1 .. 4 * ((Pad'Length + 2) / 3));
            ELen : Natural;
            S1   : constant Natural := Starts (J) + 1;
            E1   : Natural;
            R    : E.View_Result;
         begin
            Pad (1 .. J) := [others => ' '];
            Pad (J + 1 .. Pad'Last) := Raw;
            B64_Encode (Pad, Enc, ELen);
            E1 := ELen - Drops (J);
            if S1 > E1 then
               R := E.To_View_Text ("");
            else
               R := E.To_View_Text (Enc (S1 .. E1));
            end if;
            if not R.Ok then
               Fail (L, Load_Too_Long, Loc);
               Fatal := True;
               return;
            end if;
            Alts (J + 1) := R.Value;
         end;
      end loop;
   end Derive_Offset;

   --  Split "CommandLine|windash|contains" into field name + modifiers.
   procedure Parse_Field_Key
     (L         : in out Loader;
      Key       : String;
      Loc       : Natural;
      Field     : out E.Field_Name;
      Mods      : out E.Modifier_Set;
      Supported : out Boolean)
   is
      Start : Positive := Key'First;
      Piece : Natural;
      M     : E.Modifier_Kind;
      Ok    : Boolean;
      First : Boolean := True;
   begin
      Field := (Length => 0, Data => [others => ' ']);
      Mods := E.Empty_Modifiers;
      Supported := True;
      for I in Key'Range loop
         if Key (I) = '|' then
            Piece := I - Start;
            if First then
               if Piece = 0
                 or else Start + Piece - 1 > Key'Last
                 or else Piece >
                   Limits.Default_Field_Length
               then
                  Fail (L, Load_Too_Long, Loc);
                  Supported := False;
                  return;
               end if;
               declare
                  R : constant E.Field_Result :=
                    E.To_Field_Name (Key (Start .. Start + Piece - 1));
               begin
                  if not R.Ok then
                     Fail (L, Load_Too_Long, Loc);
                     Supported := False;
                     return;
                  end if;
                  Field := R.Value;
               end;
               First := False;
            else
               M := E.Parse_Modifier (Key (Start .. I - 1));
               if M = E.Mod_Unknown then
                  Fail (L, Load_Unknown_Modifier, Loc);
                  Supported := False;
                  return;
               end if;
               E.Add_Modifier (Mods, M, Ok);
               if not Ok then
                  Fail (L, Load_Too_Many_Modifiers, Loc);
                  Supported := False;
                  return;
               end if;
            end if;
            Start := I + 1;
         end if;
      end loop;
      if First then
         declare
            R : constant E.Field_Result := E.To_Field_Name (Key);
         begin
            if not R.Ok then
               Fail (L, Load_Too_Long, Loc);
               Supported := False;
               return;
            end if;
            Field := R.Value;
         end;
      else
         if Start > Key'Last then
            Fail (L, Load_Unknown_Modifier, Loc);
            Supported := False;
            return;
         end if;
         M := E.Parse_Modifier (Key (Start .. Key'Last));
         if M = E.Mod_Unknown then
            Fail (L, Load_Unknown_Modifier, Loc);
            Supported := False;
            return;
         end if;
         E.Add_Modifier (Mods, M, Ok);
         if not Ok then
            Fail (L, Load_Too_Many_Modifiers, Loc);
            Supported := False;
            return;
         end if;
      end if;
   end Parse_Field_Key;

   procedure Append_Field
     (L : in out Loader; Sel : Natural; F : E.Field_Constraint; Loc : Natural)
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

   --  Build one field constraint from a scalar YAML value. Plain-style
   --  integers (EventID: 4728) become E_Int; quoted or non-numeric
   --  scalars become E_Text. Chains holding re/wildcard become
   --  E_Pattern so the core fails closed with Unsupported.
   procedure Add_Scalar_Field
     (L       : in out Loader;
      Sel     : Natural;
      Key     : String;
      Text    : String;
      Is_Plain : Boolean;
      Loc     : Natural)
   is
      Field : E.Field_Name;
      Mods  : E.Modifier_Set;
      OK    : Boolean;
      F     : E.Field_Constraint;
      Wants_Pattern : Boolean;
      VT    : E.Modifier_Kind;
      CT    : E.Modifier_Kind;
      Has_CIDR : Boolean;
      VW    : E.Single_View;
      Fatal : Boolean;
   begin
      Parse_Field_Key (L, Key, Loc, Field, Mods, OK);
      if not OK then
         return;
      end if;
      if E.Has_Modifier (Mods, E.Mod_Exists) then
         --  `exists` is standalone with a boolean value; anything else
         --  is a malformed rule, rejected here rather than guessed at.
         if Mods.Count /= 1 then
            Fail (L, Load_Bad_Value, Loc);
            return;
         end if;
         if Same_Folded (Text, "true") then
            F := (Field => Field, Modifiers => Mods,
                  Expected => (Kind => E.E_Int, Int_Value => 1),
                  Views => (others => <>));
         elsif Same_Folded (Text, "false") then
            F := (Field => Field, Modifiers => Mods,
                  Expected => (Kind => E.E_Int, Int_Value => 0),
                  Views => (others => <>));
         else
            Fail (L, Load_Bad_Value, Loc);
            return;
         end if;
         Append_Field (L, Sel, F, Loc);
         return;
      end if;
      Wants_Pattern := False;
      for I in 1 .. Mods.Count loop
         if Mods.Items (I) in E.Mod_Re | E.Mod_Re_I | E.Mod_Re_M
           | E.Mod_Re_S | E.Mod_Wildcard
         then
            Wants_Pattern := True;
         end if;
      end loop;
      VT := E.View_Token (Mods);
      CT := E.Comparison_Of (Mods);
      Has_CIDR := E.Has_Modifier (Mods, E.Mod_CIDR);
      if CT /= E.Mod_None and then Has_CIDR then
         --  The loader cannot parse one value two ways; the chain is
         --  refused here rather than guessed at (core gate agrees).
         Fail (L, Load_Unsupported_Chain, Loc);
         return;
      end if;
      if CT /= E.Mod_None then
         --  Comparisons need a bare integer. Quoted text stays text
         --  in this loader, so a quoted number is malformed here;
         --  non-numeric and out-of-range magnitudes are malformed
         --  too (pySigma types compare operators as numeric-only).
         if not Is_Plain then
            Fail (L, Load_Bad_Integer, Loc);
            return;
         end if;
         begin
            F := (Field => Field, Modifiers => Mods,
                  Expected => (Kind => E.E_Int,
                               Int_Value => Integer'Value (Text)),
                  Views => (others => <>));
            Append_Field (L, Sel, F, Loc);
         exception
            when Constraint_Error =>
               Fail (L, Load_Bad_Integer, Loc);
         end;
         return;
      end if;
      if Has_CIDR then
         declare
            Net : constant IP.IP_Network := IP.Parse_Network (Text);
         begin
            if Net.Base.Length = 0 then
               Fail (L, Load_Bad_Value, Loc);
               return;
            end if;
            F := (Field => Field, Modifiers => Mods,
                  Expected => (Kind => E.E_CIDR, Net => Net),
                  Views => (others => <>));
            Append_Field (L, Sel, F, Loc);
         end;
         return;
      end if;
      F := (Field => Field, Modifiers => Mods,
            Expected => (Kind => E.E_Text,
                         Single => (Length => 0, Data => [others => ' '])),
                Views => (others => <>));
      if Wants_Pattern then
         declare
            P : constant E.Pattern_Result := E.To_Pattern (Text);
         begin
            if not P.Ok then
               Fail (L, Load_Too_Long, Loc);
               return;
            end if;
            F.Expected := (Kind => E.E_Pattern, Pattern => P.Value);
         end;
      elsif Is_Plain then
         if VT /= E.Mod_None then
            --  Views derive from text; a view over an integer
            --  value is a malformed rule.
            Fail (L, Load_Bad_Value, Loc);
            return;
         end if;
         begin
            F.Expected :=
              (Kind => E.E_Int,
               Int_Value => Integer'Value (Text));
         exception
            when Constraint_Error =>
               declare
                  V : constant E.Value_Result := E.To_Value_Text (Text);
               begin
                  if not V.Ok then
                     Fail (L, Load_Too_Long, Loc);
                     return;
                  end if;
                  F.Expected := (Kind => E.E_Text, Single => V.Value);
               end;
         end;
      else
         declare
            V : constant E.Value_Result := E.To_Value_Text (Text);
         begin
            if not V.Ok then
               Fail (L, Load_Too_Long, Loc);
               return;
            end if;
            F.Expected := (Kind => E.E_Text, Single => V.Value);
         end;
      end if;
      if VT /= E.Mod_None and then F.Expected.Kind = E.E_Text then
         --  Patterns (re/wildcard) keep E_Pattern and fail closed in
         --  the core; only text values get derived views.
         if VT = E.Mod_Base64Offset then
            Derive_Offset (L, Text, Loc, F.Views.Offset, Fatal);
            if Fatal then
               return;
            end if;
            F.Views.Has_Offset := True;
            F.Views.Count := 1;
         else
            Derive_Single (L, VT, Text, Loc, VW, Fatal);
            if Fatal then
               return;
            end if;
            F.Views.Items (1) := VW;
            F.Views.Count := 1;
         end if;
      end if;
      Append_Field (L, Sel, F, Loc);
   end Add_Scalar_Field;

   procedure Add_List_Item
     (L   : in out Loader;
      Idx : Natural;
      Text : String; Is_Plain : Boolean; Loc : Natural)
   is
      --  Idx is the selection frame owning the list: list scalars
      --  arrive while the sequence's skip frame is on top, so the
      --  top frame is NOT the accumulator (wrong-frame items used to
      --  vanish into the skip frame, loading every YAML list empty).
      F : Frame renames L.Frames (Idx);
   begin
      if F.List_Count >= Limits.Default_Values_Per_Sel then
         Fail (L, Load_Too_Many_Values, Loc);
         return;
      end if;
      if Is_Plain then
         declare
            V : Integer;
         begin
            --  Convert first: incrementing before converting used to
            --  leak phantom empty items on Constraint_Error.
            V := Integer'Value (Text);
            F.List_Count := F.List_Count + 1;
            F.List_Ints (F.List_Count) := V;
            F.List_Has_Int := True;
            return;
         exception
            when Constraint_Error =>
               null;
         end;
      end if;
      declare
         V : constant E.Value_Result := E.To_Value_Text (Text);
      begin
         if not V.Ok then
            Fail (L, Load_Too_Long, Loc);
            return;
         end if;
         F.List_Count := F.List_Count + 1;
         F.List_Items (F.List_Count) := V.Value;
         F.List_Has_Txt := True;
      end;
   end Add_List_Item;

   procedure Close_List
     (L : in out Loader; Idx : Natural; Loc : Natural) is
      F     : Frame renames L.Frames (Idx);
      Field : E.Field_Name;
      Mods  : E.Modifier_Set;
      OK    : Boolean;
      FC    : E.Field_Constraint;
      VT    : E.Modifier_Kind;
      CT    : E.Modifier_Kind;
      Has_CIDR : Boolean;
      VW    : E.Single_View;
      Fatal : Boolean;
   begin
      F.In_List := False;
      Parse_Field_Key
        (L, F.Key (1 .. F.Key_Len), Loc, Field, Mods, OK);
      if not OK then
         return;
      end if;
      if E.Has_Modifier (Mods, E.Mod_Exists) then
         --  Presence never takes a list value.
         Fail (L, Load_Bad_Value, Loc);
         return;
      end if;
      VT := E.View_Token (Mods);
      CT := E.Comparison_Of (Mods);
      Has_CIDR := E.Has_Modifier (Mods, E.Mod_CIDR);
      if CT /= E.Mod_None and then Has_CIDR then
         Fail (L, Load_Unsupported_Chain, Loc);
         return;
      end if;
      if F.List_Has_Int and then F.List_Has_Txt then
         --  Mixed lists never compare and never form networks.
         if Has_CIDR then
            Fail (L, Load_Bad_Value, Loc);
         else
            Fail (L, Load_Bad_Integer, Loc);
         end if;
         return;
      end if;
      if CT /= E.Mod_None and then F.List_Has_Txt then
         --  Comparison values are bare integers, never text.
         Fail (L, Load_Bad_Integer, Loc);
         return;
      end if;
      if Has_CIDR and then F.List_Has_Int then
         --  Networks parse from text; integers are malformed here.
         Fail (L, Load_Bad_Value, Loc);
         return;
      end if;
      if VT /= E.Mod_None and then F.List_Has_Int then
         --  Views derive from text; a view over integers is malformed.
         Fail (L, Load_Bad_Value, Loc);
         return;
      end if;
      if F.List_Has_Int then
         FC := (Field => Field, Modifiers => Mods,
                Expected => (Kind => E.E_Int_List,
                             Ints => [others => 0],
                             Int_Count => 0),
                  Views => (others => <>));
         FC.Expected.Int_Count := F.List_Count;
         for I in 1 .. F.List_Count loop
            FC.Expected.Ints (I) := F.List_Ints (I);
         end loop;
      elsif Has_CIDR then
         FC := (Field => Field, Modifiers => Mods,
                Expected => (Kind => E.E_CIDR_List,
                             Nets => [others => <>],
                             Net_Count => 0),
                Views => (others => <>));
         FC.Expected.Net_Count := F.List_Count;
         for I in 1 .. F.List_Count loop
            declare
               Net : constant IP.IP_Network := IP.Parse_Network
                 (F.List_Items (I).Data (1 .. F.List_Items (I).Length));
            begin
               if Net.Base.Length = 0 then
                  Fail (L, Load_Bad_Value, Loc);
                  return;
               end if;
               FC.Expected.Nets (I) := Net;
            end;
         end loop;
      else
         FC := (Field => Field, Modifiers => Mods,
                Expected => (Kind => E.E_Text_List,
                             Items => [others =>
                               (Length => 0, Data => [others => ' '])],
                             Count => 0),
                Views => (others => <>));
         FC.Expected.Count := F.List_Count;
         for I in 1 .. F.List_Count loop
            FC.Expected.Items (I) := F.List_Items (I);
         end loop;
         if VT /= E.Mod_None then
            if VT = E.Mod_Base64Offset then
               --  One value fans into three alternatives; a list of
               --  those needs per-value grouping the flat rule
               --  cannot express, so the chain is refused here.
               Fail (L, Load_Unsupported_Chain, Loc);
               return;
            end if;
            for I in 1 .. F.List_Count loop
               Derive_Single
                 (L, VT,
                  F.List_Items (I).Data (1 .. F.List_Items (I).Length),
                  Loc, VW, Fatal);
               if Fatal then
                  return;
               end if;
               FC.Views.Items (I) := VW;
            end loop;
            FC.Views.Count := F.List_Count;
         end if;
      end if;
      Append_Field (L, F.Sel_Index, FC, Loc);
      F.List_Count := 0;
      F.List_Has_Int := False;
      F.List_Has_Txt := False;
   end Close_List;

   procedure Open_Selection (L : in out Loader; Name : String; Loc : Natural) is
   begin
      if not E.Can_Add_Selection (L.Rule.Sel_Count) then
         Fail (L, Load_Too_Many_Selections, Loc);
         Push (L, F_Skip, Loc);
         return;
      end if;
      declare
         R : constant E.Field_Result := E.To_Field_Name (Name);
      begin
         if not R.Ok then
            Fail (L, Load_Too_Long, Loc);
            Push (L, F_Skip, Loc);
            return;
         end if;
         L.Rule.Sel_Count := L.Rule.Sel_Count + 1;
         L.Rule.Selections (L.Rule.Sel_Count).Name := R.Value;
         L.Rule.Selections (L.Rule.Sel_Count).Field_Count := 0;
         for J in L.Rule.Selections (L.Rule.Sel_Count).Fields'Range loop
            L.Rule.Selections (L.Rule.Sel_Count).Fields (J) :=
               (Field     => (Length => 0, Data => [others => ' ']),
                Modifiers => E.Empty_Modifiers,
                Expected  => (Kind   => E.E_Text,
                              Single => (Length => 0,
                                         Data => [others => ' '])),
            Views => (others => <>));
         end loop;
         Push (L, F_Selection, Loc);
         L.Frames (L.Depth).Sel_Index := L.Rule.Sel_Count;
      end;
   end Open_Selection;

   ------------------------
   --  Condition parsing --
   ------------------------

   type Token_Array is array (1 .. Max_Cond_Tokens) of Token_Buffer;
   type Token_Lens is array (1 .. Max_Cond_Tokens) of Natural;

   function Resolve_Ref
     (L : in out Loader; Name : String; Loc : Natural) return Natural
   is
   begin
      for I in 1 .. L.Rule.Sel_Count loop
         if E.Image_Of (L.Rule.Selections (I).Name) = Name then
            return I;
         end if;
      end loop;
      Fail (L, Load_Unknown_Condition, Loc);
      return 0;
   end Resolve_Ref;

   function New_Node (L : in out Loader; N : E.Condition_Node) return Natural is
   begin
      if not E.Can_Add_Node (L.Rule.Node_Count) then
         Fail (L, Load_Too_Many_Nodes, 0);
         return 0;
      end if;
      L.Rule.Node_Count := L.Rule.Node_Count + 1;
      L.Rule.Nodes (L.Rule.Node_Count) := N;
      return L.Rule.Node_Count;
   end New_Node;

   --  Minimal condition grammar (see SPECIFICATION.md):
   --    or  := and {"or" and}
   --    and := unary {"and" unary}
   --    unary := ["not"] primary
   --    primary := IDENT | "1" "of" PREFIX* | "all" "of" PREFIX*
   --  Parentheses and aggregation pipes are rejected explicitly.
   procedure Parse_Condition (L : in out Loader) is
      Tokens : Token_Array := [others => [others => ' ']];
      Lens   : Token_Lens := [others => 0];
      Count  : Natural := 0;
      Pos    : Natural := 1;
      Start  : Natural;

      function Tok (I : Natural) return String is
        (Tokens (I) (1 .. Lens (I)));

      procedure Parse_Or (R : out Natural; Ok : out Boolean);
      procedure Parse_And (R : out Natural; Ok : out Boolean);
      procedure Parse_Unary (R : out Natural; Ok : out Boolean);
      procedure Parse_Primary (R : out Natural; Ok : out Boolean);

      procedure Parse_Primary (R : out Natural; Ok : out Boolean) is
         Idx : Natural;
      begin
         R := 0;
         Ok := False;
         if Pos > Count then
            Fail (L, Load_Unknown_Condition, 0);
            return;
         end if;
         if Tok (Pos) = "1" or else Tok (Pos) = "all" then
            declare
               Is_One : constant Boolean := Tok (Pos) = "1";
            begin
               Pos := Pos + 1;
               if Pos + 1 > Count + 1
                 or else Tok (Pos) /= "of"
               then
                  Fail (L, Load_Unknown_Condition, 0);
                  return;
               end if;
               Pos := Pos + 1;
               if Pos > Count then
                  Fail (L, Load_Unknown_Condition, 0);
                  return;
               end if;
               declare
                  P : constant String := Tok (Pos);
               begin
                  if P'Length < 2 or else P (P'Last) /= '*' then
                     Fail (L, Load_Unknown_Condition, 0);
                     return;
                  end if;
                  declare
                     FR : constant E.Field_Result :=
                       E.To_Field_Name (P (P'First .. P'Last - 1));
                  begin
                     if not FR.Ok then
                        Fail (L, Load_Too_Long, 0);
                        return;
                     end if;
                     Pos := Pos + 1;
                     if Is_One then
                        Idx := New_Node
                          (L, (Kind => E.N_One_Of, Prefix => FR.Value));
                     else
                        Idx := New_Node
                          (L, (Kind => E.N_All_Of, Prefix => FR.Value));
                     end if;
                     if L.Error /= Load_Ok then
                        return;
                     end if;
                     R := Idx;
                     Ok := True;
                  end;
               end;
            end;
         elsif Tok (Pos) = "near" or else Tok (Pos) = "count" then
            --  Reserved Phase 2 surface; rejected explicitly.
            Fail (L, Load_Unknown_Condition, 0);
            return;
         else
            declare
               S : constant Natural := Resolve_Ref (L, Tok (Pos), 0);
            begin
               if L.Error /= Load_Ok then
                  return;
               end if;
               Pos := Pos + 1;
               Idx := New_Node (L, (Kind => E.N_Ref, Sel_Index => S));
               if L.Error /= Load_Ok then
                  return;
               end if;
               R := Idx;
               Ok := True;
            end;
         end if;
      end Parse_Primary;

      procedure Parse_Unary (R : out Natural; Ok : out Boolean) is
         Inner : Natural;
         Idx   : Natural;
      begin
         if Pos <= Count and then Tok (Pos) = "not" then
            Pos := Pos + 1;
            Parse_Primary (Inner, Ok);
            if not Ok then
               R := 0;
               return;
            end if;
            Idx := New_Node (L, (Kind => E.N_Not, Child => Inner));
            if L.Error /= Load_Ok then
               Ok := False;
               R := 0;
               return;
            end if;
            R := Idx;
            Ok := True;
         else
            Parse_Primary (R, Ok);
         end if;
      end Parse_Unary;

      procedure Parse_And (R : out Natural; Ok : out Boolean) is
         Left, Right : Natural;
         Idx         : Natural;
      begin
         Parse_Unary (Left, Ok);
         if not Ok then
            R := 0;
            return;
         end if;
         while Pos <= Count and then Tok (Pos) = "and" loop
            Pos := Pos + 1;
            Parse_Unary (Right, Ok);
            if not Ok then
               R := 0;
               return;
            end if;
            Idx := New_Node
              (L, (Kind => E.N_And, Left => Left, Right => Right));
            if L.Error /= Load_Ok then
               Ok := False;
               R := 0;
               return;
            end if;
            Left := Idx;
         end loop;
         R := Left;
         Ok := True;
      end Parse_And;

      procedure Parse_Or (R : out Natural; Ok : out Boolean) is
         Left, Right : Natural;
         Idx         : Natural;
      begin
         Parse_And (Left, Ok);
         if not Ok then
            R := 0;
            return;
         end if;
         while Pos <= Count and then Tok (Pos) = "or" loop
            Pos := Pos + 1;
            Parse_And (Right, Ok);
            if not Ok then
               R := 0;
               return;
            end if;
            Idx := New_Node
              (L, (Kind => E.N_Or, Left => Left, Right => Right));
            if L.Error /= Load_Ok then
               Ok := False;
               R := 0;
               return;
            end if;
            Left := Idx;
         end loop;
         R := Left;
         Ok := True;
      end Parse_Or;

      Root : Natural;
      Ok   : Boolean;
   begin
      --  Tokenize on spaces.
      while Pos <= L.Cond_Len loop
         while Pos <= L.Cond_Len and then L.Cond (Pos) = ' ' loop
            Pos := Pos + 1;
         end loop;
         exit when Pos > L.Cond_Len;
         Start := Pos;
         while Pos <= L.Cond_Len and then L.Cond (Pos) /= ' ' loop
            Pos := Pos + 1;
         end loop;
         if Count >= Max_Cond_Tokens then
            Fail (L, Load_Too_Many_Nodes, 0);
            return;
         end if;
         if Pos - Start > Max_Token_Length then
            Fail (L, Load_Too_Long, 0);
            return;
         end if;
         Count := Count + 1;
         Lens (Count) := Pos - Start;
         Tokens (Count) (1 .. Pos - Start) := L.Cond (Start .. Pos - 1);
      end loop;
      if Count = 0 then
         Fail (L, Load_Empty_Rule, 0);
         return;
      end if;
      Pos := 1;
      Parse_Or (Root, Ok);
      if not Ok then
         return;
      end if;
      if Pos <= Count then
         Fail (L, Load_Unknown_Condition, 0);
         return;
      end if;
      L.Rule.Root := Root;
   end Parse_Condition;

   --------------------
   --  Event driver --
   --------------------

   procedure Handle_Scalar
     (L : in out Loader; Text : String; Is_Plain : Boolean; Loc : Natural)
   is
      F : Frame renames L.Frames (L.Depth);
   begin
      if F.Ignored then
         return;
      end if;
      if F.In_List then
         Add_List_Item (L, L.Depth, Text, Is_Plain, Loc);
         return;
      end if;
      if F.Expects_Key then
         Copy_Key (L, Text, Loc);
         return;
      end if;
      F.Expects_Key := True;
      case F.Kind is
         when F_Root =>
            if Pending_Key (L) = "condition" then
               if Text'Length > Max_Cond_Length then
                  Fail (L, Load_Too_Long, Loc);
                  return;
               end if;
               L.Cond_Len := Text'Length;
               L.Cond (1 .. Text'Length) := Text;
               L.Have_Cond := True;
            end if;
            --  All other root scalars (title, id, status, ...) are
            --  metadata and intentionally ignored.
         when F_Detection =>
            --  `condition` lives under `detection` in real Sigma rules.
            if Pending_Key (L) = "condition" then
               if Text'Length > Max_Cond_Length then
                  Fail (L, Load_Too_Long, Loc);
                  return;
               end if;
               L.Cond_Len := Text'Length;
               L.Cond (1 .. Text'Length) := Text;
               L.Have_Cond := True;
            end if;
         when F_Selection =>
            Add_Scalar_Field
              (L, F.Sel_Index, Pending_Key (L), Text, Is_Plain, Loc);
         when F_Skip =>
            null;
      end case;
   end Handle_Scalar;

   procedure Handle_Map_Value (L : in out Loader; Loc : Natural) is
      F   : Frame renames L.Frames (L.Depth);
      Key : constant String := Pending_Key (L);
   begin
      if F.Ignored then
         Push (L, F_Skip, Loc);
         return;
      end if;
      if F.Expects_Key then
         --  No pending key: this mapping is the frame's own content
         --  (document root, or the body of detection/selection).
         return;
      end if;
      F.Expects_Key := True;
      case F.Kind is
         when F_Root =>
            if Key = "detection" then
               Push (L, F_Detection, Loc);
               L.In_Detect := True;
            else
               --  logsource and other metadata subtrees are skipped.
               Push (L, F_Skip, Loc);
            end if;
         when F_Detection =>
            Open_Selection (L, Key, Loc);
         when F_Selection =>
            --  A mapping as a field value is outside Phase 1.
            Fail (L, Load_Unknown_Condition, Loc);
            Push (L, F_Skip, Loc);
         when F_Skip =>
            Push (L, F_Skip, Loc);
      end case;
   end Handle_Map_Value;

   procedure Handle_Seq_Value (L : in out Loader; Loc : Natural) is
      F : Frame renames L.Frames (L.Depth);
   begin
      if F.Ignored then
         Push (L, F_Skip, Loc);
         return;
      end if;
      if F.Kind = F_Skip then
         --  A sequence nested inside a list value is outside Phase 1.
         Fail (L, Load_Unknown_Condition, Loc);
         Push (L, F_Skip, Loc);
         return;
      end if;
      if F.Expects_Key then
         --  No pending key: a bare sequence where a mapping belongs.
         Fail (L, Load_Unknown_Condition, Loc);
         Push (L, F_Skip, Loc);
         return;
      end if;
      F.Expects_Key := True;
      case F.Kind is
         when F_Selection =>
            F.In_List := True;
            F.List_Count := 0;
            F.List_Has_Int := False;
            F.List_Has_Txt := False;
            --  Items arrive while the sequence's skip frame is on top;
            --  the scalar/sequence-end handlers redirect them to the
            --  selection frame below.
            Push (L, F_Skip, Loc);
         when others =>
            --  Sequences outside a selection value are not Phase 1
            --  (e.g. a list-valued condition); reject explicitly.
            Fail (L, Load_Unknown_Condition, Loc);
            Push (L, F_Skip, Loc);
      end case;
   end Handle_Seq_Value;

   procedure Load_Detection
     (YAML_Text : String;
      Rule      : out E.Compiled_Rule;
      Error     : out Load_Error;
      Detail    : out Natural)
   is
      P  : Instance;
      L  : Loader;
      Ev : Yaml.Event;
   begin
      Clear_Rule (Rule);
      P.Set_Input (YAML_Text);
      Push (L, F_Root, 0);
      loop
         begin
            Ev := P.Next;
         exception
            when Yaml.Lexer_Error | Yaml.Parser_Error =>
               Fail (L, Load_YAML_Error,
                     Natural (P.Current_Lexer_Token_Start.Index));
               exit;
         end;
         case Ev.Kind is
            when Yaml.Stream_End =>
               exit;
            when Yaml.Stream_Start | Yaml.Document_Start
               | Yaml.Document_End | Yaml.Annotation_Start
               | Yaml.Annotation_End =>
               null;
            when Yaml.Alias =>
               --  Anchors/aliases are valid YAML but outside Phase 1.
               Fail (L, Load_YAML_Error,
                     Natural (Ev.Start_Position.Index));
               exit;
            when Yaml.Scalar =>
               declare
                  S : constant String := Ev.Content.Value.Data.all;
                  Plain : constant Boolean :=
                    Ev.Scalar_Style = Yaml.Plain;
               begin
                  --  Route list items to the selection frame below the
                  --  sequence's skip frame.
                  if L.Depth >= 2
                    and then L.Frames (L.Depth).Kind = F_Skip
                    and then L.Frames (L.Depth - 1).In_List
                  then
                     Add_List_Item (L, L.Depth - 1, S, Plain,
                       Natural (Ev.Start_Position.Index));
                  else
                     Handle_Scalar
                       (L, S, Plain,
                        Natural (Ev.Start_Position.Index));
                  end if;
               end;
               exit when L.Error /= Load_Ok;
            when Yaml.Mapping_Start =>
               Handle_Map_Value (L, Natural (Ev.Start_Position.Index));
               exit when L.Error /= Load_Ok;
            when Yaml.Mapping_End =>
               Pop (L);
            when Yaml.Sequence_Start =>
               Handle_Seq_Value (L, Natural (Ev.Start_Position.Index));
               exit when L.Error /= Load_Ok;
            when Yaml.Sequence_End =>
               --  Close the list on the selection frame below the
               --  sequence's skip frame.
               if L.Depth >= 2
                 and then L.Frames (L.Depth).Kind = F_Skip
                 and then L.Frames (L.Depth - 1).In_List
               then
                  L.Frames (L.Depth - 1).In_List := False;
                  Close_List
                    (L, L.Depth - 1,
                     Natural (Ev.Start_Position.Index));
               end if;
               Pop (L);
               exit when L.Error /= Load_Ok;
         end case;
      end loop;
      if L.Error = Load_Ok then
         if L.Rule.Sel_Count = 0 then
            Fail (L, Load_Empty_Rule, 0);
         elsif not L.Have_Cond then
            Fail (L, Load_Empty_Rule, 0);
         else
            Parse_Condition (L);
         end if;
      end if;
      if L.Error = Load_Ok then
         Rule := L.Rule;
      else
         Clear_Rule (Rule);
      end if;
      Error := L.Error;
      Detail := L.Detail;
   exception
      when others =>
         Clear_Rule (Rule);
         Error := Load_Internal;
         Detail := 0;
   end Load_Detection;

end Sigma_Verdict.Boundary;
