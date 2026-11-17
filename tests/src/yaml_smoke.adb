with Ada.Text_IO;
with Sigma_Verdict.Boundary;
with Sigma_Verdict.Defaults;

--  Loads corpus rules end to end: YAML text -> Compiled_Rule -> verdict.
procedure Yaml_Smoke is

   use Sigma_Verdict.Defaults.Engine;
   use Sigma_Verdict.Boundary;

   Rule  : E.Compiled_Rule;
   Event : Event_Record;
   R     : Eval_Result;

   procedure Check (Cond : Boolean; Name : String) is
   begin
      if not Cond then
         raise Program_Error with "FAILED: " & Name;
      end if;
   end Check;

   procedure Load_File (Path : String; Want : Load_Error := Load_Ok) is
      F      : Ada.Text_IO.File_Type;
      Text   : String (1 .. 4096);
      Last   : Natural := 0;
      Error  : Load_Error;
      Detail : Natural;
   begin
      Ada.Text_IO.Open (F, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (F) loop
         declare
            Line : constant String := Ada.Text_IO.Get_Line (F);
         begin
            exit when Last + Line'Length + 1 > Text'Last;
            Text (Last + 1 .. Last + Line'Length) := Line;
            Last := Last + Line'Length;
            Text (Last + 1) := ASCII.LF;
            Last := Last + 1;
         end;
      end loop;
      Ada.Text_IO.Close (F);
      Load_Detection (Text (1 .. Last), Rule, Error, Detail);
      if Error /= Want then
         Ada.Text_IO.Put_Line ("UNEXPECTED LOAD: " & Load_Error'Image (Error) &
                                 " at" & Natural'Image (Detail));
         raise Program_Error with "yaml load failed: " & Path;
      end if;
   end Load_File;

   procedure Set_Event
     (Id      : Integer;
      Cmd     : String;
      Has_Cmd : Boolean := True;
      Ip      : String := "")
   is
   begin
      Event.Count :=
        1 + (if Has_Cmd then 1 else 0) + (if Ip'Length > 0 then 1 else 0);
      Event.Fields (1).Name := To_Field_Name ("EventID").Value;
      Event.Fields (1).Value := (Kind => V_Int, Int_Value => Id);
      if Has_Cmd then
         Event.Fields (2).Name := To_Field_Name ("CommandLine").Value;
         Event.Fields (2).Value :=
           (Kind => V_Text, Text_Value => To_Event_Text (Cmd).Value);
      end if;
      if Ip'Length > 0 then
         declare
            Slot : constant Positive := (if Has_Cmd then 3 else 2);
         begin
            Event.Fields (Slot).Name := To_Field_Name ("SourceIp").Value;
            Event.Fields (Slot).Value :=
              (Kind => V_Text, Text_Value => To_Event_Text (Ip).Value);
         end;
      end if;
   end Set_Event;

begin
   --  contains (existing rule).
   Load_File ("tests/corpus/4728_whoami.yml");
   Ada.Text_IO.Put_Line ("loaded selections:" &
                           Selection_Count'Image (Rule.Sel_Count));
   Set_Event (4728, "whoami /priv");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "whoami match");

   --  exists false: matches only when CommandLine is absent.
   Load_File ("tests/corpus/4728_nocmd.yml");
   Set_Event (4728, "", Has_Cmd => False);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "nocmd absent match");
   Set_Event (4728, "whoami");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "nocmd present no match");

   --  cased contains: exact case required.
   Load_File ("tests/corpus/4728_cased.yml");
   Set_Event (4728, "run WHOAMI");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "cased match");
   Set_Event (4728, "run whoami");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "cased mismatch");

   --  contains all: every list item must match.
   Load_File ("tests/corpus/4728_all.yml");
   Set_Event (4728, "whoami /priv");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "all both present");
   Set_Event (4728, "whoami /all");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "all one missing");

   --  ---- P1b: value views, end to end ----

   --  windash placeholder: the slash form matches, the literal
   --  reading stays intact.
   Load_File ("tests/corpus/4728_windash.yml");
   Set_Event (4728, "run /nop /quiet");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "windash e2e slash");
   Set_Event (4728, "run nop");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "windash e2e absent");

   --  wide replaces the value: interleaved bytes match, plain does not.
   Load_File ("tests/corpus/4728_wide.yml");
   Set_Event (4728, "xxA" & Character'Val (0) &
                      "B" & Character'Val (0) & "yy");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "wide e2e");
   Set_Event (4728, "xxAByy");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "wide e2e plain");

   --  utf16: exact bytes including the BOM.
   Load_File ("tests/corpus/4728_utf16.yml");
   Set_Event (4728, Character'Val (16#FF#) & Character'Val (16#FE#) &
                       "A" & Character'Val (0) &
                       "B" & Character'Val (0));
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "utf16 e2e");
   Set_Event (4728, "A" & Character'Val (0) &
                      "B" & Character'Val (0));
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "utf16 e2e no bom");

   --  base64: digest matches, the plain value does not.
   Load_File ("tests/corpus/4728_base64.yml");
   Set_Event (4728, "log d2hvYW1p end");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "base64 e2e");
   Set_Event (4728, "run whoami");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "base64 e2e plain");

   --  base64offset: every phase matches through the same rule.
   Load_File ("tests/corpus/4728_b64offset.yml");
   Set_Event (4728, "xxd2hvYW1p");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "b64offset e2e 0");
   Set_Event (4728, "xxdob2Fta");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "b64offset e2e 1");
   Set_Event (4728, "xx3aG9hbW");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "b64offset e2e 2");
   Set_Event (4728, "run whoami");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "b64offset e2e plain");

   --  Loader rejections for malformed view rules.
   Load_File ("tests/corpus/4728_windash4.yml", Load_Bad_Value);
   Ada.Text_IO.Put_Line ("rejected: windash over-limit");
   Load_File ("tests/corpus/4728_wide_bad.yml", Load_Bad_Value);
   Ada.Text_IO.Put_Line ("rejected: wide non-ascii");
   Load_File ("tests/corpus/4728_utf16le.yml", Load_Unknown_Modifier);
   Ada.Text_IO.Put_Line ("rejected: non-canonical utf16le");
   Load_File ("tests/corpus/4728_intview.yml", Load_Bad_Value);
   Ada.Text_IO.Put_Line ("rejected: view over integer");
   Load_File ("tests/corpus/4728_b64offset_list.yml",
              Load_Unsupported_Chain);
   Ada.Text_IO.Put_Line ("rejected: base64offset over list");

   --  ---- P2: comparisons + CIDR, end to end ----

   --  gt: strictly greater EventIDs match.
   Load_File ("tests/corpus/4728_gt.yml");
   Set_Event (4728, "run whoami");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "gt e2e match");
   Set_Event (4727, "run whoami");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "gt e2e no");

   --  IPv4 CIDR: inside matches, outside and garbage do not.
   Load_File ("tests/corpus/4728_cidr4.yml");
   Set_Event (4728, "x", Ip => "10.1.2.3");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "cidr4 e2e match");
   Set_Event (4728, "x", Ip => "11.0.0.1");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "cidr4 e2e no");
   Set_Event (4728, "x", Ip => "not.an.ip");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "cidr4 e2e malformed");

   --  IPv6 CIDR end to end.
   Load_File ("tests/corpus/4728_cidr6.yml");
   Set_Event (4728, "x", Ip => "2001:db8::1");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "cidr6 e2e match");
   Set_Event (4728, "x", Ip => "2001:db9::1");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "cidr6 e2e no");

   --  Host bits mask: 192.168.1.1/24 covers .99 (lenient, see DESIGN).
   Load_File ("tests/corpus/4728_cidr_host.yml");
   Set_Event (4728, "x", Ip => "192.168.1.99");
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "cidr host e2e");

   --  Loader rejections for malformed comparison/CIDR rules.
   Load_File ("tests/corpus/4728_gt_quoted.yml", Load_Bad_Integer);
   Ada.Text_IO.Put_Line ("rejected: quoted comparison value");
   Load_File ("tests/corpus/4728_gt_big.yml", Load_Bad_Integer);
   Ada.Text_IO.Put_Line ("rejected: over-range comparison value");
   Load_File ("tests/corpus/4728_cidr_bad.yml", Load_Bad_Value);
   Ada.Text_IO.Put_Line ("rejected: bad CIDR prefix");
   Load_File ("tests/corpus/4728_cidr_zeros.yml", Load_Bad_Value);
   Ada.Text_IO.Put_Line ("rejected: leading-zero octet");
   Load_File ("tests/corpus/4728_gtcidr.yml", Load_Unsupported_Chain);
   Ada.Text_IO.Put_Line ("rejected: mixed operator chain");

   Ada.Text_IO.Put_Line ("yaml_smoke: matched as expected");
end Yaml_Smoke;
