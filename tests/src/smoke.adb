with Sigma_Verdict.Defaults;
with Sigma_Verdict.IP;

--  Smoke test: EventID 4728 + CommandLine contains "whoami".
procedure Smoke is

   use Sigma_Verdict.Defaults.Engine;

   package IP renames Sigma_Verdict.IP;

   Rule  : Compiled_Rule;
   Event : Event_Record;
   R     : Eval_Result;

   procedure Check (Cond : Boolean; Name : String) is
   begin
      if not Cond then
         raise Program_Error with "FAILED: " & Name;
      end if;
   end Check;

begin
   --  selection:
   --    EventID: 4728
   --    CommandLine|contains: 'whoami'
   Rule.Sel_Count := 1;
   Rule.Selections (1).Name := To_Field_Name ("selection").Value;
   Rule.Selections (1).Field_Count := 2;

   Rule.Selections (1).Fields (1) :=
     (Field     => To_Field_Name ("EventID").Value,
      Modifiers => Empty_Modifiers,
       Expected  => (Kind => E_Int, Int_Value => 4728),
       Views     => (others => <>));

   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_Contains,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                     Single => To_Value_Text ("whoami").Value),
       Views     => (others => <>));

   Rule.Node_Count := 1;
   Rule.Nodes (1) := (Kind => N_Ref, Sel_Index => 1);
   Rule.Root := 1;

   --  Matching event.
   Event.Count := 2;
   Event.Fields (1).Name := To_Field_Name ("EventID").Value;
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4728);
   Event.Fields (2).Name := To_Field_Name ("CommandLine").Value;
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("C:\x whoami /all").Value);

   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "match");

   --  Wrong EventID must not match.
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4738);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "eventid mismatch");

   --  Missing whoami must not match.
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4728);
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("C:\x hostname").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "text mismatch");

   --  Regression: endswith with a needle longer than the haystack must
   --  fail closed (no match, no error), never raise on the offset
   --  subtraction.
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_Endswith,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                     Single => To_Value_Text ("whoami /all plus extra").Value),
       Views     => (others => <>));
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("whoami").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "endswith longer needle");

   --  Sanity: a genuine endswith still matches.
   Rule.Selections (1).Fields (2).Expected :=
     (Kind   => E_Text,
      Single => To_Value_Text ("whoami").Value);
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("run whoami").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "endswith match");

   --  ---- P1a: cased / all / exists ----

   --  cased: exact case required.
   Rule.Selections (1).Field_Count := 2;
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 2, Items => [1 => Mod_Cased,
                                          2 => Mod_Contains,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                     Single => To_Value_Text ("WHOAMI").Value),
       Views     => (others => <>));
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("run whoami").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "cased mismatch");
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("run WHOAMI").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "cased match");

   --  all: every list item must match (AND).
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 2, Items => [1 => Mod_Contains,
                                          2 => Mod_All,
                                          others => Mod_None]),
      Expected  => (Kind  => E_Text_List,
                    Items => [1 => To_Value_Text ("whoami").Value,
                              2 => To_Value_Text ("/priv").Value,
                              others => (Length => 0,
                                         Data   => [others => ' '])],
                     Count => 2),
       Views     => (others => <>));
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("whoami /priv").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "all both present");
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("whoami /all").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "all one missing");

   --  exists: presence only, polarity from the value.
   Rule.Selections (1).Field_Count := 1;
   Rule.Selections (1).Fields (1) :=
     (Field     => To_Field_Name ("EventID").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_Exists,
                                          others => Mod_None]),
       Expected  => (Kind => E_Int, Int_Value => 1),
       Views     => (others => <>));
   Event.Count := 2;
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4738);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "exists present");
   Rule.Selections (1).Field_Count := 2;
   Rule.Selections (1).Fields (1) :=
     (Field     => To_Field_Name ("EventID").Value,
      Modifiers => Empty_Modifiers,
       Expected  => (Kind => E_Int, Int_Value => 4728),
       Views     => (others => <>));
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_Exists,
                                          others => Mod_None]),
       Expected  => (Kind => E_Int, Int_Value => 0),
       Views     => (others => <>));
   Event.Count := 1;
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4728);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "exists false absent");
   Event.Count := 2;
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("x").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "exists false present");

   --  all over integers; field 2 reset to a benign matcher.
   Rule.Selections (1).Field_Count := 2;
   Rule.Selections (1).Fields (1) :=
     (Field     => To_Field_Name ("EventID").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_All,
                                          others => Mod_None]),
      Expected  => (Kind      => E_Int_List,
                    Ints      => [4728, 4738, others => 0],
                     Int_Count => 2),
       Views     => (others => <>));
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_Contains,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                     Single => To_Value_Text ("whoami").Value),
       Views     => (others => <>));
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4728);
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("run whoami").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "int all missing one");
   Rule.Selections (1).Fields (1).Modifiers := Empty_Modifiers;
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "int any present");

   --  Defence in depth: illegal hand-built chains fail closed.
   Rule.Selections (1).Fields (1) :=
     (Field     => To_Field_Name ("EventID").Value,
      Modifiers => Empty_Modifiers,
       Expected  => (Kind => E_Int, Int_Value => 4728),
       Views     => (others => <>));
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 2, Items => [1 => Mod_Contains,
                                          2 => Mod_Startswith,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                     Single => To_Value_Text ("whoami").Value),
       Views     => (others => <>));
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "two matchers unsupported");
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 2, Items => [1 => Mod_Exists,
                                          2 => Mod_Contains,
                                          others => Mod_None]),
       Expected  => (Kind => E_Int, Int_Value => 1),
       Views     => (others => <>));
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "exists plus matcher unsupported");
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_Exists,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                    Single => To_Value_Text ("maybe").Value),
      Views     => (others => <>));
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "exists non-bool unsupported");

   --  ---- P1b: value views ----

   --  windash: "-nop" carries a placeholder at position 1, so every
   --  5-way variant matches; a dash that is not a placeholder never
   --  expands.
   Rule.Selections (1).Field_Count := 2;
   Rule.Selections (1).Fields (1) :=
     (Field     => To_Field_Name ("EventID").Value,
      Modifiers => Empty_Modifiers,
      Expected  => (Kind => E_Int, Int_Value => 4728),
      Views     => (others => <>));
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 2, Items => [1 => Mod_Windash,
                                          2 => Mod_Contains,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                    Single => To_Value_Text ("-nop").Value),
      Views     => (others => <>));
   Rule.Selections (1).Fields (2).Views.Items (1).Dash_N := 1;
   Rule.Selections (1).Fields (2).Views.Items (1).Dash_At (1) := 1;
   Rule.Selections (1).Fields (2).Views.Count := 1;
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4728);
   Event.Fields (2).Value :=
     (Kind => V_Text,
      Text_Value => To_Event_Text ("run /nop /quiet").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "windash slash");
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("run -nop").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "windash dash");
   Event.Fields (2).Value :=
     (Kind => V_Text,
      Text_Value => To_Event_Text
        ("run " & Character'Val (16#E2#) & Character'Val (16#80#) &
         Character'Val (16#93#) & "nop end").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "windash en dash");
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("run nop").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "windash absent");

   --  "a-b" has no placeholder (the dash follows a word character),
   --  so the slash form must NOT match.
   Rule.Selections (1).Fields (2).Expected :=
     (Kind   => E_Text,
      Single => To_Value_Text ("a-b").Value);
   Rule.Selections (1).Fields (2).Views.Items (1).Dash_N := 0;
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("run a/b").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "windash non-placeholder");
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("run a-b").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "windash literal");

   --  wide replaces the value: interleaved bytes match, the plain
   --  form does not.
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 2, Items => [1 => Mod_Contains,
                                          2 => Mod_Wide,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                    Single => To_Value_Text ("AB").Value),
      Views     => (others => <>));
   Rule.Selections (1).Fields (2).Views.Items (1).Has_Alt := True;
   Rule.Selections (1).Fields (2).Views.Items (1).Alt :=
     To_View_Text ("A" & Character'Val (0) &
                   "B" & Character'Val (0)).Value;
   Rule.Selections (1).Fields (2).Views.Count := 1;
   Event.Fields (2).Value :=
     (Kind => V_Text,
      Text_Value => To_Event_Text
        ("xxA" & Character'Val (0) & "B" & Character'Val (0) & "yy").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "wide match");
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("xxAByy").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "wide plain no match");

   --  utf16 requires the BOM; utf16be swaps the interleave order.
   Rule.Selections (1).Fields (2).Modifiers :=
     (Count => 1, Items => [1 => Mod_UTF16, others => Mod_None]);
   Rule.Selections (1).Fields (2).Views.Items (1).Alt :=
     To_View_Text (Character'Val (16#FF#) & Character'Val (16#FE#) &
                   "A" & Character'Val (0) &
                   "B" & Character'Val (0)).Value;
   Event.Fields (2).Value :=
     (Kind => V_Text,
      Text_Value => To_Event_Text
        (Character'Val (16#FF#) & Character'Val (16#FE#) &
         "A" & Character'Val (0) & "B" & Character'Val (0)).Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "utf16 bom match");
   Event.Fields (2).Value :=
     (Kind => V_Text,
      Text_Value => To_Event_Text
        ("A" & Character'Val (0) & "B" & Character'Val (0)).Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "utf16 missing bom");
   Rule.Selections (1).Fields (2).Modifiers :=
     (Count => 2, Items => [1 => Mod_Contains,
                             2 => Mod_UTF16BE, others => Mod_None]);
   Rule.Selections (1).Fields (2).Views.Items (1).Alt :=
     To_View_Text (Character'Val (0) & "A" &
                   Character'Val (0) & "B").Value;
   Event.Fields (2).Value :=
     (Kind => V_Text,
      Text_Value => To_Event_Text
        ("x" & Character'Val (0) & "A" &
         Character'Val (0) & "B").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "utf16be match");

   --  base64 is encoded-only: the digest matches, "whoami" does not.
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 2, Items => [1 => Mod_Contains,
                                          2 => Mod_Base64,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                    Single => To_Value_Text ("whoami").Value),
      Views     => (others => <>));
   Rule.Selections (1).Fields (2).Views.Items (1).Has_Alt := True;
   Rule.Selections (1).Fields (2).Views.Items (1).Alt :=
     To_View_Text ("d2hvYW1p").Value;
   Rule.Selections (1).Fields (2).Views.Count := 1;
   Event.Fields (2).Value :=
     (Kind => V_Text,
      Text_Value => To_Event_Text ("log d2hvYW1p end").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "base64 match");
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("run whoami").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "base64 plain no match");

   --  base64offset: all three phases match independently.
   Rule.Selections (1).Fields (2).Modifiers :=
     (Count => 2, Items => [1 => Mod_Contains,
                             2 => Mod_Base64Offset, others => Mod_None]);
   Rule.Selections (1).Fields (2).Views.Has_Offset := True;
   Rule.Selections (1).Fields (2).Views.Items (1).Has_Alt := False;
   Rule.Selections (1).Fields (2).Views.Count := 1;
   Rule.Selections (1).Fields (2).Views.Offset (1) :=
     To_View_Text ("d2hvYW1p").Value;
   Rule.Selections (1).Fields (2).Views.Offset (2) :=
     To_View_Text ("dob2Fta").Value;
   Rule.Selections (1).Fields (2).Views.Offset (3) :=
     To_View_Text ("3aG9hbW").Value;
   Event.Fields (2).Value :=
     (Kind => V_Text,
      Text_Value => To_Event_Text ("xxd2hvYW1p").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "b64offset phase 0");
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("xxdob2Fta").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "b64offset phase 1");
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("xx3aG9hbW").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "b64offset phase 2");
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("run whoami").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "b64offset plain no match");

   --  all + wide: every list item is viewed, ANDed across items.
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 3, Items => [1 => Mod_Contains,
                                          2 => Mod_All,
                                          3 => Mod_Wide,
                                          others => Mod_None]),
      Expected  => (Kind  => E_Text_List,
                    Items => [1 => To_Value_Text ("AB").Value,
                              2 => To_Value_Text ("CD").Value,
                              others => (Length => 0,
                                         Data   => [others => ' '])],
                    Count => 2),
      Views     => (others => <>));
   Rule.Selections (1).Fields (2).Views.Items (1).Has_Alt := True;
   Rule.Selections (1).Fields (2).Views.Items (1).Alt :=
     To_View_Text ("A" & Character'Val (0) &
                   "B" & Character'Val (0)).Value;
   Rule.Selections (1).Fields (2).Views.Items (2).Has_Alt := True;
   Rule.Selections (1).Fields (2).Views.Items (2).Alt :=
     To_View_Text ("C" & Character'Val (0) &
                   "D" & Character'Val (0)).Value;
   Rule.Selections (1).Fields (2).Views.Count := 2;
   Event.Fields (2).Value :=
     (Kind => V_Text,
      Text_Value => To_Event_Text
        ("A" & Character'Val (0) & "B" & Character'Val (0) & " " &
         "C" & Character'Val (0) & "D" & Character'Val (0)).Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "all wide both");
   Event.Fields (2).Value :=
     (Kind => V_Text,
      Text_Value => To_Event_Text
        ("A" & Character'Val (0) & "B" & Character'Val (0) &
         " plain").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "all wide one missing");

   --  Defence in depth: illegal view shapes fail closed.
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 2, Items => [1 => Mod_Wide,
                                          2 => Mod_Base64,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                    Single => To_Value_Text ("AB").Value),
      Views     => (others => <>));
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "mixed views unsupported");
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 2, Items => [1 => Mod_Exists,
                                          2 => Mod_Wide,
                                          others => Mod_None]),
      Expected  => (Kind => E_Int, Int_Value => 1),
      Views     => (others => <>));
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "exists plus view unsupported");
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_Wide,
                                          others => Mod_None]),
      Expected  => (Kind => E_Int, Int_Value => 4728),
      Views     => (others => <>));
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "int with view unsupported");
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_Wide,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                    Single => To_Value_Text ("AB").Value),
      Views     => (others => <>));
   Rule.Selections (1).Fields (2).Views.Count := 2;
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "view count mismatch unsupported");
   Rule.Selections (1).Fields (2).Views.Count := 1;
   Rule.Selections (1).Fields (2).Views.Items (1).Has_Alt := True;
   Rule.Selections (1).Fields (2).Views.Items (1).Alt :=
     To_View_Text ("QUI=").Value;
   Rule.Selections (1).Fields (2).Views.Items (1).Dash_N := 1;
   Rule.Selections (1).Fields (2).Views.Items (1).Dash_At (1) := 1;
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "alts plus dashes unsupported");
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_Base64Offset,
                                          others => Mod_None]),
      Expected  => (Kind  => E_Text_List,
                    Items => [1 => To_Value_Text ("whoami").Value,
                              others => (Length => 0,
                                         Data   => [others => ' '])],
                    Count => 1),
      Views     => (others => <>));
   Rule.Selections (1).Fields (2).Views.Has_Offset := True;
   Rule.Selections (1).Fields (2).Views.Count := 1;
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "offset on list unsupported");

   --  ---- P2: comparisons + CIDR ----

   Rule.Selections (1).Field_Count := 2;
   Rule.Selections (1).Fields (1) :=
     (Field     => To_Field_Name ("EventID").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_GT,
                                          others => Mod_None]),
      Expected  => (Kind => E_Int, Int_Value => 4727),
      Views     => (others => <>));
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("CommandLine").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_Contains,
                                          others => Mod_None]),
      Expected  => (Kind   => E_Text,
                    Single => To_Value_Text ("whoami").Value),
      Views     => (others => <>));
   Event.Count := 2;
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4728);
   Event.Fields (2).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("run whoami").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "gt match");
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4727);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "gt equal no");
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4726);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "gt below no");

   --  The other three operators, one polarity each.
   Rule.Selections (1).Fields (1).Modifiers :=
     (Count => 1, Items => [1 => Mod_GTE, others => Mod_None]);
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4727);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "gte equal match");
   Rule.Selections (1).Fields (1).Modifiers :=
     (Count => 1, Items => [1 => Mod_LT, others => Mod_None]);
   Rule.Selections (1).Fields (1).Expected :=
     (Kind => E_Int, Int_Value => -5);
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => -10);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "lt negative match");
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 0);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "lt above no");
   Rule.Selections (1).Fields (1).Modifiers :=
     (Count => 1, Items => [1 => Mod_LTE, others => Mod_None]);
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => -5);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "lte equal match");

   --  Integer edges: extremes compare without wrapping.
   Rule.Selections (1).Fields (1).Modifiers :=
     (Count => 1, Items => [1 => Mod_GTE, others => Mod_None]);
   Rule.Selections (1).Fields (1).Expected :=
     (Kind => E_Int, Int_Value => Integer'Last);
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => Integer'Last);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "gte last match");
   Rule.Selections (1).Fields (1).Modifiers :=
     (Count => 1, Items => [1 => Mod_GT, others => Mod_None]);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "gt last no");

   --  Lists: OR by default, AND with all. Type mismatch stays a
   --  clean non-match even under operators.
   Rule.Selections (1).Fields (1) :=
     (Field     => To_Field_Name ("EventID").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_GT,
                                          others => Mod_None]),
      Expected  => (Kind      => E_Int_List,
                    Ints      => [4727, 4729, others => 0],
                    Int_Count => 2),
      Views     => (others => <>));
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4728);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "gt list or match");
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4726);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "gt list or no");
   Rule.Selections (1).Fields (1).Modifiers :=
     (Count => 2, Items => [1 => Mod_GT, 2 => Mod_All,
                            others => Mod_None]);
   Rule.Selections (1).Fields (1).Expected :=
     (Kind      => E_Int_List,
      Ints      => [4727, 4726, others => 0],
      Int_Count => 2);
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4728);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "gt all match");
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4727);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "gt all no");
   Event.Fields (1).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("4728").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "gt text event no");

   --  Illegal comparison shapes fail closed.
   Rule.Selections (1).Fields (1) :=
     (Field     => To_Field_Name ("EventID").Value,
      Modifiers => (Count => 2, Items => [1 => Mod_GT, 2 => Mod_Cased,
                                          others => Mod_None]),
      Expected  => (Kind => E_Int, Int_Value => 4727),
      Views     => (others => <>));
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4728);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "gt plus cased unsupported");
   Rule.Selections (1).Fields (1).Modifiers :=
     (Count => 2, Items => [1 => Mod_GT, 2 => Mod_Wide,
                            others => Mod_None]);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "gt plus view unsupported");
   Rule.Selections (1).Fields (1).Modifiers :=
     (Count => 2, Items => [1 => Mod_GT, 2 => Mod_Contains,
                            others => Mod_None]);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "gt plus matcher unsupported");
   Rule.Selections (1).Fields (1) :=
     (Field     => To_Field_Name ("EventID").Value,
      Modifiers => Empty_Modifiers,
      Expected  => (Kind => E_Int, Int_Value => 4727),
      Views     => (others => <>));
   Rule.Selections (1).Fields (1).Views.Count := 1;
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "int with views unsupported");

   --  ---- CIDR ----

   Event.Count := 3;
   Event.Fields (3).Name := To_Field_Name ("SourceIp").Value;
   Rule.Selections (1).Field_Count := 2;
   Rule.Selections (1).Fields (1) :=
     (Field     => To_Field_Name ("EventID").Value,
      Modifiers => Empty_Modifiers,
      Expected  => (Kind => E_Int, Int_Value => 4728),
      Views     => (others => <>));
   Event.Fields (1).Value := (Kind => V_Int, Int_Value => 4728);
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("SourceIp").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_CIDR,
                                          others => Mod_None]),
      Expected  => (Kind   => E_CIDR,
                    Net    => IP.Parse_Network ("10.0.0.0/8")),
      Views     => (others => <>));
   Event.Fields (3).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("10.1.2.3").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "cidr v4 match");
   Event.Fields (3).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("11.0.0.1").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "cidr v4 no");
   Event.Fields (3).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("not.an.ip").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "cidr malformed event no");

   --  Host bits mask (lenient): 192.168.1.1/24 covers .99.
   Rule.Selections (1).Fields (2).Expected :=
     (Kind => E_CIDR, Net => IP.Parse_Network ("192.168.1.1/24"));
   Event.Fields (3).Value :=
     (Kind => V_Text,
      Text_Value => To_Event_Text ("192.168.1.99").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "cidr masked match");
   Event.Fields (3).Value :=
     (Kind => V_Text,
      Text_Value => To_Event_Text ("192.168.2.99").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "cidr masked no");

   --  Edges: /32 exact, /0 matches everything, bare IP is /32.
   Rule.Selections (1).Fields (2).Expected :=
     (Kind => E_CIDR, Net => IP.Parse_Network ("1.2.3.4/32"));
   Event.Fields (3).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("1.2.3.4").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "cidr /32 match");
   Event.Fields (3).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("1.2.3.5").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "cidr /32 no");
   Rule.Selections (1).Fields (2).Expected :=
     (Kind => E_CIDR, Net => IP.Parse_Network ("0.0.0.0/0"));
   Event.Fields (3).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("203.0.113.7").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "cidr /0 match");
   Rule.Selections (1).Fields (2).Expected :=
     (Kind => E_CIDR, Net => IP.Parse_Network ("1.2.3.4"));
   Event.Fields (3).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("1.2.3.4").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "cidr bare match");

   --  IPv6: full, compressed, and embedded-v4 forms.
   Rule.Selections (1).Fields (2).Expected :=
     (Kind => E_CIDR, Net => IP.Parse_Network ("2001:db8::/32"));
   Event.Fields (3).Value :=
     (Kind => V_Text,
      Text_Value => To_Event_Text ("2001:db8::1").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "cidr v6 match");
   Event.Fields (3).Value :=
     (Kind => V_Text,
      Text_Value => To_Event_Text ("2001:db9::1").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "cidr v6 no");
   Event.Fields (3).Value :=
     (Kind => V_Text,
      Text_Value => To_Event_Text ("::ffff:10.0.0.1").Value);
   Rule.Selections (1).Fields (2).Expected :=
     (Kind => E_CIDR, Net => IP.Parse_Network ("10.0.0.0/8"));
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "cidr v4 mapped");
   Event.Fields (3).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("::1").Value);
   Rule.Selections (1).Fields (2).Expected :=
     (Kind => E_CIDR, Net => IP.Parse_Network ("10.0.0.0/8"));
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "cidr v6 vs v4 rule no");
   Event.Fields (3).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("10.0.0.1").Value);
   Rule.Selections (1).Fields (2).Expected :=
     (Kind => E_CIDR,
      Net    => IP.Parse_Network ("::ffff:10.0.0.0/104"));
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched,
          "cidr v4 in v6 range");

   --  Version mismatch the other way, and wrong event type.
   Rule.Selections (1).Fields (2).Expected :=
     (Kind => E_CIDR, Net => IP.Parse_Network ("::/0"));
   Event.Fields (3).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("10.0.0.1").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "cidr v6 /0 all");
   Event.Fields (3).Value :=
     (Kind => V_Int, Int_Value => 10);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched,
          "cidr int event no");

   --  Lists: OR by default, AND with all.
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("SourceIp").Value,
      Modifiers => (Count => 1, Items => [1 => Mod_CIDR,
                                          others => Mod_None]),
      Expected  => (Kind      => E_CIDR_List,
                    Nets      => [1 => IP.Parse_Network ("10.0.0.0/8"),
                                  2 => IP.Parse_Network ("192.168.0.0/16"),
                                  others => <>],
                    Net_Count => 2),
      Views     => (others => <>));
   Event.Fields (3).Value :=
     (Kind => V_Text,
      Text_Value => To_Event_Text ("192.168.5.5").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "cidr list or");
   Event.Fields (3).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("172.16.0.1").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "cidr list no");
   Rule.Selections (1).Fields (2).Modifiers :=
     (Count => 2, Items => [1 => Mod_CIDR, 2 => Mod_All,
                            others => Mod_None]);
   Rule.Selections (1).Fields (2).Expected :=
     (Kind      => E_CIDR_List,
      Nets      => [1 => IP.Parse_Network ("10.0.0.0/8"),
                    2 => IP.Parse_Network ("10.1.0.0/16"),
                    others => <>],
      Net_Count => 2);
   Event.Fields (3).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("10.1.2.3").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then R.Matched, "cidr all match");
   Event.Fields (3).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("10.2.2.3").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_None and then not R.Matched, "cidr all no");

   --  Illegal CIDR shapes fail closed.
   Rule.Selections (1).Fields (2) :=
     (Field     => To_Field_Name ("SourceIp").Value,
      Modifiers => (Count => 2, Items => [1 => Mod_CIDR, 2 => Mod_Wide,
                                          others => Mod_None]),
      Expected  => (Kind   => E_CIDR,
                    Net    => IP.Parse_Network ("10.0.0.0/8")),
      Views     => (others => <>));
   Event.Fields (3).Value :=
     (Kind => V_Text, Text_Value => To_Event_Text ("10.1.2.3").Value);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "cidr plus view unsupported");
   Rule.Selections (1).Fields (2).Modifiers :=
     (Count => 2, Items => [1 => Mod_CIDR, 2 => Mod_GT,
                            others => Mod_None]);
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "cidr plus comparison unsupported");
   Rule.Selections (1).Fields (2).Modifiers :=
     (Count => 1, Items => [1 => Mod_CIDR, others => Mod_None]);
   Rule.Selections (1).Fields (2).Expected :=
     (Kind => E_CIDR, Net => (Base   => (Length => 0,
                                         Bytes  => [others => 0]),
                              Prefix => 0));
   R := Evaluate (Rule, Event);
   Check (R.Error = Error_Unsupported_Modifier and then not R.Matched,
          "invalid stored net unsupported");
end Smoke;
