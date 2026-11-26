-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

import Shirudo.Events
import Shirudo.Measured

/-!
The eventlog's records as shirudo writes them and as `upatches_line()` of
util/eventlog.c reads them back into the events `Shirudo.Measured` folds.
`walk_lines()` reads each line's `type` and `boot_id` to tell an init
record from the others, and `upatches_line()` reads its `type`, an init
record's `set` and the `upatch` member, through `json_parse()`.

A line is the JSON object `json_parse()` takes from it: `JVal` holds the
strings as `parse_string()` decodes them, which `Shirudo.JsonString`
proves exact for every string `json_str()` writes. The model follows the
schema dispatch of `parse_object()`, `parse_value()` and
`parse_array_into()` member by member: a key the schema names is taken
once, a second time is refused; a string goes into its buffer only when it
fits, with its NUL; `null` names a key and writes nothing; a value of
another type is refused; a key the schema does not name is skipped. The
set entries and the `upatch` member share the name and payload buffers,
and each entry's callback, `upatches_set_entry()`, takes the entry only
when it named both fields itself. The limits on a key's, a string's and
a document's length, on depth and on the number of keys, which only
refuse more, are left out.

For every record the writer gives, with an upatch name that
`upatch_name_valid()` accepts and its payload's 64 hex digits:
`read_upatch`, `read_init`, `read_key`, `read_tree` show that the reader
returns exactly the events of `Measured.Record.events`, whatever the
record's other fields hold. For every line at all, `load_from_fields` and
`unload_from_fields` show that a load or an unload comes only from the
fields that name it: the `type` and the `upatch` member's `name` and
`payload_sha256` of that line, or an entry of an init record's `set`,
each a name and a payload `upatch_member_valid()` accepts; and
`init_from_type` that an init event comes only from a `type` of `init`.
-/

namespace Shirudo.EventlogRecord
open Shirudo

abbrev Str := List UInt8

/-- A JSON value as `json_parse()` reads it, its strings decoded. -/
inductive JVal where
  | str (s : Str)
  | num (n : Int)
  | bool (b : Bool)
  | null
  | arr (xs : List JVal)
  | obj (ms : List (Str × JVal))

def kType : Str := Events.ascii "type"
def kBootId : Str := Events.ascii "boot_id"
def kSet : Str := Events.ascii "set"
def kUpatch : Str := Events.ascii "upatch"
def kName : Str := Events.ascii "name"
def kPayload : Str := Events.ascii "payload_sha256"
def tInit : Str := Events.ascii "init"
def tLoad : Str := Events.ascii "upatch_load"
def tUnload : Str := Events.ascii "upatch_unload"

/-- What `parse_string()` writes into a buffer of `cap` bytes: a string
without a NUL, which the parser never decodes, and room for its own. -/
def fits (s : Str) (cap : Nat) : Bool := !s.contains 0 && decide (s.length < cap)

/-- `hex_nibble()` finds a digit of either case. -/
def hexDigit (c : UInt8) : Bool :=
  (48 ≤ c && c ≤ 57) || (65 ≤ c && c ≤ 70) || (97 ≤ c && c ≤ 102)

/-- `upatch_member_valid()`: a name `upatch_name_valid()` accepts and a
payload `hex_decode()` takes as 32 bytes. -/
def memberValid (name payload : Str) : Bool :=
  Events.nameValid name && decide (payload.length = 64) &&
    payload.all hexDigit

/-! ### The reader -/

/-- The name and payload buffers, with what the entry schema
`{name, payload_sha256}` has named and seen in the object at hand. -/
structure Entry where
  name : Str
  payload : Str
  namedName : Bool := false
  seenName : Bool := false
  namedPayload : Bool := false
  seenPayload : Bool := false

/-- One member of an object read with the entry schema. -/
def entryMember (e : Entry) (m : Str × JVal) : Option Entry :=
  if m.1 = kName then
    if e.namedName then none else
    match m.2 with
    | .str s => if fits s 257 then
        some { e with name := s, namedName := true, seenName := true }
      else none
    | .null => some { e with namedName := true }
    | _ => none
  else if m.1 = kPayload then
    if e.namedPayload then none else
    match m.2 with
    | .str s => if fits s 65 then
        some { e with payload := s, namedPayload := true, seenPayload := true }
      else none
    | .null => some { e with namedPayload := true }
    | _ => none
  else some e

/-- `parse_object()` with the entry schema, its seen flags reset, into
the buffers as they are. -/
def entryObj (name payload : Str) (ms : List (Str × JVal)) : Option Entry :=
  ms.foldlM entryMember { name := name, payload := payload }

/-- What `upatches_line()` keeps while `json_parse()` reads a line. -/
structure Top where
  type : Str := []
  name : Str := []
  payload : Str := []
  namedType : Bool := false
  namedSet : Bool := false
  namedUpatch : Bool := false
  upatchSeen : Bool := false
  loads : List (Str × Str) := []

/-- One entry of `set`, then `upatches_set_entry()`. -/
def setElem (t : Top) : JVal → Option Top
  | .obj ms =>
    match entryObj t.name t.payload ms with
    | none => none
    | some e =>
      if e.seenName && e.seenPayload && memberValid e.name e.payload then
        some { t with
          name := []
          payload := []
          loads := t.loads ++ [(e.name, e.payload)] }
      else none
  | _ => none

/-- One member of the line, with `set` named only in an init record. -/
def topMember (isInit : Bool) (t : Top) (m : Str × JVal) : Option Top :=
  if m.1 = kType then
    if t.namedType then none else
    match m.2 with
    | .str s => if fits s 32 then some { t with type := s, namedType := true }
      else none
    | .null => some { t with namedType := true }
    | _ => none
  else if isInit && m.1 = kSet then
    if t.namedSet then none else
    match m.2 with
    | .arr xs => xs.foldlM setElem { t with namedSet := true }
    | .null => some { t with namedSet := true }
    | _ => none
  else if m.1 = kUpatch then
    if t.namedUpatch then none else
    match m.2 with
    | .obj ms =>
      match entryObj t.name t.payload ms with
      | none => none
      | some e => some { t with
          name := e.name
          payload := e.payload
          namedUpatch := true
          upatchSeen := true }
    | .null => some { t with namedUpatch := true }
    | _ => none
  else some t

/-- `upatches_line()`: an init record gives the init event and a load for
each entry of its set; a load or an unload record its event; any other
record nothing; `none` is an error. -/
def upatchesLine (isInit : Bool) : JVal → Option (List Measured.Event)
  | .obj ms =>
    match ms.foldlM (topMember isInit) {} with
    | none => none
    | some t =>
      if isInit then some (.init :: t.loads.map fun p => .load p.1 p.2)
      else if t.type = tLoad || t.type = tUnload then
        if t.upatchSeen && memberValid t.name t.payload then
          some [if t.type = tLoad then .load t.name t.payload
            else .unload t.name t.payload]
        else none
      else some []
  | _ => none

/-- `walk_lines()`'s schema `{boot_id, type}`: the type it reads. -/
structure Walk where
  type : Str := []
  namedBoot : Bool := false
  namedType : Bool := false

def walkMember (w : Walk) (m : Str × JVal) : Option Walk :=
  if m.1 = kBootId then
    if w.namedBoot then none else
    match m.2 with
    | .str s => if fits s 64 then some { w with namedBoot := true } else none
    | .null => some { w with namedBoot := true }
    | _ => none
  else if m.1 = kType then
    if w.namedType then none else
    match m.2 with
    | .str s => if fits s 32 then some { w with type := s, namedType := true }
      else none
    | .null => some { w with namedType := true }
    | _ => none
  else some w

/-- `walk_lines()` then `upatches_line()`: a line is an init record when
its `type` is `init`. -/
def readLine : JVal → Option (List Measured.Event)
  | .obj ms =>
    match ms.foldlM walkMember {} with
    | none => none
    | some w => upatchesLine (w.type = tInit) (.obj ms)
  | _ => none

/-! ### The writer -/

/-- `eventlog_record_open()`: the members every record starts with. -/
def openMembers (type digest ts bootId : Str) : List (Str × JVal) :=
  [(Events.ascii "schema", .num 1), (Events.ascii "ts", .str ts),
   (Events.ascii "nv_index", .str (Events.ascii "0x01818E00")),
   (Events.ascii "alg", .str (Events.ascii "sha256")),
   (Events.ascii "digest", .str digest), (kType, .str type),
   (kBootId, .str bootId)]

/-- The `reason` an unload by a revocation adds. -/
def reasonMembers : Option Str → List (Str × JVal)
  | some r => [(Events.ascii "reason", .str r)]
  | none => []

/-- `format_upatch_event()` of builtin-upatch.c. -/
def upatchRecord (load : Bool) (name payload digest ts bootId : Str)
    (reason : Option Str) : JVal :=
  .obj (openMembers (if load then tLoad else tUnload) digest ts bootId ++
    ((kUpatch, .obj [(kName, .str name), (kPayload, .str payload)]) ::
      reasonMembers reason))

/-- `append_init_event()` of builtin-init.c: the restored set and the
register's binding. -/
def initRecord (set : List (Str × Str)) (digest ts bootId : Str)
    (reset pcr phase : Int)
    (cert setDigest treeRoot pcrBefore phaseBefore boundIn nvName writer
      anchor anchorDigest chain : Str) (certs : List Str) : JVal :=
  .obj (openMembers tInit digest ts bootId ++
    [(Events.ascii "tpm_reset_count", .num reset),
     (Events.ascii "cert_sha256", .str cert),
     (Events.ascii "certs", .arr (certs.map .str)),
     (Events.ascii "set_digest", .str setDigest),
     (Events.ascii "tree_root", .str treeRoot),
     (kSet, .arr (set.map fun p => .obj [(kName, .str p.1), (kPayload, .str p.2)])),
     (Events.ascii "pcr", .num pcr),
     (Events.ascii "pcr_before", .str pcrBefore),
     (Events.ascii "phase_pcr", .num phase),
     (Events.ascii "phase_before", .str phaseBefore),
     (Events.ascii "bound_in", .str boundIn),
     (Events.ascii "nv_name", .str nvName),
     (Events.ascii "nv_writer_public", .str writer),
     (Events.ascii "anchor", .str anchor),
     (Events.ascii "anchor_digest", .str anchorDigest),
     (Events.ascii "chain", .str chain)])

/-- `append_key_event()` of builtin-keys.c. -/
def keyRecord (digest ts bootId fingerprint cert : Str) : JVal :=
  .obj (openMembers (Events.ascii "key_revoke") digest ts bootId ++
    [(Events.ascii "key", .obj [(Events.ascii "fingerprint", .str fingerprint),
      (Events.ascii "cert_sha256", .str cert)])])

/-- `tree_event_append()` of builtin-bpm.c. -/
def treeRecord (digest ts bootId op id operation chain : Str) (seq : Int) :
    JVal :=
  .obj (openMembers (Events.ascii "tree_op") digest ts bootId ++
    [(Events.ascii "tree", .obj [(Events.ascii "seq", .num seq),
      (Events.ascii "op", .str op), (Events.ascii "id", .str id),
      (Events.ascii "operation_digest", .str operation)]),
     (Events.ascii "chain", .str chain)])

/-! ### The keys apart -/

theorem kPayload_ne : kPayload ≠ kName := by decide
theorem kSet_ne : kSet ≠ kType := by decide
theorem kUpatch_ne_type : kUpatch ≠ kType := by decide
theorem kUpatch_ne_set : kUpatch ≠ kSet := by decide
theorem kType_ne_boot : kType ≠ kBootId := by decide
theorem kBoot_ne_type : kBootId ≠ kType := by decide
theorem kBoot_ne_set : kBootId ≠ kSet := by decide
theorem kBoot_ne_upatch : kBootId ≠ kUpatch := by decide

/-! ### Every record reads back as its events -/

theorem fits_name {n : Str} (h : Events.NameAdmitted n) : fits n 257 = true := by
  obtain ⟨hv, hl⟩ := h
  have h0 : ¬ (0 : UInt8) ∈ n := fun hm =>
    (Events.nameChar_ne (Events.nameValid_mem hv 0 hm)).1 rfl
  simp [fits, Events.nameMax] at *
  exact ⟨h0, by omega⟩

theorem fits_payload {p : Str} (hp : p.length = 64) (hh : p.all hexDigit = true) :
    fits p 65 = true := by
  have h0 : ¬ (0 : UInt8) ∈ p := fun hm => by
    have := List.all_eq_true.1 hh 0 hm
    simp [hexDigit] at this
  simp [fits, hp, h0]

/-- What the writer gives a upatch: a name `upatch_name_valid()` accepts,
of at most `UPATCH_NAME_MAX` bytes, and `hex_encode()`'s 64 digits. -/
def Written (n p : Str) : Prop :=
  Events.NameAdmitted n ∧ p.length = 64 ∧ p.all hexDigit = true

theorem written_valid {n p : Str} (h : Written n p) : memberValid n p = true := by
  obtain ⟨hn, hp, hh⟩ := h
  simp [memberValid, hn.1, hp, hh]

/-- A key neither reader names. -/
def Skips (k : Str) : Bool :=
  k != kType && k != kBootId && k != kSet && k != kUpatch

/-- A key the walk does not name. -/
def WalkSkips (k : Str) : Bool := k != kType && k != kBootId

theorem walk_skip : ∀ (l : List (Str × JVal)) (w : Walk),
    (l.map Prod.fst).all WalkSkips = true → l.foldlM walkMember w = some w
  | [], _, _ => rfl
  | m :: l, w, h => by
    simp only [List.map_cons, List.all_cons, Bool.and_eq_true] at h
    obtain ⟨hm, hl⟩ := h
    simp only [WalkSkips, Bool.and_eq_true, bne_iff_ne, ne_eq] at hm
    have hstep : walkMember w m = some w := by
      simp [walkMember, hm.1, hm.2]
    simp only [List.foldlM_cons, hstep, Option.bind_eq_bind, Option.bind_some]
    exact walk_skip l w hl

theorem top_skip (isInit : Bool) : ∀ (l : List (Str × JVal)) (t : Top),
    (l.map Prod.fst).all Skips = true → l.foldlM (topMember isInit) t = some t
  | [], _, _ => rfl
  | m :: l, t, h => by
    simp only [List.map_cons, List.all_cons, Bool.and_eq_true] at h
    obtain ⟨hm, hl⟩ := h
    simp only [Skips, Bool.and_eq_true, bne_iff_ne, ne_eq] at hm
    have hstep : topMember isInit t m = some t := by
      simp [topMember, hm.1.1.1, hm.1.2, hm.2]
    simp only [List.foldlM_cons, hstep, Option.bind_eq_bind, Option.bind_some]
    exact top_skip isInit l t hl

theorem walk_type_step (w : Walk) (s : Str) (hn : w.namedType = false)
    (hf : fits s 32 = true) :
    walkMember w (kType, .str s) = some { w with type := s, namedType := true } := by
  simp [walkMember, hn, hf, kType_ne_boot]

theorem walk_boot_step (w : Walk) (s : Str) (hn : w.namedBoot = false)
    (hf : fits s 64 = true) :
    walkMember w (kBootId, .str s) = some { w with namedBoot := true } := by
  simp [walkMember, hn, hf]

theorem top_type_step (isInit : Bool) (t : Top) (s : Str)
    (hn : t.namedType = false) (hf : fits s 32 = true) :
    topMember isInit t (kType, .str s) =
      some { t with type := s, namedType := true } := by
  simp [topMember, hn, hf]

theorem top_boot_step (isInit : Bool) (t : Top) (s : Str) :
    topMember isInit t (kBootId, .str s) = some t := by
  simp [topMember, kBoot_ne_type, kBoot_ne_set, kBoot_ne_upatch]

theorem top_upatch_step (isInit : Bool) (t : Top) (ums : List (Str × JVal))
    (e : Entry) (hn : t.namedUpatch = false)
    (he : entryObj t.name t.payload ums = some e) :
    topMember isInit t (kUpatch, .obj ums) =
      some { t with
        name := e.name
        payload := e.payload
        namedUpatch := true
        upatchSeen := true } := by
  simp [topMember, hn, he, kUpatch_ne_type, kUpatch_ne_set]

theorem top_set_step (t : Top) (xs : List JVal) (hn : t.namedSet = false) :
    topMember true t (kSet, .arr xs) = xs.foldlM setElem { t with namedSet := true } := by
  simp [topMember, hn, kSet_ne]

theorem entry_pair (n0 p0 n p : Str) (hn : fits n 257 = true)
    (hp : fits p 65 = true) :
    entryObj n0 p0 [(kName, .str n), (kPayload, .str p)] =
      some { name := n
             payload := p
             namedName := true
             seenName := true
             namedPayload := true
             seenPayload := true } := by
  simp [entryObj, List.foldlM, entryMember, hn, hp, kPayload_ne]

/-- The members every record starts with, but its `type` and `boot_id`. -/
def openHead (digest ts : Str) : List (Str × JVal) :=
  [(Events.ascii "schema", .num 1), (Events.ascii "ts", .str ts),
   (Events.ascii "nv_index", .str (Events.ascii "0x01818E00")),
   (Events.ascii "alg", .str (Events.ascii "sha256")),
   (Events.ascii "digest", .str digest)]

theorem openMembers_eq (type digest ts bootId : Str) :
    openMembers type digest ts bootId =
      openHead digest ts ++ [(kType, .str type), (kBootId, .str bootId)] := rfl

theorem openHead_skips (digest ts : Str) :
    ((openHead digest ts).map Prod.fst).all Skips = true := by
  show ([Events.ascii "schema", Events.ascii "ts", Events.ascii "nv_index",
    Events.ascii "alg", Events.ascii "digest"] : List Str).all Skips = true
  decide

theorem openHead_walkSkips (digest ts : Str) :
    ((openHead digest ts).map Prod.fst).all WalkSkips = true := by
  show ([Events.ascii "schema", Events.ascii "ts", Events.ascii "nv_index",
    Events.ascii "alg", Events.ascii "digest"] : List Str).all WalkSkips = true
  decide

/-- The walk reads a record's type from its first members alone. -/
theorem walk_open (type digest ts bootId : Str) (rest : List (Str × JVal))
    (ht : fits type 32 = true) (hb : fits bootId 64 = true)
    (hr : (rest.map Prod.fst).all WalkSkips = true) :
    (openMembers type digest ts bootId ++ rest).foldlM walkMember {} =
      some { type := type, namedType := true, namedBoot := true } := by
  rw [openMembers_eq, List.append_assoc, List.foldlM_append,
    walk_skip _ _ (openHead_walkSkips digest ts), Option.bind_eq_bind,
    Option.bind_some, List.cons_append, List.foldlM_cons,
    walk_type_step _ _ rfl ht, Option.bind_eq_bind, Option.bind_some,
    List.cons_append, List.nil_append, List.foldlM_cons,
    walk_boot_step _ _ rfl hb, Option.bind_eq_bind, Option.bind_some,
    walk_skip _ _ hr]

theorem top_open (isInit : Bool) (type digest ts bootId : Str)
    (ht : fits type 32 = true) :
    (openMembers type digest ts bootId).foldlM (topMember isInit) {} =
      some { type := type, namedType := true } := by
  rw [openMembers_eq, List.foldlM_append,
    top_skip _ _ _ (openHead_skips digest ts), Option.bind_eq_bind,
    Option.bind_some, List.foldlM_cons, top_type_step _ _ _ rfl ht,
    Option.bind_eq_bind, Option.bind_some, List.foldlM_cons,
    top_boot_step, Option.bind_eq_bind, Option.bind_some]
  rfl

theorem tLoad_fits : fits tLoad 32 = true := by decide
theorem tUnload_fits : fits tUnload 32 = true := by decide
theorem tInit_fits : fits tInit 32 = true := by decide
theorem tLoad_ne_init : tLoad ≠ tInit := by decide
theorem tUnload_ne_init : tUnload ≠ tInit := by decide
theorem tUnload_ne_load : tUnload ≠ tLoad := by decide

theorem reason_skips (reason : Option Str) :
    ((reasonMembers reason).map Prod.fst).all Skips = true := by
  cases reason
  · rfl
  · show ([Events.ascii "reason"] : List Str).all Skips = true
    decide

theorem upatch_walkSkips (name payload : Str) (reason : Option Str) :
    ((((kUpatch, JVal.obj [(kName, .str name), (kPayload, .str payload)]) ::
      reasonMembers reason)).map Prod.fst).all WalkSkips = true := by
  cases reason
  · show ([kUpatch] : List Str).all WalkSkips = true
    decide
  · show ([kUpatch, Events.ascii "reason"] : List Str).all WalkSkips = true
    decide

/-- A load or an unload record reads back as its event, whatever its
digest, time, boot ID and reason. -/
theorem read_upatch (load : Bool) (name payload digest ts bootId : Str)
    (reason : Option Str) (hw : Written name payload)
    (hb : fits bootId 64 = true) :
    readLine (upatchRecord load name payload digest ts bootId reason) =
      some [if load then .load name payload else .unload name payload] := by
  have hname := fits_name hw.1
  have hpay := fits_payload hw.2.1 hw.2.2
  have hmv := written_valid hw
  have hty : fits (if load then tLoad else tUnload) 32 = true := by
    cases load
    · exact tUnload_fits
    · exact tLoad_fits
  have hwalk := walk_open (if load then tLoad else tUnload) digest ts bootId
    _ hty hb (upatch_walkSkips name payload reason)
  have hentry := entry_pair [] [] name payload hname hpay
  have htop : (openMembers (if load then tLoad else tUnload) digest ts bootId ++
      ((kUpatch, JVal.obj [(kName, .str name), (kPayload, .str payload)]) ::
        reasonMembers reason)).foldlM (topMember false) {} =
      some { type := if load then tLoad else tUnload
             namedType := true
             name := name
             payload := payload
             namedUpatch := true
             upatchSeen := true } := by
    rw [List.foldlM_append, top_open _ _ _ _ _ hty, Option.bind_eq_bind,
      Option.bind_some, List.foldlM_cons,
      top_upatch_step _ _ _ _ rfl hentry, Option.bind_eq_bind,
      Option.bind_some, top_skip _ _ _ (reason_skips reason)]
  have hni : decide ((if load then tLoad else tUnload) = tInit) = false := by
    cases load
    · simpa using tUnload_ne_init
    · simpa using tLoad_ne_init
  unfold readLine upatchRecord
  dsimp only
  rw [hwalk]
  dsimp only
  rw [hni]
  unfold upatchesLine
  dsimp only
  rw [htop]
  cases load
  · simp [hmv, tUnload_ne_load]
  · simp [hmv]

/-- The entries of a written set: each taken, the buffers cleared. -/
theorem set_fold (set : List (Str × Str)) (hset : ∀ q ∈ set, Written q.1 q.2)
    (t : Top) (hn : t.name = []) (hp : t.payload = []) :
    (set.map fun q => JVal.obj [(kName, .str q.1), (kPayload, .str q.2)]).foldlM
      setElem t = some { t with loads := t.loads ++ set } := by
  induction set generalizing t with
  | nil => cases t; simp_all
  | cons q set ih =>
    have hq := hset q List.mem_cons_self
    have hstep : setElem t (.obj [(kName, .str q.1), (kPayload, .str q.2)]) =
        some { t with name := [], payload := [], loads := t.loads ++ [q] } := by
      simp [setElem, entry_pair _ _ _ _ (fits_name hq.1)
        (fits_payload hq.2.1 hq.2.2), written_valid hq]
    simp only [List.map_cons, List.foldlM_cons, hstep, Option.bind_eq_bind,
      Option.bind_some]
    rw [ih (fun r hr => hset r (List.mem_cons_of_mem q hr)) _ rfl rfl]
    cases t
    simp only at hn hp
    subst hn hp
    simp

/-- The members of an init record after its first ones, before its set. -/
def initMid (reset : Int) (cert setDigest treeRoot : Str) (certs : List Str) :
    List (Str × JVal) :=
  [(Events.ascii "tpm_reset_count", .num reset),
   (Events.ascii "cert_sha256", .str cert),
   (Events.ascii "certs", .arr (certs.map .str)),
   (Events.ascii "set_digest", .str setDigest),
   (Events.ascii "tree_root", .str treeRoot)]

/-- The members of an init record after its set. -/
def initTail (pcr phase : Int) (pcrBefore phaseBefore boundIn nvName writer
    anchor anchorDigest chain : Str) : List (Str × JVal) :=
  [(Events.ascii "pcr", .num pcr),
   (Events.ascii "pcr_before", .str pcrBefore),
   (Events.ascii "phase_pcr", .num phase),
   (Events.ascii "phase_before", .str phaseBefore),
   (Events.ascii "bound_in", .str boundIn),
   (Events.ascii "nv_name", .str nvName),
   (Events.ascii "nv_writer_public", .str writer),
   (Events.ascii "anchor", .str anchor),
   (Events.ascii "anchor_digest", .str anchorDigest),
   (Events.ascii "chain", .str chain)]

theorem initRecord_eq (set : List (Str × Str)) (digest ts bootId : Str)
    (reset pcr phase : Int)
    (cert setDigest treeRoot pcrBefore phaseBefore boundIn nvName writer
      anchor anchorDigest chain : Str) (certs : List Str) :
    initRecord set digest ts bootId reset pcr phase cert setDigest treeRoot
        pcrBefore phaseBefore boundIn nvName writer anchor anchorDigest chain
        certs =
      .obj (openMembers tInit digest ts bootId ++
        (initMid reset cert setDigest treeRoot certs ++
          ((kSet, .arr (set.map fun p => .obj [(kName, .str p.1),
            (kPayload, .str p.2)])) ::
          initTail pcr phase pcrBefore phaseBefore boundIn nvName writer anchor
            anchorDigest chain))) := rfl

theorem initMid_skips (reset : Int) (cert setDigest treeRoot : Str)
    (certs : List Str) :
    ((initMid reset cert setDigest treeRoot certs).map Prod.fst).all Skips =
      true := by
  show ([Events.ascii "tpm_reset_count", Events.ascii "cert_sha256",
    Events.ascii "certs", Events.ascii "set_digest",
    Events.ascii "tree_root"] : List Str).all Skips = true
  decide

theorem initTail_skips (pcr phase : Int) (pcrBefore phaseBefore boundIn nvName
    writer anchor anchorDigest chain : Str) :
    ((initTail pcr phase pcrBefore phaseBefore boundIn nvName writer anchor
      anchorDigest chain).map Prod.fst).all Skips = true := by
  show ([Events.ascii "pcr", Events.ascii "pcr_before",
    Events.ascii "phase_pcr", Events.ascii "phase_before",
    Events.ascii "bound_in", Events.ascii "nv_name",
    Events.ascii "nv_writer_public", Events.ascii "anchor",
    Events.ascii "anchor_digest", Events.ascii "chain"] : List Str).all
      Skips = true
  decide

theorem walkSkips_of_skips {l : List (Str × JVal)}
    (h : (l.map Prod.fst).all Skips = true) :
    (l.map Prod.fst).all WalkSkips = true := by
  rw [List.all_eq_true] at h ⊢
  intro k hk
  have := h k hk
  simp only [Skips, WalkSkips, Bool.and_eq_true] at this ⊢
  exact this.1.1

/-- An init record reads back as the init event and a load for each
member of its set, in order, whatever its other fields hold. -/
theorem read_init (set : List (Str × Str)) (digest ts bootId : Str)
    (reset pcr phase : Int)
    (cert setDigest treeRoot pcrBefore phaseBefore boundIn nvName writer
      anchor anchorDigest chain : Str) (certs : List Str)
    (hset : ∀ q ∈ set, Written q.1 q.2) (hb : fits bootId 64 = true) :
    readLine (initRecord set digest ts bootId reset pcr phase cert setDigest
        treeRoot pcrBefore phaseBefore boundIn nvName writer anchor
        anchorDigest chain certs) =
      some (Measured.Record.events (.init set)) := by
  have hmid := initMid_skips reset cert setDigest treeRoot certs
  have htail := initTail_skips pcr phase pcrBefore phaseBefore boundIn nvName
    writer anchor anchorDigest chain
  have hrest : ((initMid reset cert setDigest treeRoot certs ++
      ((kSet, JVal.arr (set.map fun p => .obj [(kName, .str p.1),
        (kPayload, .str p.2)])) ::
      initTail pcr phase pcrBefore phaseBefore boundIn nvName writer anchor
        anchorDigest chain)).map Prod.fst).all WalkSkips = true := by
    simp only [List.map_append, List.map_cons, List.all_append, List.all_cons,
      walkSkips_of_skips hmid, walkSkips_of_skips htail, Bool.true_and,
      Bool.and_true]
    decide
  have hwalk := walk_open tInit digest ts bootId _ tInit_fits hb hrest
  let t0 : Top := { type := tInit, namedType := true, namedSet := true }
  have hfold := set_fold set hset t0 rfl rfl
  have htop : (openMembers tInit digest ts bootId ++
      (initMid reset cert setDigest treeRoot certs ++
        ((kSet, JVal.arr (set.map fun p => .obj [(kName, .str p.1),
          (kPayload, .str p.2)])) ::
        initTail pcr phase pcrBefore phaseBefore boundIn nvName writer anchor
          anchorDigest chain))).foldlM (topMember true) {} =
      some { type := tInit
             namedType := true
             namedSet := true
             loads := set } := by
    rw [List.foldlM_append, top_open _ _ _ _ _ tInit_fits, Option.bind_eq_bind,
      Option.bind_some, List.foldlM_append, top_skip _ _ _ hmid,
      Option.bind_eq_bind, Option.bind_some, List.foldlM_cons,
      top_set_step _ _ rfl]
    rw [show ({ type := tInit, namedType := true } : Top) =
      { type := tInit, namedType := true } from rfl]
    rw [hfold, Option.bind_eq_bind, Option.bind_some,
      top_skip _ _ _ htail]
    rfl
  rw [initRecord_eq]
  unfold readLine
  dsimp only
  rw [hwalk]
  dsimp only
  have hi : decide (tInit = tInit) = true := by simp
  rw [hi]
  unfold upatchesLine
  dsimp only
  rw [htop]
  simp [Measured.Record.events]

/-- A record of another type than an upatch's or init reads back as no
upatch event, whatever members follow its first ones. -/
theorem read_other (type digest ts bootId : Str) (rest : List (Str × JVal))
    (ht : fits type 32 = true) (hb : fits bootId 64 = true)
    (hi : type ≠ tInit) (hl : type ≠ tLoad) (hu : type ≠ tUnload)
    (hr : (rest.map Prod.fst).all Skips = true) :
    readLine (.obj (openMembers type digest ts bootId ++ rest)) = some [] := by
  have hwalk := walk_open type digest ts bootId rest ht hb
    (walkSkips_of_skips hr)
  have htop : (openMembers type digest ts bootId ++ rest).foldlM
      (topMember false) {} = some { type := type, namedType := true } := by
    rw [List.foldlM_append, top_open _ _ _ _ _ ht, Option.bind_eq_bind,
      Option.bind_some, top_skip _ _ _ hr]
  unfold readLine
  dsimp only
  rw [hwalk]
  dsimp only
  have hd : decide (type = tInit) = false := by simp [hi]
  rw [hd]
  unfold upatchesLine
  dsimp only
  rw [htop]
  simp [hl, hu]

/-- A key revocation reads back as no upatch event. -/
theorem read_key (digest ts bootId fingerprint cert : Str)
    (hb : fits bootId 64 = true) :
    readLine (keyRecord digest ts bootId fingerprint cert) =
      some (Measured.Record.events .other) :=
  read_other _ digest ts bootId _ (by decide) hb (by decide) (by decide)
    (by decide)
    (by
      show ([Events.ascii "key"] : List Str).all Skips = true
      decide)

/-- A tree operation reads back as no upatch event. -/
theorem read_tree (digest ts bootId op id operation chain : Str) (seq : Int)
    (hb : fits bootId 64 = true) :
    readLine (treeRecord digest ts bootId op id operation chain seq) =
      some (Measured.Record.events .other) :=
  read_other _ digest ts bootId _ (by decide) hb (by decide) (by decide)
    (by decide)
    (by
      show ([Events.ascii "tree", Events.ascii "chain"] : List Str).all
        Skips = true
      decide)

/-! ### Only a line's own fields give its events -/

/-- The fields of `ms` that name an event of `type` for `n` and `p`: the
`type` and the `upatch` member's `name` and `payload_sha256`. -/
def UpatchFields (ms : List (Str × JVal)) (type n p : Str) : Prop :=
  (kType, .str type) ∈ ms ∧ ∃ ums, (kUpatch, .obj ums) ∈ ms ∧
    (kName, .str n) ∈ ums ∧ (kPayload, .str p) ∈ ums

/-- An entry of the `set` of `ms` with `name` `n` and `payload_sha256`
`p`. -/
def SetEntry (ms : List (Str × JVal)) (n p : Str) : Prop :=
  ∃ xs, (kSet, .arr xs) ∈ ms ∧ ∃ ems, JVal.obj ems ∈ xs ∧
    (kName, .str n) ∈ ems ∧ (kPayload, .str p) ∈ ems

theorem foldlM_inv {α β : Type} (f : α → β → Option α) (P : α → Prop) :
    ∀ (l : List β) (a a' : α), P a →
      (∀ x b y, b ∈ l → P x → f x b = some y → P y) →
      l.foldlM f a = some a' → P a'
  | [], a, a', ha, _, h => by
    simp only [List.foldlM_nil, pure, Option.some.injEq] at h
    exact h ▸ ha
  | b :: l, a, a', ha, hf, h => by
    simp only [List.foldlM_cons] at h
    cases hb : f a b with
    | none => simp [hb] at h
    | some y =>
      simp only [hb, Option.bind_eq_bind, Option.bind_some] at h
      exact foldlM_inv f P l y a' (hf a b y List.mem_cons_self ha hb)
        (fun x c z hc => hf x c z (List.mem_cons_of_mem b hc)) h

/-- What an entry object leaves in the buffers comes from its own members,
or was there before. -/
def EntryInv (n0 p0 : Str) (ums : List (Str × JVal)) (e : Entry) : Prop :=
  (e.name = n0 ∨ (kName, .str e.name) ∈ ums) ∧
    (e.seenName = true → (kName, .str e.name) ∈ ums) ∧
    (e.payload = p0 ∨ (kPayload, .str e.payload) ∈ ums) ∧
    (e.seenPayload = true → (kPayload, .str e.payload) ∈ ums)

theorem entryMember_inv {n0 p0 : Str} {ums : List (Str × JVal)} {x y : Entry}
    {b : Str × JVal} (hb : b ∈ ums) (hx : EntryInv n0 p0 ums x)
    (h : entryMember x b = some y) : EntryInv n0 p0 ums y := by
  obtain ⟨k, v⟩ := b
  by_cases hk : k = kName
  · subst hk
    cases hn : x.namedName <;> cases v <;> simp [entryMember, hn] at h
    case false.str s =>
      obtain ⟨-, rfl⟩ := h
      exact ⟨Or.inr hb, fun _ => hb, hx.2.2.1, hx.2.2.2⟩
    case false.null =>
      subst h
      exact hx
  · by_cases hp : k = kPayload
    · subst hp
      cases hn : x.namedPayload <;> cases v <;>
        simp [entryMember, hn, kPayload_ne] at h
      case false.str s =>
        obtain ⟨-, rfl⟩ := h
        exact ⟨hx.1, hx.2.1, Or.inr hb, fun _ => hb⟩
      case false.null =>
        subst h
        exact hx
    · simp [entryMember, hk, hp] at h
      subst h
      exact hx

theorem entryObj_inv {n0 p0 : Str} {ums : List (Str × JVal)} {e : Entry}
    (h : entryObj n0 p0 ums = some e) : EntryInv n0 p0 ums e :=
  foldlM_inv entryMember (EntryInv n0 p0 ums) ums { name := n0, payload := p0 }
    e ⟨Or.inl rfl, (fun h => by cases h), Or.inl rfl, (fun h => by cases h)⟩
    (fun _ _ _ hb hx hs => entryMember_inv hb hx hs) h

/-- What `upatches_line()` keeps comes from the members of the line: the
type from its `type`, the buffers from its one `upatch` member, empty
until that member is read, and every entry taken from its `set`. -/
structure TopInv (isInit : Bool) (ms : List (Str × JVal)) (t : Top) : Prop where
  type : t.type = [] ∨ (kType, .str t.type) ∈ ms
  bufs : (t.name = [] ∧ t.payload = []) ∨ ∃ ums, (kUpatch, .obj ums) ∈ ms ∧
    (t.name = [] ∨ (kName, .str t.name) ∈ ums) ∧
    (t.payload = [] ∨ (kPayload, .str t.payload) ∈ ums)
  fresh : t.namedUpatch = false → t.name = [] ∧ t.payload = []
  loads : ∀ q ∈ t.loads, memberValid q.1 q.2 = true ∧ isInit = true ∧
    SetEntry ms q.1 q.2

theorem setElem_inv {ms : List (Str × JVal)} {xs : List JVal}
    (hset : (kSet, .arr xs) ∈ ms) {x y : Top} {b : JVal} (hb : b ∈ xs)
    (hx : TopInv true ms x) (h : setElem x b = some y) : TopInv true ms y := by
  cases b with
  | obj ems =>
    cases he : entryObj x.name x.payload ems with
    | none => simp [setElem, he] at h
    | some e =>
      have hi := entryObj_inv he
      cases hsn : e.seenName <;> cases hsp : e.seenPayload <;>
        cases hmv : memberValid e.name e.payload <;>
        simp [setElem, he, hsn, hsp, hmv] at h
      subst h
      refine ⟨hx.type, Or.inl ⟨rfl, rfl⟩, (fun _ => ⟨rfl, rfl⟩), ?_⟩
      intro q hq
      rcases List.mem_append.1 hq with hq | hq
      · exact hx.loads q hq
      · simp only [List.mem_singleton] at hq
        subst hq
        exact ⟨hmv, rfl, xs, hset, ems, hb, hi.2.1 hsn, hi.2.2.2 hsp⟩
  | _ => simp [setElem] at h

theorem topMember_inv {isInit : Bool} {ms : List (Str × JVal)} {x y : Top}
    {b : Str × JVal} (hb : b ∈ ms) (hx : TopInv isInit ms x)
    (h : topMember isInit x b = some y) : TopInv isInit ms y := by
  obtain ⟨k, v⟩ := b
  by_cases hk : k = kType
  · subst hk
    cases hn : x.namedType <;> cases v <;> simp [topMember, hn] at h
    case false.str s =>
      obtain ⟨-, rfl⟩ := h
      exact ⟨Or.inr hb, hx.bufs, hx.fresh, hx.loads⟩
    case false.null =>
      subst h
      exact ⟨hx.type, hx.bufs, hx.fresh, hx.loads⟩
  · by_cases hs : isInit = true ∧ k = kSet
    · obtain ⟨hi, rfl⟩ := hs
      subst hi
      cases hn : x.namedSet <;> cases v <;> simp [topMember, hn, kSet_ne] at h
      case false.arr xs =>
        exact foldlM_inv setElem (TopInv true ms) xs { x with namedSet := true } y
          ⟨hx.type, hx.bufs, hx.fresh, hx.loads⟩
          (fun _ _ _ hb' hx' hs' => setElem_inv hb hb' hx' hs') h
      case false.null =>
        subst h
        exact ⟨hx.type, hx.bufs, hx.fresh, hx.loads⟩
    · by_cases hu : k = kUpatch
      · subst hu
        have hs' : ¬ (isInit = true ∧ kUpatch = kSet) :=
          fun h => kUpatch_ne_set h.2
        cases hn : x.namedUpatch <;> cases v <;>
          simp [topMember, hn, kUpatch_ne_type, kUpatch_ne_set] at h
        case false.obj ums =>
          cases he : entryObj x.name x.payload ums with
          | none => simp [he] at h
          | some e =>
            simp only [he, Option.some.injEq] at h
            subst h
            have hi := entryObj_inv he
            obtain ⟨h0n, h0p⟩ := hx.fresh hn
            rw [h0n, h0p] at hi
            exact ⟨hx.type, Or.inr ⟨ums, hb, hi.1, hi.2.2.1⟩,
              (fun h => by cases h), hx.loads⟩
        case false.null =>
          subst h
          exact ⟨hx.type, hx.bufs, (fun h => by cases h), hx.loads⟩
      · have hs2 : ¬ ((isInit && decide (k = kSet)) = true) := by
          simpa using hs
        simp [topMember, hk, hu, hs2] at h
        subst h
        exact hx

theorem top_inv {isInit : Bool} {ms : List (Str × JVal)} {t : Top}
    (h : ms.foldlM (topMember isInit) {} = some t) : TopInv isInit ms t :=
  foldlM_inv (topMember isInit) (TopInv isInit ms) ms _ t
    ⟨Or.inl rfl, Or.inl ⟨rfl, rfl⟩, (fun _ => ⟨rfl, rfl⟩),
      (fun q hq => by cases hq)⟩
    (fun _ _ _ hb hx hs => topMember_inv hb hx hs) h

theorem walk_type {ms : List (Str × JVal)} {w : Walk}
    (h : ms.foldlM walkMember {} = some w) :
    w.type = [] ∨ (kType, .str w.type) ∈ ms := by
  refine foldlM_inv walkMember
    (fun w => w.type = [] ∨ (kType, .str w.type) ∈ ms) ms _ w (Or.inl rfl) ?_ h
  intro x b y hb hx hs
  obtain ⟨k, v⟩ := b
  by_cases hkb : k = kBootId
  · subst hkb
    cases hn : x.namedBoot <;> cases v <;> simp [walkMember, hn] at hs
    case false.str s => obtain ⟨-, rfl⟩ := hs; exact hx
    case false.null => subst hs; exact hx
  · by_cases hkt : k = kType
    · subst hkt
      cases hn : x.namedType <;> cases v <;>
        simp [walkMember, hn, kType_ne_boot] at hs
      case false.str s => obtain ⟨-, rfl⟩ := hs; exact Or.inr hb
      case false.null => subst hs; exact hx
    · simp [walkMember, hkb, hkt] at hs
      subst hs
      exact hx

theorem nameValid_ne {n : Str} (h : Events.nameValid n = true) : n ≠ [] := by
  rintro rfl
  simp [Events.nameValid] at h

/-- What `readLine` returns for a line `ms`, read as a record of its
`type`: the walk's and the reader's folds, both whole. -/
theorem readLine_obj {ms : List (Str × JVal)} {evs : List Measured.Event}
    (h : readLine (.obj ms) = some evs) :
    ∃ w t, ms.foldlM walkMember {} = some w ∧
      ms.foldlM (topMember (decide (w.type = tInit))) {} = some t ∧
      (w.type = tInit → evs = .init :: t.loads.map fun q => .load q.1 q.2) ∧
      (w.type ≠ tInit → (t.type = tLoad ∨ t.type = tUnload) ∧
        t.upatchSeen = true ∧ memberValid t.name t.payload = true ∧
        evs = [if t.type = tLoad then .load t.name t.payload
          else .unload t.name t.payload] ∨ evs = []) := by
  cases hw : ms.foldlM walkMember {} with
  | none => simp [readLine, hw] at h
  | some w =>
    simp only [readLine, hw] at h
    by_cases hi : w.type = tInit
    · have hd : decide (w.type = tInit) = true := by simp [hi]
      rw [hd] at h
      cases ht : ms.foldlM (topMember true) {} with
      | none => simp [upatchesLine, ht] at h
      | some t =>
        refine ⟨w, t, rfl, by rw [hd]; exact ht, ?_, fun hn => absurd hi hn⟩
        intro _
        simp [upatchesLine, ht] at h
        exact h.symm
    · have hd : decide (w.type = tInit) = false := by simp [hi]
      rw [hd] at h
      cases ht : ms.foldlM (topMember false) {} with
      | none => simp [upatchesLine, ht] at h
      | some t =>
        refine ⟨w, t, rfl, by rw [hd]; exact ht, fun h' => absurd h' hi, ?_⟩
        intro _
        simp only [upatchesLine, ht, Bool.false_eq_true, ite_false] at h
        by_cases hlu : t.type = tLoad ∨ t.type = tUnload
        · have hlu' : (decide (t.type = tLoad) || decide (t.type = tUnload)) =
              true := by
            rcases hlu with h1 | h1 <;> simp [h1]
          simp only [hlu', ite_true] at h
          by_cases hok : t.upatchSeen = true ∧ memberValid t.name t.payload = true
          · left
            have hok' : (t.upatchSeen && memberValid t.name t.payload) = true := by
              simp [hok.1, hok.2]
            simp only [hok', ite_true, Option.some.injEq] at h
            exact ⟨hlu, hok.1, hok.2, h.symm⟩
          · have hok' : (t.upatchSeen && memberValid t.name t.payload) = false := by
              cases h1 : t.upatchSeen <;> cases h2 : memberValid t.name t.payload <;>
                simp_all
            simp [hok'] at h
        · right
          have hlu' : (decide (t.type = tLoad) || decide (t.type = tUnload)) =
              false := by
            simp only [not_or] at hlu
            simp [hlu.1, hlu.2]
          simp only [hlu', Bool.false_eq_true, ite_false, Option.some.injEq] at h
          exact h.symm

theorem tLoad_ne_unload : tLoad ≠ tUnload := by decide

theorem str_mem_of_type {ms : List (Str × JVal)} {ty : Str} (hne : ty ≠ [])
    (h : ty = [] ∨ (kType, .str ty) ∈ ms) : (kType, .str ty) ∈ ms :=
  h.resolve_left hne

theorem upatch_fields {ms : List (Str × JVal)} {isInit : Bool} {t : Top}
    (hi : TopInv isInit ms t) (hmv : memberValid t.name t.payload = true) :
    ∃ ums, (kUpatch, .obj ums) ∈ ms ∧ (kName, .str t.name) ∈ ums ∧
      (kPayload, .str t.payload) ∈ ums := by
  simp only [memberValid, Bool.and_eq_true, decide_eq_true_eq] at hmv
  obtain ⟨⟨hnv, hlen⟩, -⟩ := hmv
  have hne := nameValid_ne hnv
  have hpe : t.payload ≠ [] := fun h0 => by rw [h0] at hlen; simp at hlen
  rcases hi.bufs with ⟨h0, -⟩ | ⟨ums, hu, hn, hp⟩
  · exact absurd h0 hne
  · exact ⟨ums, hu, hn.resolve_left hne, hp.resolve_left hpe⟩

/-- A load comes only from the line's own fields: its `type` of
`upatch_load` and its `upatch` member's `name` and `payload_sha256`, or,
in an init record, an entry of its `set` that names both itself; either
way a name and a payload `upatch_member_valid()` accepts. -/
theorem load_from_fields {v : JVal} {evs : List Measured.Event}
    (h : readLine v = some evs) {n p : Str}
    (he : Measured.Event.load n p ∈ evs) :
    memberValid n p = true ∧ ∃ ms, v = .obj ms ∧
      (UpatchFields ms tLoad n p ∨
        ((kType, .str tInit) ∈ ms ∧ SetEntry ms n p)) := by
  cases v with
  | obj ms =>
    obtain ⟨w, t, hw, ht, hinit, hother⟩ := readLine_obj h
    have hi := top_inv ht
    by_cases hwi : w.type = tInit
    · rw [hinit hwi] at he
      simp only [List.mem_cons, reduceCtorEq, false_or, List.mem_map] at he
      obtain ⟨q, hq, hqe⟩ := he
      simp only [Measured.Event.load.injEq] at hqe
      obtain ⟨rfl, rfl⟩ := hqe
      obtain ⟨hmv, -, hset⟩ := hi.loads q hq
      have htype := walk_type hw
      rw [hwi] at htype
      exact ⟨hmv, ms, rfl, Or.inr ⟨str_mem_of_type (by decide) htype, hset⟩⟩
    · rcases hother hwi with ⟨hlu, -, hmv, hevs⟩ | hevs
      · rw [hevs] at he
        by_cases hl : t.type = tLoad
        · simp only [hl, ite_true, List.mem_singleton,
            Measured.Event.load.injEq] at he
          obtain ⟨rfl, rfl⟩ := he
          refine ⟨hmv, ms, rfl, Or.inl ⟨?_, upatch_fields hi hmv⟩⟩
          have := hi.type
          rw [hl] at this
          exact str_mem_of_type (by decide) this
        · simp [hl] at he
      · rw [hevs] at he
        cases he
  | _ => simp [readLine] at h

/-- An unload comes only from the line's own `type` of `upatch_unload` and
its `upatch` member's `name` and `payload_sha256`, a name and a payload
`upatch_member_valid()` accepts. -/
theorem unload_from_fields {v : JVal} {evs : List Measured.Event}
    (h : readLine v = some evs) {n p : Str}
    (he : Measured.Event.unload n p ∈ evs) :
    memberValid n p = true ∧ ∃ ms, v = .obj ms ∧ UpatchFields ms tUnload n p := by
  cases v with
  | obj ms =>
    obtain ⟨w, t, hw, ht, hinit, hother⟩ := readLine_obj h
    have hi := top_inv ht
    by_cases hwi : w.type = tInit
    · rw [hinit hwi] at he
      simp at he
    · rcases hother hwi with ⟨hlu, -, hmv, hevs⟩ | hevs
      · rw [hevs] at he
        by_cases hl : t.type = tLoad
        · simp [hl] at he
        · have hu : t.type = tUnload := hlu.resolve_left hl
          simp only [hl, ite_false, List.mem_singleton,
            Measured.Event.unload.injEq] at he
          obtain ⟨rfl, rfl⟩ := he
          refine ⟨hmv, ms, rfl, ?_, upatch_fields hi hmv⟩
          have := hi.type
          rw [hu] at this
          exact str_mem_of_type (by decide) this
      · rw [hevs] at he
        cases he
  | _ => simp [readLine] at h

/-- An init event comes only from a line whose `type` is `init`. -/
theorem init_from_type {v : JVal} {evs : List Measured.Event}
    (h : readLine v = some evs) (he : Measured.Event.init ∈ evs) :
    ∃ ms, v = .obj ms ∧ (kType, .str tInit) ∈ ms := by
  cases v with
  | obj ms =>
    obtain ⟨w, t, hw, -, -, hother⟩ := readLine_obj h
    by_cases hwi : w.type = tInit
    · have htype := walk_type hw
      rw [hwi] at htype
      exact ⟨ms, rfl, str_mem_of_type (by decide) htype⟩
    · rcases hother hwi with ⟨-, -, -, hevs⟩ | hevs
      · rw [hevs] at he
        by_cases hl : t.type = tLoad <;> simp [hl] at he
      · rw [hevs] at he
        cases he
  | _ => simp [readLine] at h

end Shirudo.EventlogRecord
