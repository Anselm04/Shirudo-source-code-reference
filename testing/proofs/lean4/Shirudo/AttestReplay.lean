-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

import Shirudo.Events

/-!
How `attest verify` chooses the records it replays, in util/attest.c.
`on_record()` reads the evidence's eventlog record by record: it refuses
a type that is no record word, a digest that does not decode and, past
`RECORDS_MAX` records of the current register, any record; an init record
whose other fields do not decode or whose reset count passes a `__u32`;
and a load or an unload of a name `upatch_name_valid()` refuses. An init
record starts the register over: the records before it are dropped, it
becomes the first, and it counts towards `inits_epoch`, which starts at 1
on the first init record and on one whose reset count differs from the
last one's, both given, and grows otherwise. Every other record follows;
it is derived when its fields decode to an event whose digest is the
record's. `verify_epoch()`, `verify_replay()`, `verify_derived()` and the
init check of `verify_state()` then ask for one init record of this TPM
reset, of the certified reset count, the records folding to the certified
register value, every record after the init derived, and the init's digest
the one the operator expects.

A record is what `on_record()` takes from one element: whether its type
is a record word, its digest if it decodes, and its kind with the fields
`on_record()` reads. An event is `Shirudo.Events.Event`, so the digest a
record derives is `Event.digest`. The register value, reset count and
expected init digest stand for what `verify_register()` and the caller
give; that the register's certification checks is the report's other
lines.

`select_sound`: when every check passes, the certified value is the fold
of the last init record and the records after it, the init's digest is
the expected one and its reset count the certified one, and every record
after it carries an event whose digest is its own. `verify_history` puts
it together with `Events.verify_sound`: whatever extended the register,
it was extended by the expected init event and then by exactly the
events the records after the last init name, in order, unless SHA-256
collides on the strings the two folds hash.
-/

namespace Shirudo.AttestReplay
open Shirudo Events

/-- `RECORDS_MAX`. -/
def recordsMax : Nat := 4096

/-- What `on_record()` reads of a record beyond its type and digest. -/
inductive Kind where
  /-- An init record: its `tpm_reset_count`, negative when it has none,
  and whether its other fields decode. -/
  | init (reset : Int) (fieldsOk : Bool)
  /-- A load or an unload: whether `upatch_name_valid()` takes its name,
  and the event its fields name if they decode. -/
  | upatch (nameOk : Bool) (event : Option Event)
  /-- A tree operation, a key revocation or a type `on_record()` does not
  read: the event its fields name if they decode, none otherwise. -/
  | other (event : Option Event)

/-- One element of the evidence's eventlog. -/
structure Rec where
  word : Bool
  digest : Option Digest
  kind : Kind

/-- `(__u32)` of an `__s64` the parser read. -/
def u32 (x : Int) : Nat := (x % 4294967296).toNat

/-- What `on_record()` keeps: this register's records with whether each
is derived, the init records counted, `inits_epoch`, and the last init's
reset count and digest. -/
structure St where
  recs : List (Digest × Bool)
  inits : Nat
  epoch : Nat
  haveReset : Bool
  reset : Nat
  initDigest : Digest

def St.empty : St :=
  { recs := [], inits := 0, epoch := 0, haveReset := false, reset := 0,
    initDigest := Digest.zero }

variable (sha : List UInt8 → Digest)

/-- A record is derived when its fields name an event whose digest is
the record's. -/
def derivedOf (ev : Option Event) (d : Digest) : Bool :=
  match ev with
  | some e => (Event.digest sha e).bytes == d.bytes
  | none => false

/-- `on_record()`. -/
def step (st : St) (r : Rec) : Option St :=
  if recordsMax ≤ st.recs.length then none
  else if !r.word then none
  else
    match r.digest with
    | none => none
    | some d =>
      match r.kind with
      | .init reset ok =>
        if !ok || decide (4294967295 < reset) then none
        else
          some { recs := [(d, false)]
                 inits := st.inits + 1
                 epoch :=
                   if st.inits + 1 = 1 ∨ (0 ≤ reset ∧ st.haveReset = true ∧
                       u32 reset ≠ st.reset) then 1 else st.epoch + 1
                 haveReset := decide (0 ≤ reset)
                 reset := u32 reset
                 initDigest := d }
      | .upatch nameOk ev =>
        if !nameOk then none
        else some { st with recs := st.recs ++ [(d, derivedOf sha ev d)] }
      | .other ev =>
        some { st with recs := st.recs ++ [(d, derivedOf sha ev d)] }

/-- The eventlog read whole, from the zeroed state `attest_verify()`
allocates. -/
def parse (l : List Rec) : Option St := l.foldlM (step sha) St.empty

/-- `verify_epoch()`, `verify_replay()`, `verify_derived()` and the init
check of `verify_state()` pass, for the certified register value `value`
and reset count `reset` and the expected init digest `init`. -/
structure Passes (st : St) (value : Digest) (reset : Nat) (init : Digest) :
    Prop where
  epoch : st.epoch = 1
  resetCount : st.haveReset = true ∧ st.reset = reset
  replay : (st.recs.map Prod.fst).foldl (fold sha) Digest.zero = value
  derived : ∀ x ∈ st.recs.tail, x.2 = true
  initDigest : st.initDigest = init

/-! ### The records after the last init -/

def IsInit (r : Rec) : Prop := ∃ reset ok, r.kind = .init reset ok

/-- The event a record's fields name. -/
def eventOf (r : Rec) : Option Event :=
  match r.kind with
  | .init .. => none
  | .upatch _ ev => ev
  | .other ev => ev

/-- What `on_record()` appends for a record after the init. -/
def entryOf (r : Rec) : Digest × Bool :=
  match r.digest with
  | some d => (d, derivedOf sha (eventOf r) d)
  | none => (Digest.zero, false)

/-- What the state says of the records `done` read so far: none an init
record yet, or the last init and the records after it, each with a
digest. -/
def Inv (done : List Rec) (st : St) : Prop :=
  (st.inits = 0 ∧ st.epoch = 0 ∧ ∀ r ∈ done, ¬ IsInit r) ∨
  (∃ pre i post reset ok d, done = pre ++ i :: post ∧
    i.kind = .init reset ok ∧ i.digest = some d ∧ 0 < st.inits ∧
    (∀ r ∈ post, ¬ IsInit r ∧ r.digest.isSome) ∧
    st.recs = (d, false) :: post.map (entryOf sha) ∧ st.initDigest = d ∧
    st.haveReset = decide (0 ≤ reset) ∧ st.reset = u32 reset)

theorem inv_append {done : List Rec} {st : St} {r : Rec} {d : Digest}
    {ev : Option Event} (hi : Inv sha done st) (hd : r.digest = some d)
    (hev : eventOf r = ev) (hni : ¬ IsInit r) :
    Inv sha (done ++ [r])
      { st with recs := st.recs ++ [(d, derivedOf sha ev d)] } := by
  have hent : entryOf sha r = (d, derivedOf sha ev d) := by
    simp [entryOf, hd, hev]
  rcases hi with ⟨h0, h1, hall⟩ | ⟨pre, i, post, rs, ok, di, hdone, hik, hid,
      hpos, hpost, hrecs, hdig, hhave, hres⟩
  · refine Or.inl ⟨h0, h1, ?_⟩
    intro x hx
    rcases List.mem_append.1 hx with hx | hx
    · exact hall x hx
    · simp only [List.mem_singleton] at hx
      subst hx
      exact hni
  · refine Or.inr ⟨pre, i, post ++ [r], rs, ok, di, by rw [hdone]; simp,
      hik, hid, hpos, ?_, ?_, hdig, hhave, hres⟩
    · intro x hx
      rcases List.mem_append.1 hx with hx | hx
      · exact hpost x hx
      · simp only [List.mem_singleton] at hx
        subst hx
        exact ⟨hni, by simp [hd]⟩
    · simp [hrecs, hent]

theorem step_inv {done : List Rec} {st st' : St} {r : Rec}
    (hi : Inv sha done st) (h : step sha st r = some st') :
    Inv sha (done ++ [r]) st' := by
  unfold step at h
  by_cases hmax : recordsMax ≤ st.recs.length
  · simp [hmax] at h
  cases hw : r.word
  · simp [hmax, hw] at h
  cases hd : r.digest with
  | none => simp [hmax, hw, hd] at h
  | some d =>
    cases hk : r.kind with
    | init reset ok =>
      by_cases hbad : (!ok || decide (4294967295 < reset)) = true
      · simp [hmax, hw, hd, hk, hbad] at h
      have hbad' : (!ok || decide (4294967295 < reset)) = false := by
        simpa using hbad
      simp only [hmax, hw, hd, hk, hbad', Bool.not_true, Bool.false_eq_true,
        ite_false, Option.some.injEq] at h
      subst h
      exact Or.inr ⟨done, r, [], reset, ok, d, rfl, hk, hd, Nat.succ_pos _,
        (fun _ h => by cases h), rfl, rfl, rfl, rfl⟩
    | upatch nameOk ev =>
      cases hn : nameOk
      · simp [hmax, hw, hd, hk, hn] at h
      simp only [hmax, hw, hd, hk, hn, Bool.not_true, Bool.false_eq_true,
        ite_false, Option.some.injEq] at h
      subst h
      exact inv_append sha hi hd (by simp [eventOf, hk])
        (fun ⟨_, _, h⟩ => by rw [hk] at h; cases h)
    | other ev =>
      simp only [hmax, hw, hd, hk, Bool.not_true, Bool.false_eq_true,
        ite_false, Option.some.injEq] at h
      subst h
      exact inv_append sha hi hd (by simp [eventOf, hk])
        (fun ⟨_, _, h⟩ => by rw [hk] at h; cases h)

theorem parse_inv : ∀ (l done : List Rec) (st st' : St), Inv sha done st →
    l.foldlM (step sha) st = some st' → Inv sha (done ++ l) st'
  | [], done, st, st', hi, h => by
    simp only [List.foldlM_nil, pure, Option.some.injEq] at h
    subst h
    simpa using hi
  | r :: l, done, st, st', hi, h => by
    simp only [List.foldlM_cons] at h
    cases hs : step sha st r with
    | none => simp [hs] at h
    | some st1 =>
      simp only [hs, Option.bind_eq_bind, Option.bind_some] at h
      have := parse_inv l (done ++ [r]) st1 st' (step_inv sha hi hs) h
      simpa using this

/-- The records after the init, each derived: the events they name. -/
theorem post_events : ∀ (post : List Rec),
    (∀ r ∈ post, r.digest.isSome = true) →
    (∀ x ∈ post.map (entryOf sha), x.2 = true) →
    ∃ evs : List Event, post.map eventOf = evs.map some ∧
      (post.map (entryOf sha)).map Prod.fst = evs.map (Event.digest sha) ∧
      post.map Rec.digest = evs.map fun e => some (Event.digest sha e)
  | [], _, _ => ⟨[], rfl, rfl, rfl⟩
  | r :: post, hsome, hder => by
    obtain ⟨evs, h1, h2, h3⟩ := post_events post
      (fun x hx => hsome x (List.mem_cons_of_mem r hx))
      (fun x hx => hder x (List.mem_cons_of_mem _ hx))
    cases hd : r.digest with
    | none => have := hsome r List.mem_cons_self; simp [hd] at this
    | some d =>
      have hr := hder (entryOf sha r) List.mem_cons_self
      cases he : eventOf r with
      | none => simp [entryOf, hd, he, derivedOf] at hr
      | some e =>
        have hb : (Event.digest sha e).bytes = d.bytes := by
          simpa [entryOf, hd, he, derivedOf] using hr
        have hed : Event.digest sha e = d := Digest.ext_bytes hb
        refine ⟨e :: evs, by simp [he, h1], ?_, ?_⟩
        · simp [entryOf, hd, he, hed, h2]
        · simp [hd, hed, h3]

/-- The facts the checks leave about the records `l` the state was read
from. -/
theorem select_core {l : List Rec} {st : St} (h : parse sha l = some st)
    {value : Digest} {reset : Nat} {init : Digest}
    (hp : Passes sha st value reset init) :
    ∃ (pre : List Rec) (i : Rec) (post : List Rec) (rs : Int) (ok : Bool)
      (evs : List Event), l = pre ++ i :: post ∧ i.kind = .init rs ok ∧
      i.digest = some init ∧ 0 ≤ rs ∧ u32 rs = reset ∧
      (∀ r ∈ post, ¬ IsInit r) ∧ post.map eventOf = evs.map some ∧
      post.map Rec.digest = evs.map (fun e => some (Event.digest sha e)) ∧
      st.recs.map Prod.fst = init :: evs.map (Event.digest sha) := by
  have hi := parse_inv sha l [] St.empty st
    (Or.inl ⟨rfl, rfl, fun _ h => by cases h⟩) h
  rcases hi with ⟨-, h0, -⟩ | ⟨pre, i, post, rs, ok, d, hdone, hik, hid, -,
      hpost,
      hrecs, hdig, hhave, hres⟩
  · rw [hp.epoch] at h0
    cases h0
  · have hdi : d = init := hdig.symm.trans hp.initDigest
    subst hdi
    have hder : ∀ x ∈ post.map (entryOf sha), x.2 = true := by
      intro x hx
      exact hp.derived x (by rw [hrecs]; exact hx)
    obtain ⟨evs, h1, h2, h3⟩ := post_events sha post
      (fun r hr => (hpost r hr).2) hder
    have hpos : 0 ≤ rs := by
      have := hp.resetCount.1
      rw [hhave] at this
      simpa using this
    refine ⟨pre, i, post, rs, ok, evs, by simpa using hdone, hik, hid, hpos,
      hres ▸ hp.resetCount.2, fun r hr => (hpost r hr).1, h1, h3, ?_⟩
    rw [hrecs]
    simp [h2]

/-- When every check passes, the certified register value is the fold of
the last init record and the records after it, that init carries the
expected digest and the certified reset count, and every record after it
names an event whose digest is its own. -/
theorem select_sound {l : List Rec} {st : St} (h : parse sha l = some st)
    {value : Digest} {reset : Nat} {init : Digest}
    (hp : Passes sha st value reset init) :
    ∃ (pre : List Rec) (i : Rec) (post : List Rec) (rs : Int) (ok : Bool)
      (evs : List Event), l = pre ++ i :: post ∧ i.kind = .init rs ok ∧
      i.digest = some init ∧ 0 ≤ rs ∧ u32 rs = reset ∧
      (∀ r ∈ post, ¬ IsInit r) ∧ post.map eventOf = evs.map some ∧
      post.map Rec.digest = evs.map (fun e => some (Event.digest sha e)) ∧
      (init :: evs.map (Event.digest sha)).foldl (fold sha) Digest.zero =
        value := by
  obtain ⟨pre, i, post, rs, ok, evs, h1, h2, h3, h4, h5, h6, h7, h8, h9⟩ :=
    select_core sha h hp
  exact ⟨pre, i, post, rs, ok, evs, h1, h2, h3, h4, h5, h6, h7, h8,
    h9 ▸ hp.replay⟩

/-- What `attest verify` concludes of the target's history. The operator
expects the init event `ei`. Whatever extended the register, with
whatever values `hs`, it was extended by `ei` and then by exactly the
events the records after the last init name, in order, unless SHA-256
collides on the 64-byte strings of the two folds or maps one of them to
the zero register. -/
theorem verify_history {l : List Rec} {st : St} (h : parse sha l = some st)
    {value : Digest} {reset : Nat} (ei : Event)
    (hp : Passes sha st value reset (Event.digest sha ei)) (hs : List Digest)
    (hcert : hs.foldl (fold sha) Digest.zero = value)
    (hsha : ∀ m ∈ foldInputs sha (st.recs.map Prod.fst) ++ foldInputs sha hs,
      ∀ m' ∈ foldInputs sha (st.recs.map Prod.fst) ++ foldInputs sha hs,
        sha m = sha m' → m = m')
    (hzero : ∀ m ∈ foldInputs sha (st.recs.map Prod.fst) ++ foldInputs sha hs,
      sha m ≠ Digest.zero) :
    ∃ (pre : List Rec) (i : Rec) (post : List Rec) (evs : List Event),
      l = pre ++ i :: post ∧ IsInit i ∧
      (∀ r ∈ post, ¬ IsInit r) ∧ post.map eventOf = evs.map some ∧
      hs = (ei :: evs).map (Event.digest sha) := by
  obtain ⟨pre, i, post, rs, ok, evs, h1, h2, -, -, -, h6, h7, -, h9⟩ :=
    select_core sha h hp
  refine ⟨pre, i, post, evs, h1, ⟨rs, ok, h2⟩, h6, h7, ?_⟩
  exact verify_sound sha (ei :: evs) (st.recs.map Prod.fst) hs value
    (by simpa using h9) hp.replay hcert hsha hzero

/-- The checks can pass: an init record of reset count 0 and a record
that names its event, on any hash. -/
theorem passes_witness (e : Event) (d : Digest) :
    ∃ st, parse sha [⟨true, some d, .init 0 true⟩,
        ⟨true, some (Event.digest sha e), .other (some e)⟩] = some st ∧
      Passes sha st ((d :: [Event.digest sha e]).foldl (fold sha) Digest.zero)
        0 d := by
  refine ⟨_, rfl, ⟨rfl, ⟨rfl, rfl⟩, rfl, ?_, rfl⟩⟩
  intro x hx
  simp only [List.singleton_append, List.tail_cons, List.mem_singleton] at hx
  subst hx
  simp [derivedOf]

end Shirudo.AttestReplay
