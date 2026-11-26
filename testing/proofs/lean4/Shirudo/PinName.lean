-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

/-!
The pin name codec of util/paths.h. bpffs refuses a dot in a path
component and an upatch name may carry one, so `upatch_bpffs_name()`
writes each `.` of a name as `~d` and every other byte as itself, and
`upatch_name_from_bpffs()` turns each `~d` back into a dot and refuses a
`~` before any other byte or the end. No valid upatch name holds a `~`.

For names of every length: the decoding of the encoding of a name without
`~` is that name, an encoding holds no dot, two names without `~` never
share an encoding, so no two upatches share a pin, and a pin name without
a dot that decodes is the encoding of the name it decodes to, which holds
no `~`. The codec is thus a bijection between the names without `~` and
the pin names without a dot that decode.

`encode` and `decode` are the loops of the two functions, and `bpffsName`
and `nameFromBpffs` the functions with their buffer: the first refuses an
`out_sz` below twice the length and one before it writes, as the C does,
and the second each byte that would leave no room for the NUL. A string is
its bytes before the NUL, each byte its value. A C string is shorter than
2^63 bytes, so the C's `len * 2 + 1` does not wrap and is the model's.
testing/proofs/cbmc/paths-bpffs-name-model.c checks the C against the
model on every string of up to 8 bytes and every buffer size up to 18.
-/

namespace Shirudo.PinName

/-- `.`, which bpffs refuses in a path component. -/
def dot : Nat := 0x2e

/-- `~`, which no upatch name holds. -/
def tilde : Nat := 0x7e

/-- `d`, which follows the `~` that stands for a dot. -/
def letterD : Nat := 0x64

/-- What the loop of `upatch_bpffs_name()` writes for one byte. -/
def encodeByte (c : Nat) : List Nat :=
  if c = dot then [tilde, letterD] else [c]

/-- The loop of `upatch_bpffs_name()`: each dot becomes `~d`. -/
def encode (name : List Nat) : List Nat :=
  name.flatMap encodeByte

/-- The loop of `upatch_name_from_bpffs()` with room enough: `~d` becomes a
dot, and `~` before any other byte or the end is refused, as `none`. -/
def decode : List Nat → Option (List Nat)
  | [] => some []
  | c :: rest =>
    if c = tilde then
      match rest with
      | d :: rest' => if d = letterD then (decode rest').map (dot :: ·) else none
      | [] => none
    else (decode rest).map (c :: ·)

/-- `-EINVAL` and `-ENAMETOOLONG`. -/
inductive Err where
  | inval
  | nameTooLong
  deriving DecidableEq, Repr

/-- `upatch_bpffs_name(out, out_sz, name)`: `-EINVAL` for no buffer,
`-ENAMETOOLONG` when `out_sz` is below twice the length and one, and the
encoding otherwise. -/
def bpffsName (outSz : Nat) (name : List Nat) : Except Err (List Nat) :=
  if outSz = 0 then .error .inval
  else if name.length * 2 + 1 > outSz then .error .nameTooLong
  else .ok (encode name)

/-- The loop of `upatch_name_from_bpffs()` with `j` bytes written: a `~`
before anything but `d` is `-EINVAL`, and a byte that leaves no room for
the NUL `-ENAMETOOLONG`, whichever comes first. -/
def fromLoop (outSz j : Nat) : List Nat → Except Err (List Nat)
  | [] => .ok []
  | c :: rest =>
    if c = tilde then
      match rest with
      | d :: rest' =>
        if d = letterD then
          if j + 1 ≥ outSz then .error .nameTooLong
          else (fromLoop outSz (j + 1) rest').map (dot :: ·)
        else .error .inval
      | [] => .error .inval
    else if j + 1 ≥ outSz then .error .nameTooLong
    else (fromLoop outSz (j + 1) rest).map (c :: ·)

/-- `upatch_name_from_bpffs(out, out_sz, name)`. -/
def nameFromBpffs (outSz : Nat) (name : List Nat) : Except Err (List Nat) :=
  if outSz = 0 then .error .inval else fromLoop outSz 0 name

/-! ### The codec -/

theorem encode_cons (c : Nat) (cs : List Nat) :
    encode (c :: cs) = encodeByte c ++ encode cs := by
  simp [encode]

theorem decode_tilde_d (rest : List Nat) :
    decode (tilde :: letterD :: rest) = (decode rest).map (dot :: ·) := by
  simp [decode]

theorem decode_other (c : Nat) (rest : List Nat) (h : c ≠ tilde) :
    decode (c :: rest) = (decode rest).map (c :: ·) := by
  rw [decode.eq_def]
  simp only [h, ite_false]

/-- Decoding the encoding of a name without `~` gives the name back. -/
theorem decode_encode (name : List Nat) (h : tilde ∉ name) :
    decode (encode name) = some name := by
  induction name with
  | nil => rfl
  | cons c cs ih =>
    have hc : c ≠ tilde := fun e => h (e ▸ List.mem_cons_self)
    have hcs : tilde ∉ cs := fun m => h (List.mem_cons_of_mem c m)
    rw [encode_cons]
    by_cases hd : c = dot
    · simp only [encodeByte, hd, ite_true, List.cons_append, List.nil_append]
      rw [decode_tilde_d, ih hcs]
      rfl
    · simp only [encodeByte, hd, ite_false, List.cons_append, List.nil_append]
      rw [decode_other c _ hc, ih hcs]
      rfl

/-- An encoding holds no dot, which bpffs would refuse. -/
theorem dot_not_mem_encode (name : List Nat) : dot ∉ encode name := by
  induction name with
  | nil => simp [encode]
  | cons c cs ih =>
    rw [encode_cons, List.mem_append]
    intro hm
    rcases hm with hm | hm
    · by_cases hd : c = dot
      · simp [encodeByte, hd, dot, tilde, letterD] at hm
      · simp only [encodeByte, hd, ite_false, List.mem_singleton] at hm
        exact hd hm.symm
    · exact ih hm

/-- An encoding holds a NUL only where the name does: the C writes a
string that ends where the name's encoding does. -/
theorem nul_not_mem_encode (name : List Nat) (h : 0 ∉ name) :
    0 ∉ encode name := by
  induction name with
  | nil => simp [encode]
  | cons c cs ih =>
    have hc : c ≠ 0 := fun e => h (e ▸ List.mem_cons_self)
    rw [encode_cons, List.mem_append]
    intro hm
    rcases hm with hm | hm
    · by_cases hd : c = dot
      · simp [encodeByte, hd, tilde, letterD] at hm
      · simp only [encodeByte, hd, ite_false, List.mem_singleton] at hm
        exact hc hm.symm
    · exact ih (fun m => h (List.mem_cons_of_mem c m)) hm

/-- Two names without `~` have the same encoding only when they are the
same name: no two upatches share a pin. -/
theorem encode_injective (a b : List Nat) (ha : tilde ∉ a) (hb : tilde ∉ b)
    (h : encode a = encode b) : a = b := by
  have e := decode_encode a ha
  rw [h, decode_encode b hb] at e
  exact (Option.some.inj e).symm

/-- What a pin name decodes to holds no `~`, so it is an upatch name the
codec covers. -/
theorem tilde_not_mem_decode : ∀ (p n : List Nat), decode p = some n → tilde ∉ n
  | [], n, h => by
    simp only [decode, Option.some.injEq] at h
    subst h; simp
  | c :: rest, n, h => by
    by_cases hc : c = tilde
    · cases rest with
      | nil => simp [decode, hc] at h
      | cons d rest' =>
        by_cases hd : d = letterD
        · subst hc hd
          rw [decode_tilde_d] at h
          cases hr : decode rest' with
          | none => simp [hr] at h
          | some m =>
            simp only [hr, Option.map_some, Option.some.injEq] at h
            subst h
            have := tilde_not_mem_decode rest' m hr
            simp only [List.mem_cons, not_or]
            exact ⟨by decide, this⟩
        · simp [decode, hc, hd] at h
    · rw [decode_other c rest hc] at h
      cases hr : decode rest with
      | none => simp [hr] at h
      | some m =>
        simp only [hr, Option.map_some, Option.some.injEq] at h
        subst h
        have := tilde_not_mem_decode rest m hr
        simp only [List.mem_cons, not_or]
        exact ⟨fun e => hc e.symm, this⟩

/-- A pin name without a dot that decodes is the encoding of the name it
decodes to. -/
theorem encode_decode : ∀ (p n : List Nat), dot ∉ p → decode p = some n →
    encode n = p
  | [], n, _, h => by
    simp only [decode, Option.some.injEq] at h
    subst h; rfl
  | c :: rest, n, hp, h => by
    have hc : c ≠ dot := fun e => hp (e ▸ List.mem_cons_self)
    by_cases ht : c = tilde
    · cases rest with
      | nil => simp [decode, ht] at h
      | cons d rest' =>
        by_cases hd : d = letterD
        · subst ht hd
          rw [decode_tilde_d] at h
          cases hr : decode rest' with
          | none => simp [hr] at h
          | some m =>
            simp only [hr, Option.map_some, Option.some.injEq] at h
            subst h
            have hp' : dot ∉ rest' := fun m' =>
              hp (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ m'))
            rw [encode_cons, encode_decode rest' m hp' hr]
            rfl
        · simp [decode, ht, hd] at h
    · rw [decode_other c rest ht] at h
      cases hr : decode rest with
      | none => simp [hr] at h
      | some m =>
        simp only [hr, Option.map_some, Option.some.injEq] at h
        subst h
        have hp' : dot ∉ rest := fun m' => hp (List.mem_cons_of_mem _ m')
        rw [encode_cons, encode_decode rest m hp' hr]
        simp [encodeByte, hc]

/-! ### The functions with their buffer -/

theorem length_encode_le (name : List Nat) :
    (encode name).length ≤ 2 * name.length := by
  induction name with
  | nil => simp [encode]
  | cons c cs ih =>
    rw [encode_cons, List.length_append]
    by_cases hd : c = dot <;> simp [encodeByte, hd] <;> omega

/-- `upatch_bpffs_name()` writes the encoding exactly when `out_sz` holds
twice the length and its NUL, and the encoding with its NUL fits `out_sz`. -/
theorem bpffsName_ok (outSz : Nat) (name p : List Nat) :
    bpffsName outSz name = .ok p ↔
      0 < outSz ∧ 2 * name.length + 1 ≤ outSz ∧ p = encode name := by
  unfold bpffsName
  by_cases h0 : outSz = 0
  · simp [h0]
  · by_cases h1 : name.length * 2 + 1 > outSz
    · simp only [h0, h1, ite_false, ite_true, reduceCtorEq, false_iff]
      omega
    · simp only [h0, h1, ite_false, Except.ok.injEq]
      constructor
      · intro e; exact ⟨by omega, by omega, e.symm⟩
      · intro ⟨_, _, e⟩; exact e.symm

theorem except_map_ok {α β ε : Type} (f : α → β) (x : Except ε α) (b : β) :
    x.map f = .ok b ↔ ∃ a, x = .ok a ∧ f a = b := by
  cases x <;> simp [Except.map]

theorem option_map_some {α β : Type} (f : α → β) (x : Option α) (b : β) :
    x.map f = some b ↔ ∃ a, x = some a ∧ f a = b := by
  cases x <;> simp

/-- With `j` bytes written and room for the NUL, the loop of
`upatch_name_from_bpffs()` yields the decoding exactly when it fits
`out_sz` with its NUL. -/
theorem fromLoop_ok : ∀ (outSz j : Nat) (p n : List Nat), j < outSz →
    (fromLoop outSz j p = .ok n ↔ decode p = some n ∧ j + n.length < outSz)
  | outSz, j, [], n, hj => by
    simp only [fromLoop, Except.ok.injEq, decode, Option.some.injEq]
    constructor
    · intro e; subst e; simpa using hj
    · intro ⟨e, _⟩; exact e
  | outSz, j, c :: rest, n, hj => by
    by_cases ht : c = tilde
    · cases rest with
      | nil => simp [fromLoop, decode, ht]
      | cons d rest' =>
        by_cases hd : d = letterD
        · subst ht hd
          rw [decode_tilde_d, option_map_some]
          by_cases hroom : j + 1 ≥ outSz
          · simp only [fromLoop, ite_true, hroom, reduceCtorEq, false_iff]
            intro ⟨⟨m, _, e⟩, hl⟩
            subst e
            simp at hl
            omega
          · simp only [fromLoop, ite_true, hroom, ite_false, except_map_ok]
            constructor
            · intro ⟨m, hm, e⟩
              have := (fromLoop_ok outSz (j + 1) rest' m (by omega)).1 hm
              subst e
              exact ⟨⟨m, this.1, rfl⟩, by simp; omega⟩
            · intro ⟨⟨m, hm, e⟩, hl⟩
              subst e
              simp at hl
              exact ⟨m, (fromLoop_ok outSz (j + 1) rest' m (by omega)).2
                ⟨hm, by omega⟩, rfl⟩
        · simp [fromLoop, decode, ht, hd]
    · rw [decode_other c rest ht, option_map_some, fromLoop.eq_def]
      by_cases hroom : j + 1 ≥ outSz
      · simp only [ht, ite_false, hroom, ite_true, reduceCtorEq, false_iff]
        intro ⟨⟨m, _, e⟩, hl⟩
        subst e
        simp at hl
        omega
      · simp only [ht, hroom, ite_false, except_map_ok]
        constructor
        · intro ⟨m, hm, e⟩
          have := (fromLoop_ok outSz (j + 1) rest m (by omega)).1 hm
          subst e
          exact ⟨⟨m, this.1, rfl⟩, by simp; omega⟩
        · intro ⟨⟨m, hm, e⟩, hl⟩
          subst e
          simp at hl
          exact ⟨m, (fromLoop_ok outSz (j + 1) rest m (by omega)).2
            ⟨hm, by omega⟩, rfl⟩

/-- `upatch_name_from_bpffs()` yields a name exactly when the pin name
decodes to it and it fits `out_sz` with its NUL. -/
theorem nameFromBpffs_ok (outSz : Nat) (p n : List Nat) :
    nameFromBpffs outSz p = .ok n ↔ decode p = some n ∧ n.length < outSz := by
  unfold nameFromBpffs
  by_cases h0 : outSz = 0
  · simp [h0]
  · simp only [h0, ite_false]
    rw [fromLoop_ok outSz 0 p n (by omega), Nat.zero_add]

/-- Through the C with its buffers: a name without `~` that
`upatch_bpffs_name()` encodes, `upatch_name_from_bpffs()` turns back into
the name, given room for it and its NUL. -/
theorem pin_round_trip (outSz backSz : Nat) (name p : List Nat)
    (h : tilde ∉ name) (he : bpffsName outSz name = .ok p)
    (hb : name.length < backSz) : nameFromBpffs backSz p = .ok name := by
  have ⟨_, _, e⟩ := (bpffsName_ok outSz name p).1 he
  subst e
  exact (nameFromBpffs_ok backSz _ name).2 ⟨decode_encode name h, hb⟩

end Shirudo.PinName
