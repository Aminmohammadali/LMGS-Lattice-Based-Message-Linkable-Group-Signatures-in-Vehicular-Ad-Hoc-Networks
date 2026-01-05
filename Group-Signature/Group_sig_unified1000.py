import sys
sys.path.append('..')
from lazer import *
import hashlib
import secrets
import time
import math

# public randomness
shake128 = hashlib.shake_128(bytes.fromhex("00"))
PUBLIC_PP = shake128.digest(32)
shake128 = hashlib.shake_128(bytes.fromhex("01"))
P1PP = shake128.digest(32)

# import parameters
from GS_merged_params import mod, mod_p, deg, m, n
from _GS_merged_params_cffi import lib, ffi

# ============================================================
# PARAMETERIZATION
# ============================================================
N = 16      # Default: 2 (controls signature matrix rows)
M = 3       # Default: 3 (additional columns for s1)
tau = 5     # Default: 5 (τ - multiplier for s2, s3 dimensions)

# Computed dimensions
A_rows = N
A_cols = N + M
B_rows = N
B_cols = tau * N
Bprime_rows = N
Bprime_cols = tau * N
G_rows = N
G_cols = tau * N

# Commitment matrix dimensions
A0_rows = N + M
A0_cols = N + M
B0_rows = N + M
B0_cols = tau * N
C0_rows = N + M  # B'_0 (C_0)
C0_cols = tau * N

# Vector dimensions
s1_dim = N + M
s2_dim = tau * N
s3_dim = tau * N
w_dim = tau * N
u_dim = N
e1_dim = N + M
t2_dim = N + M

# Unified matrix dimensions (computed)
m_unified = 5 + N  # 5 encryption rows + N signature rows
n_unified = 10 + (N + M) + 3 * tau * N  # 10 (r+id) + s1 + s2 + s3 + w

# Create ring
RING = polyring_t(deg, mod)

# Get parameters
params = lib.get_params("merged_param")

# initialize prover and verifier
prover = lin_prover_state_t(P1PP, params)
verifier = lin_verifier_state_t(P1PP, params)

print("=" * 70)
print("GROUP SIGNATURE SCHEME - SIZE COMPUTATION (100 RUNS)")
print("=" * 70)
print(f"\nScheme Parameters:")
print(f"  N:                   {N}")
print(f"  M:                   {M}")
print(f"  τ (tau):             {tau}")
print(f"\nDerived Dimensions:")
print(f"  A:                   {A_rows} × {A_cols}")
print(f"  B:                   {B_rows} × {B_cols}")
print(f"  B':                  {Bprime_rows} × {Bprime_cols}")
print(f"  G:                   {G_rows} × {G_cols}")
print(f"  A_0:                 {A0_rows} × {A0_cols}")
print(f"  B_0:                 {B0_rows} × {B0_cols}")
print(f"  C_0 (B'_0):          {C0_rows} × {C0_cols}")
print(f"  Unified matrix:      {m_unified} × {n_unified}")
print(f"\nRing Parameters:")
print(f"  Degree (deg):        {deg}")
print(f"  Modulus q (mod):     {mod}")
print(f"    ├─ Hexadecimal:    0x{mod:x}")
print(f"    ├─ Structure:      2^67 + {mod - 2**67}")
print(f"    ├─ Bit length:     {mod.bit_length()} bits (storage required)")
print(f"    └─ log₂(q):        {math.log2(mod):.6f} ≈ 67 bits (magnitude)")
print(f"  Modulus p (mod_p):   {mod_p} ({mod_p.bit_length()} bits)")
print("=" * 70)

# Initialize accumulators for averages
NUM_RUNS = 500
total_t0_time = 0
total_t1_time = 0
total_commitment_time = 0
total_prover_time = 0
total_verifier_time = 0
total_b_size = 0
total_u_size = 0
total_t2_size = 0
total_zkp_size = 0
verification_success_count = 0

print(f"\nRunning {NUM_RUNS} iterations...")
print("Progress: ", end="", flush=True)

for run in range(NUM_RUNS):
    if (run + 1) % 100 == 0:
        print(f"{run + 1}...", end="", flush=True)
    
    # ============================================================
    # ENCRYPTION - Generate t_0 and t_1
    # ============================================================

    # ============================================================
    # ENCRYPTION - Generate t_0 and t_1
    # ============================================================

    A_enc = polymat_t.urandom_static(RING, 4, 9, mod_p, PUBLIC_PP, 0)
    s_en = polyvec_t.brandom_static(RING, 4, 2, secrets.token_bytes(32), 0)
    e_en = polyvec_t.brandom_static(RING, 9, 2, secrets.token_bytes(32), 1)

    A_enc_T = polymat_t(RING, 9, 4)
    for i in range(9):
        for j in range(4):
            A_enc_T[i, j] = A_enc[j, i]
    b = A_enc_T * s_en + e_en

    r = polyvec_t.brandom_static(RING, 9, 2, secrets.token_bytes(32), 2)
    id_i_bytes = secrets.token_bytes(deg // 8)
    id_i_vec = polyvec_t(RING, 1, id_i_bytes)
    id_i = id_i_vec[0]

    # Start timing t_0 computation
    t0_start = time.time()
    t_0 = A_enc * r
    t0_time = time.time() - t0_start

    # Start timing t_1 computation
    t1_start = time.time()
    inner_prod = poly_t(RING)
    for i in range(9):
        inner_prod = inner_prod + b[i] * r[i]
    p_half = mod // 2
    t_1 = inner_prod + id_i * p_half
    t1_time = time.time() - t1_start

    # ============================================================
    # Compute sizes using formula: size of encryption = 5*128 + 3329
    # ============================================================
    total_encryption_size = 5 * 128 + 3329  # = 3969 bytes

    # Split between t_0 (4 polynomials) and t_1 (1 polynomial) in 4:1 ratio
    t_0_size = (total_encryption_size * 4) // 5  # 3175 bytes
    t_1_size = total_encryption_size - t_0_size   # 794 bytes

    # ============================================================
    # SIGNATURE - Generate u (using parameterized dimensions)
    # ============================================================

    A = polymat_t.urandom_static(RING, A_rows, A_cols, mod, PUBLIC_PP, 10)
    B = polymat_t.urandom_static(RING, B_rows, B_cols, mod, PUBLIC_PP, 11)
    G = polymat_t.urandom_static(RING, G_rows, G_cols, mod, PUBLIC_PP, 12)
    B_prime = polymat_t.urandom_static(RING, Bprime_rows, Bprime_cols, mod, PUBLIC_PP, 13)

    s_1 = polyvec_t.brandom_static(RING, s1_dim, 2, secrets.token_bytes(32), 10)
    s_2 = polyvec_t.brandom_static(RING, s2_dim, 2, secrets.token_bytes(32), 11)
    s_3 = polyvec_t.brandom_static(RING, s3_dim, 2, secrets.token_bytes(32), 12)

    w = polyvec_t(RING, w_dim)
    for i in range(w_dim):
        w.set_elem(id_i * s_2.get_elem(i), i)

    u = A * s_1 + B * s_2 + B_prime * s_3 + G * w

    # ============================================================
    # Encode B (matrix N×(tau*N) - PUBLIC KEY)
    # ============================================================

    # Encode each row of B separately
    b_row_sizes = []
    for row_idx in range(B_rows):
        # Extract row as polyvec
        b_row = polyvec_t(RING, B_cols)
        for col_idx in range(B_cols):
            b_row.set_elem(B[row_idx, col_idx], col_idx)
        
        # Encode this row
        coder_b_row = coder_t()
        coder_b_row.enc_begin(50000)  # Increased buffer for larger dimensions
        coder_b_row.enc_urandom(mod, b_row)
        b_row_encoded = coder_b_row.enc_end()
        b_row_sizes.append(len(b_row_encoded))

    # Total size of B
    b_size = sum(b_row_sizes)

    # ============================================================
    # Encode u (polyvec with N polynomials)
    # ============================================================
    coder_u = coder_t()
    coder_u.enc_begin(20000)  # Increased buffer
    coder_u.enc_urandom(mod, u)
    u_encoded = coder_u.enc_end()
    u_size = len(u_encoded)

    # ============================================================
    # COMMITMENT - Generate t_2 (using parameterized dimensions)
    # ============================================================

    # Start timing commitment generation
    commitment_start = time.time()
    A_0 = polymat_t.urandom_static(RING, A0_rows, A0_cols, mod, PUBLIC_PP, 20)
    B_0 = polymat_t.urandom_static(RING, B0_rows, B0_cols, mod, PUBLIC_PP, 21)
    C_0 = polymat_t.urandom_static(RING, C0_rows, C0_cols, mod, PUBLIC_PP, 22)  # B'_0
    e_1 = polyvec_t.brandom_static(RING, e1_dim, 2, secrets.token_bytes(32), 13)

    t_2 = A_0 * s_1 + B_0 * s_2 + C_0 * s_3 + e_1
    commitment_time = time.time() - commitment_start

    # ============================================================
    # Encode t_2 (polyvec with (N+M) polynomials)
    # ============================================================
    coder_t2 = coder_t()
    coder_t2.enc_begin(30000)  # Increased buffer
    coder_t2.enc_urandom(mod, t_2)
    t_2_encoded = coder_t2.enc_end()
    t_2_size = len(t_2_encoded)

    # ============================================================
    # Build Unified Statement (using parameterized dimensions)
    # ============================================================

    A_unified = polymat_t(RING, m_unified, n_unified)

    zero_poly = poly_t(RING)
    for i in range(m_unified):
        for j in range(n_unified):
            A_unified[i, j] = zero_poly

    # Encryption part (rows 0-3)
    for i in range(4):
        for j in range(9):
            A_unified[i, j] = A_enc[i, j]

    # Encryption part (row 4)
    for j in range(9):
        A_unified[4, j] = b[j]
    A_unified[4, 9] = poly_t(RING, {0: p_half})

    # Signature part (rows 5 to 5+N-1)
    for i in range(N):
        # A part: columns 10 to 10+(N+M)-1
        for j in range(N + M):
            A_unified[5 + i, 10 + j] = A[i, j]
        # B part: columns 10+(N+M) to 10+(N+M)+tau*N-1
        for j in range(tau * N):
            A_unified[5 + i, 10 + (N + M) + j] = B[i, j]
        # B' part: columns 10+(N+M)+tau*N to 10+(N+M)+2*tau*N-1
        for j in range(tau * N):
            A_unified[5 + i, 10 + (N + M) + tau * N + j] = B_prime[i, j]
        # G part: columns 10+(N+M)+2*tau*N to 10+(N+M)+3*tau*N-1
        for j in range(tau * N):
            A_unified[5 + i, 10 + (N + M) + 2 * tau * N + j] = G[i, j]

    target_unified = polyvec_t(RING, m_unified)
    for i in range(4):
        target_unified[i] = t_0[i]
    target_unified[4] = t_1
    for i in range(N):
        target_unified[5 + i] = u[i]

    witness_unified = polyvec_t(RING, n_unified)

    # r: columns 0-8
    for i in range(r.dim):
        witness_unified.set_elem(r.get_elem(i), i)
    # id_i: column 9
    witness_unified.set_elem(id_i_vec.get_elem(0), 9)
    # s_1: columns 10 to 10+(N+M)-1
    for i in range(s_1.dim):
        witness_unified.set_elem(s_1.get_elem(i), 10 + i)
    # s_2: columns 10+(N+M) to 10+(N+M)+tau*N-1
    for i in range(s_2.dim):
        witness_unified.set_elem(s_2.get_elem(i), 10 + (N + M) + i)
    # s_3: columns 10+(N+M)+tau*N to 10+(N+M)+2*tau*N-1
    for i in range(s_3.dim):
        witness_unified.set_elem(s_3.get_elem(i), 10 + (N + M) + tau * N + i)
    # w: columns 10+(N+M)+2*tau*N to 10+(N+M)+3*tau*N-1
    for i in range(w.dim):
        witness_unified.set_elem(w.get_elem(i), 10 + (N + M) + 2 * tau * N + i)

    # ============================================================
    # PROVER - Generate ZKP
    # ============================================================

    prover.set_statement(A_unified, -target_unified)
    prover.set_witness(witness_unified)

    prover_start = time.time()
    proof = prover.prove()
    prover_time = time.time() - prover_start

    zkp_size = len(proof)

    # ============================================================
    # VERIFIER - Verify ZKP
    # ============================================================

    verifier.set_statement(A_unified, -target_unified)

    verifier_start = time.time()
    try:
        verifier.verify(proof)
        verifier_time = time.time() - verifier_start
        verification_success = True
    except VerificationError:
        verifier_time = time.time() - verifier_start
        verification_success = False
    
    # Accumulate results
    total_t0_time += t0_time
    total_t1_time += t1_time
    total_commitment_time += commitment_time
    total_prover_time += prover_time
    total_verifier_time += verifier_time
    total_b_size += b_size
    total_u_size += u_size
    total_t2_size += t_2_size
    total_zkp_size += zkp_size
    if verification_success:
        verification_success_count += 1

print(" Done!\n")

# Calculate averages
avg_t0_time = total_t0_time / NUM_RUNS
avg_t1_time = total_t1_time / NUM_RUNS
avg_commitment_time = total_commitment_time / NUM_RUNS
avg_prover_time = total_prover_time / NUM_RUNS
avg_verifier_time = total_verifier_time / NUM_RUNS
avg_b_size = total_b_size / NUM_RUNS
avg_u_size = total_u_size / NUM_RUNS
avg_t2_size = total_t2_size / NUM_RUNS
avg_zkp_size = total_zkp_size / NUM_RUNS

# ============================================================
# CALCULATE TOTAL SIGNATURE SIZE (using last run's t_0 and t_1)
# ============================================================

total_signature_size = t_0_size + t_1_size + avg_t2_size + avg_zkp_size

# ============================================================
# DISPLAY RESULTS
# ============================================================

verification_rate = (verification_success_count / NUM_RUNS) * 100

print("\n" + "=" * 70)
print(f"FINAL RESULTS - GROUP SIGNATURE SCHEME (AVERAGE OF {NUM_RUNS} RUNS)")
print("=" * 70)

print("\n┌─────────────────────────────────────────────────────────────────────┐")
print("│ PUBLIC KEY SIZE (AVERAGE):                                          │")
print("├─────────────────────────────────────────────────────────────────────┤")
print(f"│ B ({B_rows}×{B_cols} matrix):                 {avg_b_size:>8.2f} bytes  ({avg_b_size/1024:.2f} KB)   │")
print("└─────────────────────────────────────────────────────────────────────┘")

print("\n┌─────────────────────────────────────────────────────────────────────┐")
print("│ SIGNATURE COMPONENTS (AVERAGE):                                     │")
print("├─────────────────────────────────────────────────────────────────────┤")
print(f"│ t_0 (encryption output):       {t_0_size:>8} bytes (fixed formula)      │")
print(f"│ t_1 (encryption output):       {t_1_size:>8} bytes (fixed formula)      │")
print(f"│ t_2 (commitment):              {avg_t2_size:>8.2f} bytes                      │")
print(f"│ π   (ZK Proof):                {avg_zkp_size:>8.2f} bytes                      │")
print("├─────────────────────────────────────────────────────────────────────┤")
print(f"│ TOTAL SIGNATURE SIZE:          {total_signature_size:>8.2f} bytes  ({total_signature_size/1024:.2f} KB)   │")
print("└─────────────────────────────────────────────────────────────────────┘")

print("\n┌─────────────────────────────────────────────────────────────────────┐")
print("│ COMPUTATION TIMES (AVERAGE):                                        │")
print("├─────────────────────────────────────────────────────────────────────┤")
print(f"│ t_0 computation:               {avg_t0_time:>10.6f} seconds            │")
print(f"│ t_1 computation:               {avg_t1_time:>10.6f} seconds            │")
print(f"│ Commitment (A_0,B_0,C_0,e_1,t_2): {avg_commitment_time:>10.6f} seconds            │")
print(f"│ Prover (ZKP generation):       {avg_prover_time:>10.6f} seconds            │")
print(f"│ Verifier (ZKP verification):   {avg_verifier_time:>10.6f} seconds            │")
print("├─────────────────────────────────────────────────────────────────────┤")
total_time = avg_t0_time + avg_t1_time + avg_commitment_time + avg_prover_time + avg_verifier_time
print(f"│ TOTAL TIME:                    {total_time:>10.6f} seconds            │")
print("└─────────────────────────────────────────────────────────────────────┘")

print("\n┌─────────────────────────────────────────────────────────────────────┐")
print("│ VERIFICATION STATUS:                                                │")
print("├─────────────────────────────────────────────────────────────────────┤")
print(f"│ Success Rate: {verification_success_count}/{NUM_RUNS} ({verification_rate:.1f}%)                                     │")
print("└─────────────────────────────────────────────────────────────────────┘")

print("\n" + "=" * 70)
print("BREAKDOWN ANALYSIS:")
print("=" * 70)
print(f"Scheme Parameters: N={N}, M={M}, τ={tau}")
print(f"Public Key (B):                        {avg_b_size:.2f} bytes (average)")
print(f"Public outputs (t_0 + t_1 + t_2):     {t_0_size + t_1_size + avg_t2_size:.2f} bytes ({(t_0_size + t_1_size + avg_t2_size)/total_signature_size*100:.1f}%)")
print(f"Zero-knowledge proof:                  {avg_zkp_size:.2f} bytes ({avg_zkp_size/total_signature_size*100:.1f}%)")
print()
print(f"Ring Modulus q Details:")
print(f"  Value:           {mod}")
print(f"  Hexadecimal:     0x{mod:x}")
print(f"  Structure:       2^67 + {mod - 2**67}")
print(f"  Bit length:      {mod.bit_length()} bits (storage)")
print(f"  log₂(q):         ~67 bits (magnitude)")
print()
print(f"NOTE: Results are averaged over {NUM_RUNS} runs.")
print(f"      t_0 and t_1 sizes use fixed formula (5×128 + 3329 = 3969 bytes)")
print(f"      Other sizes are actual encoded averages.")
print(f"      To change N, M, or τ: modify lines 20-22 at top of file")
print("=" * 70 + "\n")

# Note: Detailed timing from C library disabled for multiple runs
# Uncomment below for single-run detailed analysis:
# print("\nDetailed prover timing:")
# print_stopwatch_lnp_prover_prove(0)
# print("\nDetailed verifier timing:")
# print_stopwatch_lnp_verifier_verify(0)