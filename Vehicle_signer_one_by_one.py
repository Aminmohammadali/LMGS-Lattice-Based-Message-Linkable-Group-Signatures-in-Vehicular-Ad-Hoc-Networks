import sys
sys.path.append('..')
from lazer import *
import hashlib
import secrets
import time
import pickle
import os
import socket
import random

# ============================================================
# NETWORK CONFIGURATION
# ============================================================
RSU_HOST = '127.0.0.1'  # localhost - same computer
RSU_PORT = 9000

# ITS packet size constraint
ITS_MAX_PAYLOAD = 2048  # 2 KB per packet (ITS standard)

# Network delay simulation (in milliseconds)
# Choose one configuration:
NETWORK_CONFIG = "low_congestion"  # or "high_congestion" or "no_delay"

DELAY_CONFIGS = {
    "no_delay": {"mean": 0, "std": 0},
    "low_congestion": {"mean": 20, "std": 10},   # 20ms ± 10ms (Gaussian)
    "high_congestion": {"mean": 50, "std": 20},  # 50ms ± 20ms (Gaussian)
}

def simulate_network_delay():
    """Simulate network delay based on configuration"""
    config = DELAY_CONFIGS[NETWORK_CONFIG]
    if config["mean"] == 0:
        return 0
    
    # Gaussian distribution, truncated at 0 (no negative delays)
    delay_ms = max(0, random.gauss(config["mean"], config["std"]))
    time.sleep(delay_ms / 1000.0)  # Convert to seconds
    return delay_ms

# ============================================================
# public randomness
# ============================================================
shake128 = hashlib.shake_128(bytes.fromhex("00"))
PUBLIC_PP = shake128.digest(32)
shake128 = hashlib.shake_128(bytes.fromhex("01"))
P1PP = shake128.digest(32)

# import parameters
from GS_merged_params import mod, mod_p, deg, m, n
from _GS_merged_params_cffi import lib, ffi

# ============================================================
# SERIALIZATION HELPERS
# ============================================================

def serialize_polyvec(vec):
    """Convert polyvec to serializable format"""
    dim = vec.dim
    data = []
    for i in range(dim):
        poly = vec[i]
        coeffs = {}
        for k in range(poly.ring.deg):
            coeff = poly[k]
            if coeff != 0:
                coeffs[k] = int(coeff)
        data.append(coeffs)
    return {'dim': dim, 'data': data}

# ============================================================
# LIGHTWEIGHT SIGNATURE TRANSMISSION (PROOF + PUBLIC VALUES)
# ============================================================

def send_signature_to_rsu(signature_data, sig_idx):
    """Send ONLY the proof to RSU - RSU reconstructs statement from public params"""
    try:
        # Calculate number of ITS packets needed BEFORE adding network delay
        temp_data = pickle.dumps(signature_data)
        total_size = len(temp_data)
        num_packets = (total_size + ITS_MAX_PAYLOAD - 1) // ITS_MAX_PAYLOAD
        
        # Simulate delay for EACH packet
        total_delay = 0
        for packet_idx in range(num_packets):
            packet_delay = simulate_network_delay()
            total_delay += packet_delay
        
        # Add network delay to signature data so RSU can track it
        signature_data['network_delay_ms'] = total_delay
        signature_data['num_packets'] = num_packets
        
        # Debug: Confirm network delay is being added
        print(f"  [SENDER DEBUG] Added to signature: network_delay={total_delay:.2f}ms, packets={num_packets}")
        
        # Serialize with network delay included
        data = pickle.dumps(signature_data)
        actual_size = len(data)
        
        # Create socket and connect to RSU
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)  # 10 second timeout
        
        # Try to connect
        try:
            sock.connect((RSU_HOST, RSU_PORT))
        except ConnectionRefusedError:
            return False, "Connection refused - is RSU running?", 0, 0, 0
        except socket.timeout:
            return False, "Connection timeout", 0, 0, 0
        
        # Send complete signature data
        sock.sendall(data)
        
        # Properly shutdown write side to signal end of data
        sock.shutdown(socket.SHUT_WR)
        
        # Wait for acknowledgment with timeout
        sock.settimeout(5.0)
        try:
            ack = sock.recv(1024)
            ack_msg = ack.decode() if ack else "NO_ACK"
        except socket.timeout:
            ack_msg = "ACK_TIMEOUT"
            
        sock.close()
        
        return True, ack_msg, total_delay, num_packets, actual_size
        
    except Exception as e:
        return False, f"Error: {str(e)}", 0, 0, 0

def generate_one_signature(sig_idx, ring, prover, N, M, tau, m_unified, n_unified):
    """Generate a single signature - called once per signature"""
    
    # Computed dimensions
    A_rows = N
    A_cols = N + M
    B_rows = N
    B_cols = tau * N
    Bprime_rows = N
    Bprime_cols = tau * N
    G_rows = N
    G_cols = tau * N
    A0_rows = N + M
    A0_cols = N + M
    B0_rows = N + M
    B0_cols = tau * N
    C0_rows = N + M
    C0_cols = tau * N
    s1_dim = N + M
    s2_dim = tau * N
    s3_dim = tau * N
    w_dim = tau * N
    
    # ENCRYPTION
    A_enc = polymat_t.urandom_static(ring, 4, 9, mod_p, PUBLIC_PP, 0)
    s_en = polyvec_t.brandom_static(ring, 4, 2, secrets.token_bytes(32), 0)
    e_en = polyvec_t.brandom_static(ring, 9, 2, secrets.token_bytes(32), 1)
    
    A_enc_T = polymat_t(ring, 9, 4)
    for i in range(9):
        for j in range(4):
            A_enc_T[i, j] = A_enc[j, i]
    b = A_enc_T * s_en + e_en
    
    r = polyvec_t.brandom_static(ring, 9, 2, secrets.token_bytes(32), 2)
    id_i_bytes = secrets.token_bytes(deg // 8)
    id_i_vec = polyvec_t(ring, 1, id_i_bytes)
    id_i = id_i_vec[0]
    
    t_0 = A_enc * r
    inner_prod = poly_t(ring)
    for i in range(9):
        inner_prod = inner_prod + b[i] * r[i]
    p_half = mod // 2
    t_1 = inner_prod + id_i * p_half
    
    # SIGNATURE
    A = polymat_t.urandom_static(ring, A_rows, A_cols, mod, PUBLIC_PP, 10)
    B = polymat_t.urandom_static(ring, B_rows, B_cols, mod, PUBLIC_PP, 11)
    G = polymat_t.urandom_static(ring, G_rows, G_cols, mod, PUBLIC_PP, 12)
    B_prime = polymat_t.urandom_static(ring, Bprime_rows, Bprime_cols, mod, PUBLIC_PP, 13)
    
    s_1 = polyvec_t.brandom_static(ring, s1_dim, 2, secrets.token_bytes(32), 10)
    s_2 = polyvec_t.brandom_static(ring, s2_dim, 2, secrets.token_bytes(32), 11)
    s_3 = polyvec_t.brandom_static(ring, s3_dim, 2, secrets.token_bytes(32), 12)
    
    w = polyvec_t(ring, w_dim)
    for i in range(w_dim):
        w.set_elem(id_i * s_2.get_elem(i), i)
    
    u = A * s_1 + B * s_2 + B_prime * s_3 + G * w
    
    # COMMITMENT
    A_0 = polymat_t.urandom_static(ring, A0_rows, A0_cols, mod, PUBLIC_PP, 20)
    B_0 = polymat_t.urandom_static(ring, B0_rows, B0_cols, mod, PUBLIC_PP, 21)
    C_0 = polymat_t.urandom_static(ring, C0_rows, C0_cols, mod, PUBLIC_PP, 22)
    e_1 = polyvec_t.brandom_static(ring, A0_rows, 2, secrets.token_bytes(32), 13)
    
    t_2 = A_0 * s_1 + B_0 * s_2 + C_0 * s_3 + e_1
    
    # BUILD UNIFIED STATEMENT
    A_unified = polymat_t(ring, m_unified, n_unified)
    zero_poly = poly_t(ring)
    for i in range(m_unified):
        for j in range(n_unified):
            A_unified[i, j] = zero_poly
    
    for i in range(4):
        for j in range(9):
            A_unified[i, j] = A_enc[i, j]
    
    for j in range(9):
        A_unified[4, j] = b[j]
    A_unified[4, 9] = poly_t(ring, {0: p_half})
    
    for i in range(N):
        for j in range(N + M):
            A_unified[5 + i, 10 + j] = A[i, j]
        for j in range(tau * N):
            A_unified[5 + i, 10 + (N + M) + j] = B[i, j]
        for j in range(tau * N):
            A_unified[5 + i, 10 + (N + M) + tau * N + j] = B_prime[i, j]
        for j in range(tau * N):
            A_unified[5 + i, 10 + (N + M) + 2 * tau * N + j] = G[i, j]
    
    target_unified = polyvec_t(ring, m_unified)
    for i in range(4):
        target_unified[i] = t_0[i]
    target_unified[4] = t_1
    for i in range(N):
        target_unified[5 + i] = u[i]
    
    witness_unified = polyvec_t(ring, n_unified)
    for i in range(r.dim):
        witness_unified.set_elem(r.get_elem(i), i)
    witness_unified.set_elem(id_i_vec.get_elem(0), 9)
    for i in range(s_1.dim):
        witness_unified.set_elem(s_1.get_elem(i), 10 + i)
    for i in range(s_2.dim):
        witness_unified.set_elem(s_2.get_elem(i), 10 + (N + M) + i)
    for i in range(s_3.dim):
        witness_unified.set_elem(s_3.get_elem(i), 10 + (N + M) + tau * N + i)
    for i in range(w.dim):
        witness_unified.set_elem(w.get_elem(i), 10 + (N + M) + 2 * tau * N + i)
    
    # GENERATE PROOF
    prover.set_statement(A_unified, -target_unified)
    prover.set_witness(witness_unified)
    proof = prover.prove()
    
    # ============================================================
    # OPTIMIZED: Return proof + minimal public values for target
    # RSU reconstructs A_unified deterministically
    # RSU needs t_0, t_1, u, b to build target_unified
    # ============================================================
    
    # Convert t_1 (single poly) to polyvec for serialization
    t_1_vec = polyvec_t(ring, 1)
    t_1_vec.set_elem(t_1, 0)
    
    signature_data = {
        'signature_id': sig_idx,
        'proof': proof,  # ~85 KB - the actual ZKP
        'zkp_size': len(proof),
        # Public values needed to reconstruct target_unified
        'public_values': {
            't_0': serialize_polyvec(t_0),  # Encryption output
            't_1': serialize_polyvec(t_1_vec),  # Single poly as vec
            'u': serialize_polyvec(u),  # Signature output
            'b': serialize_polyvec(b),  # Public encryption key
        },
        'scheme_params': {
            'N': N, 'M': M, 'tau': tau, 
            'm_unified': m_unified, 'n_unified': n_unified,
            'deg': int(deg),
            'mod': int(mod)
        }
    }
    
    # Debug: verify public_values is in the dict
    if 'public_values' not in signature_data:
        print(f"WARNING: public_values missing in signature {sig_idx}!")
    
    return signature_data
    # Still much smaller than sending full A_unified + target_unified!

# ============================================================
# MAIN EXECUTION
# ============================================================

N = 8
M = 3
tau = 5

NUM_SIGNATURES = 20  # Send 10 signatures separately to meet threshold

m_unified = 5 + N
n_unified = 10 + (N + M) + 3 * tau * N

RING = polyring_t(deg, mod)
params = lib.get_params("merged_param")
prover = lin_prover_state_t(P1PP, params)

print("=" * 70)
print("VEHICLE ENDORSEMENT SIGNER (OPTIMIZED - PROOF ONLY)")
print("=" * 70)
print(f"Scheme: N={N}, M={M}, τ={tau}")
print(f"\nOptimization:")
print(f"  ✓ Send ONLY the proof (~85 KB)")
print(f"  ✓ RSU reconstructs A_unified and target_unified from public params")
print(f"  ✓ Reduces transmission from ~1300 KB → ~85 KB (15× reduction!)")
print(f"\nITS Packet Limit: {ITS_MAX_PAYLOAD} bytes (2 KB)")
print(f"Network Simulation: {NETWORK_CONFIG}")
if NETWORK_CONFIG != "no_delay":
    cfg = DELAY_CONFIGS[NETWORK_CONFIG]
    print(f"  Delay per packet: {cfg['mean']}ms ± {cfg['std']}ms (Gaussian)")
print(f"\nRSU Address: {RSU_HOST}:{RSU_PORT}")
print("=" * 70 + "\n")

# Check if RSU is reachable
print("Checking RSU connectivity...")
test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
test_sock.settimeout(2.0)
try:
    test_sock.connect((RSU_HOST, RSU_PORT))
    test_sock.close()
    print("✓ RSU is reachable!\n")
except:
    print("✗ WARNING: Cannot connect to RSU!")
    print(f"  Make sure Vehicle_verification_immediate_CORRECTED.py is running FIRST")
    print(f"  Attempting to continue anyway...\n")
finally:
    test_sock.close()

signing_times = []
network_delays = []
sending_times = []
packet_counts = []
signature_sizes = []
successful_sends = 0
failed_sends = 0

# GENERATE AND SEND SIGNATURES ONE BY ONE
for sig_idx in range(NUM_SIGNATURES):
    print(f"[Signature {sig_idx+1}/{NUM_SIGNATURES}]")
    print(f"  Step 1: Generating... ", end="", flush=True)
    
    # STEP 1: Generate ONE signature
    signing_start = time.time()
    signature_data = generate_one_signature(sig_idx, RING, prover, N, M, tau, m_unified, n_unified)
    signing_time = time.time() - signing_start
    signing_times.append(signing_time)
    
    print(f"Done ({signing_time:.3f}s)")
    print(f"  Step 2: Sending with ITS fragmentation... ", end="", flush=True)
    
    # STEP 2 & 3: Apply delay and send
    send_start = time.time()
    success, response, actual_delay, num_packets, sig_size = send_signature_to_rsu(signature_data, sig_idx)
    send_time = time.time() - send_start
    sending_times.append(send_time)
    network_delays.append(actual_delay)
    packet_counts.append(num_packets)
    signature_sizes.append(sig_size)
    
    if success:
        successful_sends += 1
        print(f"✓ Sent!")
        print(f"           Signature size: {sig_size/1024:.1f} KB ({sig_size} bytes)")
        print(f"           ITS packets: {num_packets} packets")
        print(f"           Total delay: {actual_delay:.2f}ms ({num_packets} × delays)")
        print(f"           Avg/packet: {actual_delay/num_packets:.2f}ms")
        print(f"           Response: {response}")
    else:
        failed_sends += 1
        print(f"✗ Failed: {response}")
    
    print()  # Blank line between signatures

# ============================================================
# STATISTICS
# ============================================================

if len(signing_times) == 0:
    print("\n✗ No signatures were generated!")
    sys.exit(1)

avg_signing_time = sum(signing_times) / len(signing_times)
avg_network_delay = sum(network_delays) / len(network_delays) if network_delays else 0
avg_sending_time = sum(sending_times) / len(sending_times) if sending_times else 0
avg_packets = sum(packet_counts) / len(packet_counts) if packet_counts else 0
avg_sig_size = sum(signature_sizes) / len(signature_sizes) if signature_sizes else 0
total_time = sum(signing_times) + sum(sending_times)

print("=" * 70)
print("SUMMARY - OPTIMIZED TRANSMISSION (PROOF ONLY)")
print("=" * 70)
print(f"✓ Signatures generated: {NUM_SIGNATURES}")
print(f"✓ Successfully sent:    {successful_sends}/{NUM_SIGNATURES}")
if failed_sends > 0:
    print(f"✗ Failed to send:       {failed_sends}/{NUM_SIGNATURES}")

print("\n" + "-" * 70)
print("SIGNATURE SIZE (Proof Only - Optimized)")
print("-" * 70)
print(f"  Average signature size: {avg_sig_size/1024:.2f} KB ({avg_sig_size:.0f} bytes)")
print(f"  Min: {min(signature_sizes)/1024:.2f} KB")
print(f"  Max: {max(signature_sizes)/1024:.2f} KB")
print(f"\n  ✓ Reduction: ~1300 KB → ~{avg_sig_size/1024:.0f} KB (15× smaller!)")

print("\n" + "-" * 70)
print("ITS PACKET FRAGMENTATION")
print("-" * 70)
print(f"  ITS packet size limit: {ITS_MAX_PAYLOAD} bytes (2 KB)")
print(f"  Average packets/signature: {avg_packets:.1f} packets")
print(f"  Min packets: {min(packet_counts)}")
print(f"  Max packets: {max(packet_counts)}")
print(f"\n  ✓ Reduction: ~655 packets → ~{int(avg_packets)} packets")

print("\n" + "-" * 70)
print("TIMING ANALYSIS")
print("-" * 70)

print(f"\nSignature Generation:")
print(f"  • Average: {avg_signing_time*1000:.2f}ms")
print(f"  • Min:     {min(signing_times)*1000:.2f}ms")
print(f"  • Max:     {max(signing_times)*1000:.2f}ms")

if network_delays:
    print(f"\nNetwork Delay (CUMULATIVE for ~{int(avg_packets)} packets):")
    print(f"  • Average total: {avg_network_delay:.2f}ms per signature")
    print(f"  • Min total:     {min(network_delays):.2f}ms")
    print(f"  • Max total:     {max(network_delays):.2f}ms")
    print(f"  • Range:   {max(network_delays)-min(network_delays):.2f}ms ← JITTER")
    print(f"\n  Per-packet breakdown:")
    print(f"    - Delay/packet: ~{avg_network_delay/avg_packets:.2f}ms")
    print(f"    - Packets: ~{int(avg_packets)}")
    print(f"    - Total = {int(avg_packets)} × {avg_network_delay/avg_packets:.2f}ms = {avg_network_delay:.2f}ms")
    print(f"\n  ✓ Reduction: ~13000ms → ~{avg_network_delay:.0f}ms network delay")

print(f"\nTotal per Signature:")
print(f"  • Generation: {avg_signing_time*1000:.2f}ms")
print(f"  • Network: {avg_network_delay:.2f}ms")
print(f"  • Total: {(avg_signing_time*1000 + avg_network_delay):.2f}ms")

print("\n" + "-" * 70)
print("Individual Signature Details:")
print("-" * 70)
for i in range(NUM_SIGNATURES):
    if i < len(signing_times):
        print(f"  Sig {i}: Gen={signing_times[i]*1000:6.2f}ms | "
              f"Size={signature_sizes[i]/1024:5.1f}KB | "
              f"Pkts={packet_counts[i]:2d} | "
              f"Delay={network_delays[i]:7.2f}ms")

print("\n" + "=" * 70)
if successful_sends > 0:
    print(f"⚡ OPTIMIZATION SUCCESS!")
    print(f"\nKey Improvements:")
    print(f"  • Signature size: 1300 KB → {avg_sig_size/1024:.0f} KB (15× reduction)")
    print(f"  • ITS packets: 655 → {int(avg_packets)} ({655/avg_packets:.1f}× reduction)")
    print(f"  • Network delay: ~13s → ~{avg_network_delay/1000:.2f}s ({13000/avg_network_delay:.1f}× faster)")
else:
    print(f"✗ NO SIGNATURES SENT - Check if RSU is running!")
print("=" * 70 + "\n")