import sys
sys.path.append('..')
from lazer import *
import hashlib
import pickle
import time
import socket
import threading

# ============================================================
# NETWORK CONFIGURATION
# ============================================================
RSU_HOST = '127.0.0.1'  # localhost - same computer
RSU_PORT = 9000
# ITS packet size constraint
ITS_MAX_PAYLOAD = 2048  # 2 KB per packet


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
# DESERIALIZATION HELPERS
# ============================================================

def deserialize_polyvec(data, ring):
    """Convert serialized polyvec back to polyvec object"""
    dim = data['dim']
    vec_data = data['data']
    
    vec = polyvec_t(ring, dim)
    for i in range(dim):
        coeffs = vec_data[i]
        poly = poly_t(ring, coeffs)
        vec.set_elem(poly, i)
    return vec

# ============================================================
# STATEMENT RECONSTRUCTION (FROM PUBLIC PARAMETERS)
# ============================================================

def reconstruct_statement(ring, params, b):
    """
    Reconstruct A_unified from public parameters and public value b.
    Everything is deterministic except b (which comes from signature).
    """
    N = params['N']
    M = params['M']
    tau = params['tau']
    m_unified = params['m_unified']
    n_unified = params['n_unified']
    
    # Reconstruct encryption matrices (deterministic from PUBLIC_PP)
    A_enc = polymat_t.urandom_static(ring, 4, 9, mod_p, PUBLIC_PP, 0)
    
    # Reconstruct signature matrices (deterministic from PUBLIC_PP)
    A = polymat_t.urandom_static(ring, N, N + M, mod, PUBLIC_PP, 10)
    B = polymat_t.urandom_static(ring, N, tau * N, mod, PUBLIC_PP, 11)
    G = polymat_t.urandom_static(ring, N, tau * N, mod, PUBLIC_PP, 12)
    B_prime = polymat_t.urandom_static(ring, N, tau * N, mod, PUBLIC_PP, 13)
    
    # Build A_unified (deterministic structure)
    A_unified = polymat_t(ring, m_unified, n_unified)
    zero_poly = poly_t(ring)
    for i in range(m_unified):
        for j in range(n_unified):
            A_unified[i, j] = zero_poly
    
    # Encryption part (rows 0-3)
    for i in range(4):
        for j in range(9):
            A_unified[i, j] = A_enc[i, j]
    
    # Row 4: b values (from signature) and p_half (constant)
    for j in range(9):
        A_unified[4, j] = b[j]
    p_half = mod // 2
    A_unified[4, 9] = poly_t(ring, {0: p_half})
    
    # Signature part (rows 5 onwards)
    for i in range(N):
        for j in range(N + M):
            A_unified[5 + i, 10 + j] = A[i, j]
        for j in range(tau * N):
            A_unified[5 + i, 10 + (N + M) + j] = B[i, j]
        for j in range(tau * N):
            A_unified[5 + i, 10 + (N + M) + tau * N + j] = B_prime[i, j]
        for j in range(tau * N):
            A_unified[5 + i, 10 + (N + M) + 2 * tau * N + j] = G[i, j]
    
    return A_unified

def reconstruct_target_from_public_values(ring, public_values, params):
    """
    Reconstruct target_unified from public ciphertext/signature values.
    These public values (t_0, t_1, u, b) are transmitted with the signature.
    """
    N = params['N']
    m_unified = params['m_unified']
    
    # Deserialize public values
    t_0 = deserialize_polyvec(public_values['t_0'], ring)
    t_1_vec = deserialize_polyvec(public_values['t_1'], ring)
    t_1 = t_1_vec[0]  # Extract single polynomial
    u = deserialize_polyvec(public_values['u'], ring)
    b = deserialize_polyvec(public_values['b'], ring)
    
    # Build target_unified
    target_unified = polyvec_t(ring, m_unified)
    
    # Encryption part (rows 0-3: t_0)
    for i in range(4):
        target_unified[i] = t_0[i]
    
    # Row 4: t_1
    target_unified[4] = t_1
    
    # Signature part (rows 5 onwards: u)
    for i in range(N):
        target_unified[5 + i] = u[i]
    
    return target_unified, b

# ============================================================
# RSU RECEIVER CLASS WITH IMMEDIATE VERIFICATION
# ============================================================

class RSU_Receiver:
    """RSU that verifies signatures IMMEDIATELY as they arrive"""
    
    def __init__(self, threshold, ring, verifier):
        self.threshold = threshold
        self.ring = ring
        self.verifier = verifier
        self.lock = threading.Lock()
        self.running = True
        
        # Track results
        self.verified_count = 0
        self.failed_count = 0
        self.rejected_count = 0  # Signatures rejected after threshold met
        self.verification_results = []
        
        # Track timing per signature
        self.first_receive_time = None
        self.last_verify_time = None
        
        # Track network delays
        self.network_delays = []  # Store network delay for each signature
        
    def verify_signature_immediately(self, sig_data, receive_time):
        """Verify signature immediately upon receipt"""
        sig_id = sig_data['signature_id']
        proof = sig_data['proof']
        proof_size = sig_data['zkp_size']
        params = sig_data['scheme_params']
        
        # Extract network delay if present
        network_delay = sig_data.get('network_delay_ms', 0)
        num_packets = sig_data.get('num_packets', 0)
        
        # ============================================================
        # OPTIMIZED: Reconstruct statement from public params + public values
        # ============================================================
        
        # Debug: show what keys are in sig_data
        print(f"  [DEBUG] Sig {sig_id} keys: {list(sig_data.keys())}")
        
        # Check if public values are provided
        if 'public_values' not in sig_data:
            print(f"  Error: No public values in Sig {sig_id}")
            print(f"  Available keys: {list(sig_data.keys())}")
            return False
        
        # Debug: show what's in public_values
        print(f"  [DEBUG] Public values keys: {list(sig_data['public_values'].keys())}")
        
        # Reconstruct target_unified from public values (t_0, t_1, u, b)
        target_unified, b = reconstruct_target_from_public_values(
            self.ring, sig_data['public_values'], params
        )
        
        # Reconstruct A_unified from public parameters and b
        A_unified = reconstruct_statement(self.ring, params, b)
        
        # Set statement
        self.verifier.set_statement(A_unified, -target_unified)
        
        # Verify
        verify_start = time.time()
        try:
            self.verifier.verify(proof)
            verify_time = time.time() - verify_start
            
            with self.lock:
                self.verified_count += 1
                count = self.verified_count
                # Store network delay
                self.network_delays.append(network_delay)
            
            status = "✓ VALID"
            valid = True
            
            # Calculate latency for THIS signature
            latency = (verify_start - receive_time) * 1000  # Time from receive to verify complete
            
            print(f"  [{count:2d}/{self.threshold}] Sig {sig_id}: {status} | "
                  f"Verify={verify_time*1000:.2f}ms | "
                  f"Network={network_delay:.2f}ms ({num_packets} pkts) | "
                  f"Size={proof_size} bytes")
            
        except Exception as e:
            verify_time = time.time() - verify_start
            
            with self.lock:
                self.failed_count += 1
            
            status = "✗ INVALID"
            valid = False
            latency = (verify_start - receive_time) * 1000
            
            print(f"  [--/{self.threshold}] Sig {sig_id}: {status} | "
                  f"Verify={verify_time*1000:.2f}ms | Error: {e}")
        
        result = {
            'id': sig_id,
            'valid': valid,
            'verify_time': verify_time,
            'receive_time': receive_time,
            'size': proof_size,
            'latency': latency,
            'network_delay': network_delay,
            'num_packets': num_packets
        }
        
        with self.lock:
            self.verification_results.append(result)
            self.last_verify_time = time.time()
        
        return valid
    
    def handle_client(self, client_socket, address):
        """Handle incoming signature from vehicle and verify immediately"""
        try:
            # Check if we've already met threshold - reject if so
            with self.lock:
                if self.verified_count >= self.threshold:
                    self.rejected_count += 1
                    print(f"[RSU] Rejecting signature from {address[0]} - threshold already met ({self.rejected_count} rejected)")
                    client_socket.send(b'REJECTED_THRESHOLD_MET')
                    client_socket.close()
                    return
            
            receive_time = time.time()  # Mark when we started receiving
            
            # Track first signature
            with self.lock:
                if self.first_receive_time is None:
                    self.first_receive_time = receive_time
            
            # Receive signature data
            data = b''
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                data += chunk
                
            if data:
                signature_data = pickle.loads(data)
                sig_id = signature_data['signature_id']
                
                with self.lock:
                    total_received = self.verified_count + self.failed_count + 1
                
                print(f"[RSU] Received Sig {sig_id} from {address[0]} (~{len(data)/1024:.1f} KB)")
                
                # VERIFY IMMEDIATELY (while other signatures may still be arriving)
                is_valid = self.verify_signature_immediately(signature_data, receive_time)
                
                # Send acknowledgment
                if is_valid:
                    client_socket.send(b'ACK_VALID')
                else:
                    client_socket.send(b'ACK_INVALID')
                
                # Check if threshold met - STOP accepting new signatures
                with self.lock:
                    if self.verified_count >= self.threshold:
                        print(f"\n✓ Threshold reached: {self.verified_count} valid signatures")
                        print(f"   Stopping - will reject any additional signatures")
                        self.running = False
                
        except Exception as e:
            print(f"[RSU] Error handling signature: {e}")
            import traceback
            traceback.print_exc()
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def start_receiving(self):
        """Start RSU server to receive and verify signatures"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((RSU_HOST, RSU_PORT))
        server_socket.listen(100)
        server_socket.settimeout(1.0)
        
        print(f"[RSU] Listening on {RSU_HOST}:{RSU_PORT}")
        print(f"[RSU] Will verify signatures IMMEDIATELY as they arrive")
        print(f"[RSU] Reconstructing A_unified from public params (not transmitted)")
        print(f"[RSU] Threshold: {self.threshold} valid signatures")
        print("-" * 70 + "\n")
        
        while self.running:
            try:
                client_socket, address = server_socket.accept()
                
                # Handle each client in separate thread
                # This allows simultaneous reception and verification
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[RSU] Accept error: {e}")
                    
        server_socket.close()
        
        # Calculate total collection time
        if self.first_receive_time and self.last_verify_time:
            total_time = (self.last_verify_time - self.first_receive_time) * 1000
        else:
            total_time = 0
        
        return total_time

# ============================================================
# CONFIGURATION
# ============================================================
THRESHOLD = 10

# Create ring
RING = polyring_t(deg, mod)
params = lib.get_params("merged_param")
verifier = lin_verifier_state_t(P1PP, params)

print("=" * 70)
print("RSU - OPTIMIZED VERIFICATION (STATEMENT RECONSTRUCTION)")
print("=" * 70)
print(f"Threshold: {THRESHOLD} valid signatures required")
print(f"Strategy: Reconstruct A_unified from public params (not transmitted)")
print(f"          Reduces transmission: ~1300 KB → ~85 KB per signature")
print("=" * 70 + "\n")

# ============================================================
# RECEIVE AND VERIFY SIGNATURES
# ============================================================

rsu = RSU_Receiver(THRESHOLD, RING, verifier)
total_time = rsu.start_receiving()

# ============================================================
# CALCULATE PROPER END-TO-END LATENCY
# ============================================================

print("\n" + "=" * 70)
print("RESULTS - OPTIMIZED PROTOCOL")
print("=" * 70)

# Sort results by signature ID for analysis
results = sorted(rsu.verification_results, key=lambda x: x['id'])

print(f"\nSignature Statistics:")
print(f"  Total verified:        {rsu.verified_count}")
print(f"  Total failed:          {rsu.failed_count}")
print(f"  Total rejected:        {rsu.rejected_count} (arrived after threshold met)")
print(f"  Threshold:             {THRESHOLD}")
print(f"  Status:                {'✓ THRESHOLD MET' if rsu.verified_count >= THRESHOLD else '✗ THRESHOLD NOT MET'}")

# Calculate per-signature metrics
valid_results = [r for r in results if r['valid']]

if valid_results:
    verify_times = [r['verify_time'] * 1000 for r in valid_results]
    avg_verify_time = sum(verify_times) / len(verify_times)
    
    print(f"\nPer-Signature Verification Time:")
    print(f"  Average: {avg_verify_time:.2f}ms")
    print(f"  Min:     {min(verify_times):.2f}ms")
    print(f"  Max:     {max(verify_times):.2f}ms")
    
    # Network delay statistics
    network_delays = [r.get('network_delay', 0) for r in valid_results]
    avg_network_delay = sum(network_delays) / len(network_delays) if network_delays else 0
    
    # Check if we have actual network delay data
    has_network_data = any(d > 0 for d in network_delays)
    
    print(f"\nNetwork Delay (per signature):")
    if not has_network_data:
        print(f"  ⚠ WARNING: No network delay data found in signatures!")
        print(f"  This means you're using the OLD sender script.")
        print(f"  Please use the UPDATED Vehicle_signer_one_by_one.py")
        print(f"  Falling back to theoretical calculation...")
        
        # Fallback: Calculate theoretical network delay
        avg_size = sum(r['size'] for r in valid_results) / len(valid_results)
        calc_packets = int((avg_size + ITS_MAX_PAYLOAD - 1) // ITS_MAX_PAYLOAD)
        delay_per_packet = 20  # ms (from low_congestion config)
        theoretical_delay = calc_packets * delay_per_packet
        
        print(f"  Theoretical avg delay: {theoretical_delay:.2f}ms ({calc_packets} pkts × {delay_per_packet}ms)")
        avg_network_delay = theoretical_delay
        avg_packets = calc_packets
    else:
        print(f"  Average: {avg_network_delay:.2f}ms")
        print(f"  Min:     {min(network_delays):.2f}ms")
        print(f"  Max:     {max(network_delays):.2f}ms")
        
        # Packet statistics
        if 'num_packets' in valid_results[0]:
            num_packets_list = [r['num_packets'] for r in valid_results]
            avg_packets = sum(num_packets_list) / len(num_packets_list)
            print(f"  Avg packets: {avg_packets:.1f}")
            if avg_packets > 0:
                print(f"  Avg delay per packet: {avg_network_delay/avg_packets:.2f}ms")
            else:
                print(f"  Avg delay per packet: N/A (no packets recorded)")
        else:
            # Calculate packets from size
            avg_size = sum(r['size'] for r in valid_results) / len(valid_results)
            avg_packets = (avg_size + ITS_MAX_PAYLOAD - 1) // ITS_MAX_PAYLOAD
            print(f"  Avg packets (calculated): {avg_packets:.1f}")

# OPTIMIZATION SUMMARY
print(f"\n" + "=" * 70)
print("OPTIMIZATION SUMMARY")
print("=" * 70)

if valid_results:
    avg_size = sum(r['size'] for r in valid_results) / len(valid_results)
    print(f"\n✓ Transmission Reduction:")
    print(f"  Old: ~1300 KB per signature (proof + A_unified + target_unified)")
    print(f"  New: ~{avg_size/1024:.0f} KB per signature (proof only)")
    print(f"  Savings: ~{1300 - avg_size/1024:.0f} KB per signature (15× reduction)")
    
    print(f"\n✓ Network Improvements:")
    print(f"  Old: ~655 ITS packets per signature")
    print(f"  New: ~{int((avg_size + 2047) / 2048)} ITS packets per signature")
    print(f"  Reduction: ~{655 - int((avg_size + 2047) / 2048)} fewer packets per signature")
    
    print(f"\n✓ Latency Improvements:")
    print(f"  Old network delay: ~13 seconds per signature (655 packets × 20ms)")
    print(f"  New network delay: ~{int((avg_size + 2047) / 2048) * 20}ms per signature ({int((avg_size + 2047) / 2048)} packets × 20ms)")
    print(f"  Improvement: ~{13000 - int((avg_size + 2047) / 2048) * 20}ms faster per signature")

# ============================================================
# TOTAL TIME CALCULATION
# ============================================================

print(f"\n" + "=" * 70)
print(f"TOTAL TIME CALCULATION (For Threshold t={THRESHOLD})")
print("=" * 70)

if valid_results:
    avg_verify_ms = sum(r['verify_time'] * 1000 for r in valid_results) / len(valid_results)
    avg_size = sum(r['size'] for r in valid_results) / len(valid_results)
    
    # Use ACTUAL network delay from signatures if available, otherwise calculate
    network_delays_data = [r.get('network_delay', 0) for r in valid_results]
    has_network_data = any(d > 0 for d in network_delays_data)
    
    if has_network_data:
        # Use actual measured network delay
        avg_network_delay = sum(network_delays_data) / len(network_delays_data)
        
        # Get actual packet count
        if 'num_packets' in valid_results[0]:
            num_packets_list = [r['num_packets'] for r in valid_results]
            avg_packets = sum(num_packets_list) / len(num_packets_list)
        else:
            avg_packets = (avg_size + ITS_MAX_PAYLOAD - 1) // ITS_MAX_PAYLOAD
    else:
        # Fallback: Calculate theoretical network delay
        avg_packets = (avg_size + ITS_MAX_PAYLOAD - 1) // ITS_MAX_PAYLOAD
        delay_per_packet = 20  # ms (from low_congestion config)
        avg_network_delay = avg_packets * delay_per_packet
    
    # From sender (you can update this with actual average from sender)
    generation_time = 237.0  # ms
    
    # Total = 1 × Gen + 1 × Network + t × Verify
    # Using ACTUAL measured network delay (or theoretical if not available)
    total = generation_time + avg_network_delay + (avg_verify_ms * THRESHOLD)
    
    print(f"\nFormula: Total = 1 × Gen + 1 × Network + {THRESHOLD} × Verify")
    print(f"\nComponents:")
    print(f"  1 × Generation:     {generation_time:.2f}ms")
    if has_network_data:
        print(f"  1 × Network (ITS):  {avg_network_delay:.2f}ms (actual measured, {avg_packets:.0f} pkts)")
    else:
        print(f"  1 × Network (ITS):  {avg_network_delay:.2f}ms (theoretical, {avg_packets:.0f} pkts)")
    print(f"  {THRESHOLD} × Verification:   {avg_verify_ms:.2f}ms × {THRESHOLD} = {avg_verify_ms * THRESHOLD:.2f}ms")
    print(f"  " + "-" * 60)
    print(f"  TOTAL TIME:         {total:.2f}ms")
    
    print(f"\nComparison:")
    unoptimized = 237 + 13000 + (avg_verify_ms * THRESHOLD)
    print(f"  Unoptimized: {unoptimized:.0f}ms")
    print(f"  Optimized:   {total:.0f}ms")
    print(f"  Speedup: {unoptimized/total:.1f}× faster")
    
    print(f"\nNetwork Delay Breakdown:")
    if has_network_data:
        print(f"  Min delay: {min(network_delays_data):.2f}ms")
        print(f"  Max delay: {max(network_delays_data):.2f}ms")
        print(f"  Avg delay: {avg_network_delay:.2f}ms (actual measured)")
        if avg_packets > 0:
            print(f"  Per packet: {avg_network_delay/avg_packets:.2f}ms")
    else:
        print(f"  Avg delay: {avg_network_delay:.2f}ms (theoretical calculation)")
        print(f"  Note: Using old sender - no actual network delay data")
        if avg_packets > 0:
            print(f"  Per packet: {avg_network_delay/avg_packets:.2f}ms (theoretical)")

# DETAILED RESULTS
# ============================================================

print("\n" + "-" * 70)
print(f"Individual Signature Details:")
print("-" * 70)

for r in results:
    status = "✓ VALID  " if r['valid'] else "✗ INVALID"
    network_info = f"Network={r['network_delay']:.2f}ms | " if 'network_delay' in r else ""
    print(f"  Sig {r['id']:2d}: {status} | "
          f"Verify={r['verify_time']*1000:6.2f}ms | "
          f"{network_info}"
          f"Size={r['size']} bytes ({r['size']/1024:.1f} KB)")

# ============================================================
# FINAL DECISION
# ============================================================

print("\n" + "=" * 70)
print("FINAL DECISION")
print("=" * 70)

threshold_met = rsu.verified_count >= THRESHOLD

if threshold_met:
    decision = "ACCEPTED"
    print(f"\n{'  '*8}✓✓✓ {decision} ✓✓✓")
    print(f"\n  Threshold requirement met: {rsu.verified_count} ≥ {THRESHOLD}")
    print(f"  Only first {THRESHOLD} signatures verified (rest rejected/ignored)")
    if valid_results:
        avg_verify = sum(r['verify_time'] * 1000 for r in valid_results) / len(valid_results)
        total_verify = avg_verify * THRESHOLD
        print(f"\n  Total verification time for {THRESHOLD} signatures: {total_verify:.2f}ms")
        print(f"  Formula: 1 × Gen + 1 × Delay + {THRESHOLD} × Verify")
else:
    decision = "REJECTED"
    print(f"\n{'  '*8}✗✗✗ {decision} ✗✗✗")
    print(f"\n  Threshold requirement NOT met: {rsu.verified_count} < {THRESHOLD}")
    print(f"  Need {THRESHOLD - rsu.verified_count} more valid signature(s)")

print("\n" + "=" * 70 + "\n")