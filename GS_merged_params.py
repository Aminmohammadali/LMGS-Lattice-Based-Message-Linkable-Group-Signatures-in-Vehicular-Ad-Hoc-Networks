from math import sqrt

# ============================================================
# UNIFIED PROOF PARAMETERS WITH TWO MODULI
# ============================================================

vname = "merged_param"

# ============================================================
# Polynomial Parameters
# ============================================================

deg = 64  # Polynomial degree (common for all components)

# TWO moduli for different components:
mod_p = 3329   # Modulus for encryption public values (t_0, t_1)


# For backward compatibility with C code
mod = 2**38-3  # Default modulus (C code can override this)

# ============================================================
# Statement Matrix Dimensions
# ============================================================

# Combined: encryption proof (5 rows) + signature proof (2 rows) = 7 rows
# Combined: r(9) + id_i(1) + s_1(5) + s_2(10) + s_3(10) + w(10) = 45 columns
#(5+N)*(10+N+M+3\tau N)
m, n = 21, 269
dim = (m, n)

# ============================================================
# Witness Partitions
# ============================================================

# Keep all partitions separate
wpart = [
    list(range(0, 9)),      # r from encryption
    list(range(9, 10)),     # id_i from encryption (binary)
    list(range(10, 29)),    # s_1 from signature
    list(range(29, 109)),    # s_2 from signature
    list(range(109, 189)),    # s_3 from signature
    list(range(189, 269))     # w from signature (id_i * s_2)
]

# ============================================================
# Witness Constraints
# ============================================================

wl2 = [7000, 0, 6000, 6000, 6000, 24000]  # L2 norm bounds
wbin = [0, 1, 0, 0, 0, 0]            # Binary constraints (id_i must be binary)
wlinf = 5                            # L-infinity bound