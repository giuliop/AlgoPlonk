package verifier

const tmplSmartContractVerifierBls12_381 = `# Code automatically generated - DO NOT EDIT.

import typing

import algopy as py
from algopy import subroutine, BigUInt, Bytes, arc4, UInt64, urange
from algopy.arc4 import UInt256, abimethod, DynamicArray, StaticArray, String
from algopy.op import bzero, sha256, EllipticCurve as ec, EC, setbit_bytes

Bytes32: typing.TypeAlias = StaticArray[arc4.Byte, typing.Literal[32]]

#################### Curve parameters #################

# curve order
R_MOD = 52435875175126190479447740508185965837690552500527637822603658699938581184513

# field order
P_MOD = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787

#################### Trusted setup ####################
{{ range $index, $element := .Kzg.G2 }}
G2_SRS_{{ $index }}_X_0 = {{ (fpstr $element.X.A1) }}
G2_SRS_{{ $index }}_X_1 = {{ (fpstr $element.X.A0) }}
G2_SRS_{{ $index }}_Y_0 = {{ (fpstr $element.Y.A1) }}
G2_SRS_{{ $index }}_Y_1 = {{ (fpstr $element.Y.A0) }}
{{ end }}
G1_SRS_X = {{ fpstr .Kzg.G1.X }}
G1_SRS_Y = {{ fpstr .Kzg.G1.Y }}

######################################################


class {{ (contractName) }}(py.ARC4Contract):
	@abimethod(create='require')
	def create(self, name: String) -> None:
		"""On creation, save application name in global state"""
		self.app_name = name
		self.immutable = False

	@abimethod(allow_actions=["UpdateApplication", "DeleteApplication"])
	def update(self) -> None:
		"""Creator can update and delete the application if the immutable
		   property is false."""
		assert not self.immutable
		assert py.Global.creator_address == py.Txn.sender

	@abimethod
	def make_immutable(self) -> None:
		"""Creator can make the contract immutable."""
		assert py.Global.creator_address == py.Txn.sender
		self.immutable = True

	@abimethod
	def verify(self,
	           proof: DynamicArray[Bytes32],
			   public_inputs: DynamicArray[Bytes32],
			   ) -> arc4.Bool:
		"""Verify the proof for the given public inputs.
		   Return a boolean indicating whether the proof is valid"""

		q = BigUInt(R_MOD)

		# check proof and public inputs lengths
		assert proof.length == 33
		assert public_inputs.length == {{ .NbPublicVariables }}

		### Read verifying key ###
		VK_NB_PUBLIC_INPUTS = UInt64({{ .NbPublicVariables }})
		VK_DOMAIN_SIZE = BigUInt({{ .Size }})
		VK_INV_DOMAIN_SIZE = BigUInt({{ (frstr .SizeInv) }})
		VK_OMEGA = BigUInt({{ (frstr .Generator) }})

		VK_QL = Bytes.from_hex("{{ hex .Ql }}")
		VK_QR = Bytes.from_hex("{{ hex .Qr }}")
		VK_QO = Bytes.from_hex("{{ hex .Qo }}")
		VK_QM = Bytes.from_hex("{{ hex .Qm }}")
		VK_QK = Bytes.from_hex("{{ hex .Qk }}")

		{{range $index, $element := .S -}}
		VK_S{{ inc $index }} = Bytes.from_hex("{{ hex $element }}")
		{{ end }}
		VK_COSET_SHIFT = BigUInt({{ (frstr .CosetShift) }})

		# Read the fiat-shamir values of the verifying key to match gnark's encoding of the point at infinity
		VK_QL_fs = Bytes.from_hex("{{ hexEncoded .Ql }}")
		VK_QR_fs = Bytes.from_hex("{{ hexEncoded .Qr }}")
		VK_QO_fs = Bytes.from_hex("{{ hexEncoded .Qo }}")
		VK_QM_fs = Bytes.from_hex("{{ hexEncoded .Qm }}")
		VK_QK_fs = Bytes.from_hex("{{ hexEncoded .Qk }}")
		{{range $index, $element := .S }}
		VK_S{{ inc $index }}_fs = Bytes.from_hex("{{ hexEncoded $element }}")
		{{ end }}

		### Read proof ###
		# wires commitments
		L_COM = proof[0].bytes + proof[1].bytes + proof[2].bytes
		R_COM = proof[3].bytes + proof[4].bytes + proof[5].bytes
		O_COM = proof[6].bytes + proof[7].bytes + proof[8].bytes

		# h = h_0 + x^{n+2}h_1 + x^{2(n+2)}h_2
		H_0 = proof[9].bytes + proof[10].bytes + proof[11].bytes
		H_1 = proof[12].bytes + proof[13].bytes + proof[14].bytes
		H_2 = proof[15].bytes + proof[16].bytes + proof[17].bytes

		# wire values at zeta
		L_AT_Z = proof[18].copy()
		R_AT_Z = proof[19].copy()
		O_AT_Z = proof[20].copy()

		S1_AT_Z = proof[21].copy() 						  # s1(zeta)
		S2_AT_Z = proof[22].copy() 						  # s2(zeta)
		# z(x)
		GRAND_PRODUCT = proof[23].bytes + proof[24].bytes + proof[25].bytes
		GRAND_PRODUCT_AT_Z_OMEGA = proof[26].copy()       # z(w*zeta)

		# Folded proof for opening of linear poly, l, r, o, s1, s2
		BATCH_OPENING_AT_Z = proof[27].bytes + proof[28].bytes + proof[29].bytes

		# opening at zeta * omega
		OPENING_AT_Z_OMEGA = proof[30].bytes + proof[31].bytes + proof[32].bytes

		### check proof public inputs are well-formed ###
		if (BigUInt.from_bytes(L_AT_Z.bytes) >= q
				or BigUInt.from_bytes(R_AT_Z.bytes) >= q
				or BigUInt.from_bytes(O_AT_Z.bytes) >= q
				or BigUInt.from_bytes(S1_AT_Z.bytes) >= q
				or BigUInt.from_bytes(S2_AT_Z.bytes) >= q
				or BigUInt.from_bytes(GRAND_PRODUCT_AT_Z_OMEGA.bytes) >= q
		):
			{{/*}}py.log("error: invalid proof"){{*/ -}}
			return arc4.Bool(False)

		for i in urange(public_inputs.length):
			if BigUInt.from_bytes(public_inputs[i].bytes) >= q:
				{{/*}}py.log(b"error: invalid public inputs"){{*/ -}}
				return arc4.Bool(False)

		### Verify the proof ###

		# Compute the fiat-shamir challenges as the prover (gnark).
		# After deriving all challenges, we need to make them modulo R_MOD.

		public_inputs_bytes = Bytes(b'')
		for i in urange(public_inputs.length):
			public_inputs_bytes += public_inputs[i].bytes

		gamma_pre = sha256(b'gamma' + VK_S1_fs + VK_S2_fs + VK_S3_fs + VK_QL_fs
					+ VK_QR_fs + VK_QM_fs + VK_QO_fs + VK_QK_fs + public_inputs_bytes
					+ fs(L_COM) + fs(R_COM) + fs(O_COM))
		beta_pre = sha256(b'beta' + gamma_pre)
		alpha_pre = sha256(b'alpha' + beta_pre + fs(GRAND_PRODUCT))
		zeta_pre = sha256(b'zeta' + alpha_pre + fs(H_0) + fs(H_1) + fs(H_2))

		gamma = curvemod(gamma_pre)
		beta = curvemod(beta_pre)
		alpha = curvemod(alpha_pre)
		zeta = curvemod(zeta_pre)

		# Zz is eval of Xⁿ-1 at zeta
		Zz = (expmod(zeta, VK_DOMAIN_SIZE, q) + q - BigUInt(1)) % q

		# zn is Zz * 1/n
		zn = (Zz * VK_INV_DOMAIN_SIZE) % q

		# Let's prepare to interpolate the public inputs
		w_ = BigUInt(1)
		batch = DynamicArray[UInt256]()
		for i in urange(VK_NB_PUBLIC_INPUTS):
			x = (zeta + q - w_) % q
			batch.append(UInt256(x))
			w_ = (w_ * VK_OMEGA) % q

		# Compute batch inversion
		temp = DynamicArray[UInt256]()
		prev = BigUInt(1)
		temp.append(UInt256(prev))
		for x256 in batch:
			x = BigUInt.from_bytes(x256.bytes)
			y = (x * prev) % q
			temp.append(UInt256(y))
			prev = y
		inv = expmod(prev, q - BigUInt(2), q)
		i = VK_NB_PUBLIC_INPUTS
		while i > 0:
			tmp = BigUInt.from_bytes(batch[i-1].bytes)
			cur = (inv * BigUInt.from_bytes(temp[i-1].bytes)) % q
			batch[i-1] = UInt256(cur)
			inv = (inv * tmp) % q
			i -= 1

		# We can now interpolate the public inputs (PI)
		w_ = BigUInt(1)
		for i in urange(VK_NB_PUBLIC_INPUTS):
			batch[i] = UInt256((w_ * ((BigUInt.from_bytes(batch[i].bytes) * zn)
								% q)) % q)
			w_ = (w_ * VK_OMEGA) % q

		tmp = BigUInt(0)
		PI = BigUInt(0)
		for i in urange(VK_NB_PUBLIC_INPUTS):
			tmp = (BigUInt.from_bytes(batch[i].bytes)
				   * BigUInt.from_bytes(public_inputs[i].bytes)) % q
			PI = (PI + tmp) % q

		# compute alpha2Lagrange: alpha**2 * (z**n - 1) / (z - 1)
		res = (zeta + q - BigUInt(1)) % q
		res = expmod(res, q - BigUInt(2), q)
		res = (res * zn) % q
		res = (res * alpha) % q
		res = (res * alpha) % q
		alpha2Lagrange = res

		# verify opening linearization polynomial
		s1 = (BigUInt.from_bytes(S1_AT_Z.bytes) * beta) % q
		s1 = (s1 + gamma + BigUInt.from_bytes(L_AT_Z.bytes)) % q

		s2 = (BigUInt.from_bytes(S2_AT_Z.bytes) * beta) % q
		s2 = (s2 + gamma + BigUInt.from_bytes(R_AT_Z.bytes)) % q

		o = (BigUInt.from_bytes(O_AT_Z.bytes) + gamma) % q

		s1 = (s1 * s2) % q
		s1 = (s1 * o) % q
		s1 = (s1 * alpha) % q
		s1 = (s1 * BigUInt.from_bytes(GRAND_PRODUCT_AT_Z_OMEGA.bytes)) % q

		s1 = (s1 + PI + q - alpha2Lagrange)  % q
		linearized_poly_at_z = (q - s1)

		# compute the folded commitment to H
		n2 = VK_DOMAIN_SIZE + BigUInt(2)
		zn2 = expmod(zeta, n2, q)
		folded_h = ec.scalar_mul(EC.BLS12_381g1, H_2, zn2.bytes)
		folded_h = ec.add(EC.BLS12_381g1, folded_h, H_1)
		folded_h = ec.scalar_mul(EC.BLS12_381g1, folded_h, zn2.bytes)
		folded_h = ec.add(EC.BLS12_381g1, folded_h, H_0)
		znminus1 = (expmod(zeta, VK_DOMAIN_SIZE, q) + q - BigUInt(1)) % q
		folded_h = ec.scalar_mul(EC.BLS12_381g1, folded_h, znminus1.bytes)
		folded_h = invert(folded_h)

		# compute commitment to linearization polynomial
		u = (BigUInt.from_bytes(GRAND_PRODUCT_AT_Z_OMEGA.bytes) * beta) % q
		v = (BigUInt.from_bytes(S1_AT_Z.bytes) * beta) % q
		v = (v + BigUInt.from_bytes(L_AT_Z.bytes) + gamma) % q
		w  = (BigUInt.from_bytes(S2_AT_Z.bytes) * beta) % q
		w = (w + BigUInt.from_bytes(R_AT_Z.bytes) + gamma) % q

		s1 = (u * v) % q
		s1 = (s1 * w) % q
		s1 = (s1 * alpha) % q

		coset_square = (VK_COSET_SHIFT * VK_COSET_SHIFT) % q
		betazeta = (beta * zeta) % q
		u = (betazeta + BigUInt.from_bytes(L_AT_Z.bytes) + gamma) % q

		v = (betazeta * VK_COSET_SHIFT) % q
		v = (v + BigUInt.from_bytes(R_AT_Z.bytes) + gamma) % q

		w = (betazeta * coset_square) % q
		w = (w + BigUInt.from_bytes(O_AT_Z.bytes) + gamma) % q

		s2 = (u * v) % q
		s2 = q - ((s2 * w) % q)
		s2 = (s2 * alpha + alpha2Lagrange) % q

		lin_poly_com = ec.scalar_mul(EC.BLS12_381g1, VK_QL, L_AT_Z.bytes)

		add_term = ec.scalar_mul(EC.BLS12_381g1, VK_QR, R_AT_Z.bytes)
		lin_poly_com = ec.add(EC.BLS12_381g1, lin_poly_com, add_term)

		add_term = ec.scalar_mul(EC.BLS12_381g1, VK_QO, O_AT_Z.bytes)
		lin_poly_com = ec.add(EC.BLS12_381g1, lin_poly_com, add_term)

		ab = (BigUInt.from_bytes(L_AT_Z.bytes) * BigUInt.from_bytes(R_AT_Z.bytes)) % q
		add_term = ec.scalar_mul(EC.BLS12_381g1, VK_QM, ab.bytes)
		lin_poly_com = ec.add(EC.BLS12_381g1, lin_poly_com, add_term)
		lin_poly_com = ec.add(EC.BLS12_381g1, lin_poly_com, VK_QK)

		add_term = ec.scalar_mul(EC.BLS12_381g1, VK_S3, s1.bytes)
		lin_poly_com = ec.add(EC.BLS12_381g1, lin_poly_com, add_term)

		add_term = ec.scalar_mul(EC.BLS12_381g1, GRAND_PRODUCT, s2.bytes)
		lin_poly_com = ec.add(EC.BLS12_381g1, lin_poly_com, add_term)

		lin_poly_com = ec.add(EC.BLS12_381g1, lin_poly_com, folded_h)

		# generate challenge to fold the opening proofs
		linearized_poly_at_z_bytes = bzero(32) | linearized_poly_at_z.bytes
		r_pre = sha256(b'gamma' + UInt256(zeta).bytes + lin_poly_com
			 + fs(L_COM) + fs(R_COM) + fs(O_COM) + VK_S1_fs + VK_S2_fs
			 + linearized_poly_at_z_bytes + L_AT_Z.bytes + R_AT_Z.bytes
			 + O_AT_Z.bytes + S1_AT_Z.bytes + S2_AT_Z.bytes
			 + GRAND_PRODUCT_AT_Z_OMEGA.bytes)
		r = curvemod(r_pre)
		r_acc = r

		# fold the proof in one point
		digest = lin_poly_com
		claims =  linearized_poly_at_z

		add_term = ec.scalar_mul(EC.BLS12_381g1, L_COM, r_acc.bytes)
		digest = ec.add(EC.BLS12_381g1, digest, add_term)
		claims = (claims + (BigUInt.from_bytes(L_AT_Z.bytes) * r_acc)) % q

		r_acc = (r_acc * r) % q
		add_term = ec.scalar_mul(EC.BLS12_381g1, R_COM, r_acc.bytes)
		digest = ec.add(EC.BLS12_381g1, digest, add_term)
		claims = (claims + (BigUInt.from_bytes(R_AT_Z.bytes) * r_acc)) % q

		r_acc = (r_acc * r) % q
		add_term = ec.scalar_mul(EC.BLS12_381g1, O_COM, r_acc.bytes)
		digest = ec.add(EC.BLS12_381g1, digest, add_term)
		claims = (claims + (BigUInt.from_bytes(O_AT_Z.bytes) * r_acc)) % q

		r_acc = (r_acc * r) % q
		add_term = ec.scalar_mul(EC.BLS12_381g1, VK_S1, r_acc.bytes)
		digest = ec.add(EC.BLS12_381g1, digest, add_term)
		claims = (claims + (BigUInt.from_bytes(S1_AT_Z.bytes) * r_acc)) % q

		r_acc = (r_acc * r) % q
		add_term = ec.scalar_mul(EC.BLS12_381g1, VK_S2, r_acc.bytes)
		digest = ec.add(EC.BLS12_381g1, digest, add_term)
		claims = (claims + (BigUInt.from_bytes(S2_AT_Z.bytes) * r_acc)) % q

		# verify the folded proof
		r_pre = sha256(digest + BATCH_OPENING_AT_Z + fs(GRAND_PRODUCT)
				+ OPENING_AT_Z_OMEGA + UInt256(zeta).bytes + UInt256(r).bytes)
		r = curvemod(r_pre)

		quotient = BATCH_OPENING_AT_Z
		add_term = ec.scalar_mul(EC.BLS12_381g1, OPENING_AT_Z_OMEGA, r.bytes)
		quotient = ec.add(EC.BLS12_381g1, quotient, add_term)

		add_term = ec.scalar_mul(EC.BLS12_381g1, GRAND_PRODUCT, r.bytes)
		digest = ec.add(EC.BLS12_381g1, digest, add_term)

		claims = (claims + (BigUInt.from_bytes(GRAND_PRODUCT_AT_Z_OMEGA.bytes)
	       		  * r)) % q
		G1_SRS = (bzero(48) | BigUInt(G1_SRS_X).bytes) + (bzero(48) | BigUInt(G1_SRS_Y).bytes)
		claims_com = ec.scalar_mul(EC.BLS12_381g1, G1_SRS, claims.bytes)

		digest = ec.add(EC.BLS12_381g1, digest, invert(claims_com))

		points_quotient = ec.scalar_mul(EC.BLS12_381g1, BATCH_OPENING_AT_Z, zeta.bytes)

		zeta_omega = (zeta * VK_OMEGA) % q
		r = (r * zeta_omega) % q
		add_term = ec.scalar_mul(EC.BLS12_381g1, OPENING_AT_Z_OMEGA, r.bytes)
		points_quotient = ec.add(EC.BLS12_381g1, points_quotient, add_term)

		digest = ec.add(EC.BLS12_381g1, digest, points_quotient)
		quotient = invert(quotient)

		g2 = ((bzero(48) | BigUInt(G2_SRS_0_X_1).bytes) + (bzero(48) | BigUInt(G2_SRS_0_X_0).bytes)
		+ (bzero(48) | BigUInt(G2_SRS_0_Y_1).bytes) + (bzero(48) | BigUInt(G2_SRS_0_Y_0).bytes)
		+ (bzero(48) | BigUInt(G2_SRS_1_X_1).bytes) + (bzero(48) | BigUInt(G2_SRS_1_X_0).bytes)
		+ (bzero(48) | BigUInt(G2_SRS_1_Y_1).bytes) + (bzero(48) | BigUInt(G2_SRS_1_Y_0).bytes))

		check = ec.pairing_check(EC.BLS12_381g1, digest + quotient, g2)
		return arc4.Bool(check)



@subroutine
def expmod(base: BigUInt, exponent: BigUInt, modulus: BigUInt) -> BigUInt:
	"""Compute base^exponent % modulus."""
	result = BigUInt(1)
	while exponent > 0:
		if exponent % 2 == 1:
			result = (result * base) % modulus
		exponent = exponent // 2
		base = (base * base) % modulus
	return result

@subroutine
def curvemod(x: Bytes) -> BigUInt:
	"""Compute x % R_MOD."""
	return BigUInt.from_bytes(x) % BigUInt(R_MOD)

@subroutine
def invert(p : Bytes) -> Bytes:
	"""Invert a point on the curve."""
	x = BigUInt.from_bytes(p[:48])
	y = BigUInt.from_bytes(p[48:])
	neg_y = BigUInt(P_MOD) - y
	return x.bytes + (bzero(48) | (neg_y).bytes)

@subroutine
def fs(p: Bytes) -> Bytes:
	"""If p is the point at infinity, mask the first bit with 1
	to match gnark's encoding for the fiat-shamir challenge."""
	if p == bzero(96):
		return setbit_bytes(p, 0, 1)
	return p
`
