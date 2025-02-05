/*
package verifier provides functions to generate either a verifier logicsig or
verifier smart contract from a compiled circuit.

If logicsig generation is chosen, the generated logicsig will look for its arguments
(proof and public inputs) in the first two elements of the transaction's application
arguments. This the verifier logicsig has to be used to sign an application call
transaction.

If smart contract generation is chosen, the generated contract will be an ARC4
contract with the following ABI methods:

`create` is used to create the application and will set two global properties,
- `app_name` with the provided name
- `immutable` with `false`

	@abimethod(create='require')
	def create(self, name: String) -> None:

`update` allows the creator to update / delete the application unless the
`immutable` property has been set to `true`

	@abimethod(allow_actions=["UpdateApplication", "DeleteApplication"])
	def update(self) -> None:

`make_immutable` allows the creator to set the `immutable` property to `true`,
making the contract fully decentralized with no one able to further modify or
delete it.

	@abimethod
	def make_immutable(self) -> None:

`verify` takes as parameters a proof and public inputs as exported by AlgoPlonk
and returns `True` if the proof is verifier, `False` otherwise

	@abimethod
	def verify(self, proof: ..., public_inputs: ...) -> arc4.Bool:
*/
package verifier
