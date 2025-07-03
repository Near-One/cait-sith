# Common zero-knowledge functionality

The proofs we use in this library are all Maurer proofs: "I know a secret $x$
such that $\varphi(x) = X$, with $X$ a public value", and $\varphi$ being a
homomorphism between groups, i.e. $\varphi(a + b) = \varphi(a) + \varphi(b)$.

A common case of this is the Schnorr discrete logarithm proof, with $\varphi(x)
= x \cdot G$.

In general, we write $\text{Mau}(\varphi, X; x)$ to denote the relation "I know
a private $x$ such that $\varphi(x) = X$. We also write $\text{Mau}(\varphi, X)$
to denote the verifier's view of this relation, where $x$ is not known.

- **strobe\***: minimal implementation of (parts of)
  [Strobe](https://strobe.sourceforge.io/) based on
  [Merlin](https://github.com/zkcrypto/merlin)

- **dlog**: discrete logarithm zero-knowledge: $\varphi(x) = x \cdot
  G$

- **dlogeq**: discrete logarithm zero-knowledge w.r.t. a generator and
  a public value $\varphi(x) = (x \cdot G, x \cdot H)$ where $H$ is known
