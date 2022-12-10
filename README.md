# Key-PolicyABE-golang

Intended for learning purposes only!

## Evaluation

### Cases

For comparisons with BF-IBE: Setup distinct cases where we want to compare the performance of the systems.

#### Use scenario

1. Point to point communication (email)
2. One to many (encrypted files on shared drive)

#### Number of users

1. Small company (e.g. 50 users, 15 unique roles)
2. Larger company (e.g. 5000 users, 30 unique roles)
3. Google (e.g. 150.000 users, 100 unique roles)

### Experiments

- Benchmark `Setup`.
  - Variables:
    - `n`: the number of attributes.
  - Research Questions:
    - How does performance compare to `Setup` in BF-IBE?
    - How does performance scale with `n`? Linear? Exponential? What did we expect?
- Benchmark `KeyGen`.
  - Variables:
    - `n`: the number of attributes.
    - `T`: the access tree.
  - Research Questions:
    - How does performance compare to `Extract` in BF-IBE?
    - How does performance scale with number of nodes in `n`?
    - How does performance scale with number of nodes in `T`?
- Benchmark `Encrypt`.
  - Variables: TODO
  - Research Questions: TODO
- Benchmark `Decrypt`.
  - Variables: TODO
  - Research Questions: TODO

### Feature comparison

- Setup
  - GPWS must know the full set of possible attributes before running setup, while BF can be "extended" later to allow for other patterns of identity strings while still using the same parameters.
