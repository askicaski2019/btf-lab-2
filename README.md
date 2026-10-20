# BFT Lab: Breaking and Understanding Byzantine Fault Tolerance

## Running

Requires Node.js 18+. There are no dependencies.

```bash
npm install            # optional, nothing to install
node scenarios/honest.js
```

| Script | Part |
|---|---|
| `npm run honest` | 1. Honest consensus |
| `npm run byzantine` | 2. One Byzantine voter |
| `npm run equivocation` | 3. Equivocation |
| `npm run key-theft` | 4. Key theft |
| `npm run sybil` | 5. Sybil attack |
| `npm run quorum` | 6. Quorum tampering |
| `npm run break` | 7. Five combined attacks (`scenarios/breaking_bft.js`) |
| `npm run harden` | 8. Defences replayed against each attack (`scenarios/hardened.js`) |

Added files: `hardened.js`, `scenarios/breaking_bft.js`, `scenarios/hardened.js`, this README. The original simulator is unchanged so Parts 1-6 behave as shipped.

Note: the manual says `node scenario/honest.js`; the folder is `scenarios/`.

---