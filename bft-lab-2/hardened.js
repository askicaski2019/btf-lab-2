/*
 * Part 8: Hardened BFT simulator
 *
 * Defences:
 *   8.1 EquivocationDetector  - evidence log, flags conflicting signed votes
 *   8.2 KeyRegistry           - key rotation + revocation
 *   8.3 Admission control     - only approvedValidators may vote
 *   8.4 SafeQuorum            - refuses unsafe quorum sizes
 *   8.5 Commit certificates   - value + signatures, independently verifiable
 *
 * Also fixes two implementation flaws found in Part 7:
 *   - every vote's signature is now verified
 *   - one vote per validator per round (no duplicates / ballot stuffing)
 *
 * The original simulator.js is untouched so Parts 1-7 still behave as before.
 */
const crypto = require("crypto");
const { sign, verify } = require("./crypto");

/* ---------------------------- 8.4 ---------------------------- */
function minimumQuorum(totalNodes) {
    return Math.floor((2 * totalNodes) / 3) + 1;
}

function validateQuorum(engine, totalNodes) {
    const minimum = minimumQuorum(totalNodes);
    if (engine.size() < minimum) {
        throw new Error(
            `Unsafe quorum size: ${engine.size()} < ${minimum} for ${totalNodes} validators`
        );
    }
}

class SafeQuorum {
    constructor(totalNodes) {
        this.totalNodes = totalNodes;
        validateQuorum(this, totalNodes);
    }
    size() { return minimumQuorum(this.totalNodes); }
    reached(count) { return count >= this.size(); }
}

/* ---------------------------- 8.2 ---------------------------- */
class KeyRegistry {
    constructor() {
        this.keys = new Map();     // nodeId -> current secret
        this.revoked = new Set();
    }

    register(node) {
        this.keys.set(node.id, node.secret);
    }

    // Issue a fresh random key. Any stolen old key stops working.
    rotateKey(node) {
        node.secret = `secret-${node.id}-${crypto.randomBytes(8).toString("hex")}`;
        this.keys.set(node.id, node.secret);
        console.log(`  [keys] rotated key for ${node.id}`);
    }

    revoke(nodeId) {
        this.revoked.add(nodeId);
        console.log(`  [keys] revoked ${nodeId}`);
    }

    isRevoked(nodeId) { return this.revoked.has(nodeId); }
    lookup(nodeId) { return this.keys.get(nodeId); }
}

/* ---------------------------- 8.1 ---------------------------- */
class EquivocationDetector {
    constructor() {
        this.log = [];          // equivocationLog entries
        this.seen = new Map();  // "round:sender" -> Map(value -> entry)
    }

    // Only call with votes whose signature has already been verified,
    // otherwise an attacker could frame an honest node.
    record(round, vote, recipient) {
        const entry = {
            round,
            nodeId: vote.nodeId,
            value: vote.value,
            recipient,
            signature: vote.signature
        };
        this.log.push(entry);

        const key = `${round}:${vote.nodeId}`;
        if (!this.seen.has(key)) this.seen.set(key, new Map());
        const byValue = this.seen.get(key);
        if (!byValue.has(vote.value)) byValue.set(vote.value, entry);
    }

    // Returns proof: two (or more) validly signed, conflicting messages.
    check(round, nodeId) {
        const byValue = this.seen.get(`${round}:${nodeId}`);
        if (!byValue || byValue.size <= 1) return null;
        return [...byValue.values()];
    }
}

/* ---------------------------- 8.5 ---------------------------- */
function verifyCertificate(cert, registry, approvedValidators) {
    const quorum = new SafeQuorum(approvedValidators.length);
    const signers = new Set();
    for (const s of cert.signatures) {
        if (!approvedValidators.includes(s.nodeId)) return false;
        if (!verify(s.nodeId, cert.value, registry.lookup(s.nodeId), s.signature)) return false;
        signers.add(s.nodeId);
    }
    return quorum.reached(signers.size);
}

function printCertificate(cert) {
    console.log("\nCOMMIT CERTIFICATE");
    console.log(`Round = ${cert.round}`);
    console.log(`Value = ${cert.value}`);
    console.log(`Quorum = ${cert.quorum}`);
    console.log("Signed by:");
    for (const s of cert.signatures) {
        console.log(`  ${s.nodeId}  ${s.signature.slice(0, 16)}...`);
    }
}

/* ------------------------- Simulator ------------------------- */
class HardenedSimulator {
    constructor(nodes, options = {}) {
        this.nodes = nodes;
        this.approvedValidators = options.approvedValidators || nodes.map(n => n.id);
        this.rotateEvery = options.rotateEvery || 0;

        // Quorum is based on the APPROVED set, not on whoever showed up.
        const n = this.approvedValidators.length;
        this.quorum = options.quorumEngine || new SafeQuorum(n);
        validateQuorum(this.quorum, n);                       // 8.4

        this.registry = new KeyRegistry();                   // 8.2
        nodes.forEach(node => this.registry.register(node));

        this.detector = new EquivocationDetector();          // 8.1
        this.blacklist = new Set();
        this.auditLog = [];
        this.printed = new Set();
        this.certificates = [];
        this.round = 0;
    }

    reject(vote, reason) {
        this.auditLog.push({ round: this.round, nodeId: vote.nodeId, value: vote.value, status: `REJECTED: ${reason}` });
        const key = `${this.round}:${vote.nodeId}:${vote.value}:${reason}`;
        if (this.printed.has(key)) return;   // print once per sender, keep full audit log
        this.printed.add(key);
        console.log(`  REJECT ${vote.nodeId} vote ${vote.value}: ${reason}`);
    }

    // Admission, revocation, blacklist and signature checks.
    admit(vote) {
        if (!this.approvedValidators.includes(vote.nodeId)) { this.reject(vote, "unknown validator (Sybil?)"); return false; }
        if (this.registry.isRevoked(vote.nodeId)) { this.reject(vote, "key revoked"); return false; }
        if (this.blacklist.has(vote.nodeId)) { this.reject(vote, "blacklisted"); return false; }
        if (!vote.signature ||
            !verify(vote.nodeId, vote.value, this.registry.lookup(vote.nodeId), vote.signature)) {
            this.reject(vote, "bad signature"); return false;
        }
        return true;
    }

    /*
     * extraMessages: attacker-injected votes, e.g. forged or Sybil votes,
     * delivered to every peer.
     */
    runConsensus(value, extraMessages = []) {
        this.round++;
        const round = this.round;

        // 8.2 scheduled key rotation
        if (this.rotateEvery && round > 1 && (round - 1) % this.rotateEvery === 0) {
            console.log(`\n[round ${round}] scheduled key rotation`);
            this.nodes.forEach(n => this.registry.rotateKey(n));
        }

        console.log(`\n==================== Round ${round}, proposal ${value}`);

        // All-to-all exchange: every sender's message to every peer.
        const messages = [];
        for (const sender of this.nodes) {
            for (const peer of this.nodes) {
                if (peer.id === sender.id) continue;
                const vote = sender.voteForPeer ? sender.voteForPeer(peer.id) : sender.vote(value);
                messages.push({ to: peer.id, vote });
            }
        }
        for (const vote of extraMessages) {
            for (const peer of this.nodes) {
                if (peer.id !== vote.nodeId) messages.push({ to: peer.id, vote });
            }
        }

        // Validate, then record into the evidence log
        for (const m of messages) {
            if (this.admit(m.vote)) this.detector.record(round, m.vote, m.to);
        }

        // 8.1 detect equivocation, blacklist offenders
        const senders = new Set(this.detector.log.filter(e => e.round === round).map(e => e.nodeId));
        for (const id of senders) {
            const proof = this.detector.check(round, id);
            if (proof) {
                console.log(`\n  EQUIVOCATION DETECTED: ${id}`);
                proof.forEach(p => console.log(`    ${id} -> ${p.recipient}: ${p.value}  sig ${p.signature.slice(0, 12)}...`));
                this.blacklist.add(id);
            }
        }

        // One vote per validator per round, excluding blacklisted nodes
        const counted = new Map();
        for (const e of this.detector.log) {
            if (e.round !== round || this.blacklist.has(e.nodeId)) continue;
            if (!counted.has(e.nodeId)) counted.set(e.nodeId, e);
        }

        const tally = {};
        for (const v of counted.values()) tally[v.value] = (tally[v.value] || 0) + 1;
        console.log("\n  Counted votes:", JSON.stringify(tally), `| quorum = ${this.quorum.size()}`);

        const winners = Object.keys(tally).filter(v => this.quorum.reached(tally[v]));
        if (winners.length !== 1) {
            console.log(winners.length === 0 ? "\nNO CONSENSUS" : "\nSAFETY VIOLATION!");
            return null;
        }

        // 8.5 commit certificate
        const committed = winners[0];
        const cert = {
            round,
            value: committed,
            quorum: this.quorum.size(),
            signatures: [...counted.values()]
                .filter(v => String(v.value) === committed)
                .map(v => ({ nodeId: v.nodeId, signature: v.signature }))
        };
        this.certificates.push(cert);
        this.auditLog.push({ round, status: "COMMIT", certificate: cert });
        printCertificate(cert);
        return cert;
    }
}

module.exports = {
    HardenedSimulator,
    SafeQuorum,
    KeyRegistry,
    EquivocationDetector,
    validateQuorum,
    verifyCertificate,
    minimumQuorum
};
