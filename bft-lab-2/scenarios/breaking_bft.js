/*
 * Part 7: Breaking BFT
 *
 * Five experiments against the ORIGINAL (unhardened) simulator.
 * Each one violates a different trust assumption.
 *
 * Run: node scenarios/breaking_bft.js
 */
const Node = require("../node");
const Simulator = require("../simulator");
const QuorumEngine = require("../quorum");
const { verify } = require("../crypto");
const { makeByzantine, stealKey, forgeVote } = require("../attacks");

function header(title) {
    console.log("\n\n############################################");
    console.log(title);
    console.log("############################################");
}

function fourNodes() {
    return ["A", "B", "C", "D"].map(id => new Node(id));
}

/*
 * Helper for experiments that need each node's LOCAL view.
 * The original simulator assumes everyone sees the same votes;
 * real nodes only see the messages the network delivers to them.
 */
function localDecision(nodeId, received, quorum) {
    const tally = {};
    for (const v of received) {
        tally[v.value] = (tally[v.value] || 0) + 1;
    }
    const winners = Object.keys(tally).filter(val =>
        quorum.reached(tally[val])
    );
    const decision =
        winners.length === 0 ? "NO CONSENSUS" :
        winners.length === 1 ? `COMMIT ${winners[0]}` :
        `CONFLICT ${winners.join(" & ")}`;
    console.log(`  ${nodeId} sees ${JSON.stringify(tally)} -> ${decision}`);
    return decision;
}

/* ------------------------------------------------------------------ */
header("E1: Impersonation without any key (missing signature check)");
/*
 * The simulator counts vote.value but never calls verify().
 * An attacker on the network replaces B, C and D's votes with
 * garbage-signed votes for 999.
 */
{
    const nodes = fourNodes();
    for (const n of nodes.slice(1)) {
        n.vote = () => ({
            nodeId: n.id,
            value: 999,
            signature: "not-a-real-signature"
        });
    }
    new Simulator(nodes).runConsensus(100);
    console.log("-> 999 committed with NO valid signatures. Implementation flaw.");
}

/* ------------------------------------------------------------------ */
header("E2: Key theft beyond f (validly signed forgeries)");
/*
 * Attacker steals B and C's keys, and D is Byzantine.
 * 3 of 4 identities are now attacker-controlled, but f = 1.
 */
{
    const nodes = fourNodes();
    const [, B, C, D] = nodes;

    const stolenB = stealKey(B);
    const stolenC = stealKey(C);
    B.vote = () => forgeVote("B", stolenB, 999);
    C.vote = () => forgeVote("C", stolenC, 999);
    makeByzantine(D, 999);

    const result = new Simulator(nodes).runConsensus(100);

    console.log("\nSignature check on every vote (using real secrets):");
    for (const v of result.votes) {
        const ok = verify(v.nodeId, v.value, `secret-${v.nodeId}`, v.signature);
        console.log(`  ${v.nodeId} voted ${v.value}: signature valid = ${ok}`);
    }
    console.log("-> Every forgery verifies. Honest A is outvoted. Safety lost.");
}

/* ------------------------------------------------------------------ */
header("E3: Sybil attack (membership manipulation)");
{
    // (a) 4 Sybils: attacker cannot win, but blocks progress
    const nodesA = fourNodes();
    for (let i = 1; i <= 4; i++) {
        const x = new Node(`X${i}`);
        makeByzantine(x, 999);
        nodesA.push(x);
    }
    console.log("\n(a) 4 honest + 4 Sybils");
    new Simulator(nodesA).runConsensus(100);
    console.log("-> Quorum grew to 6; honest nodes alone can't reach it. Availability lost.");

    // (b) 10 Sybils: attacker owns a quorum outright
    const nodesB = fourNodes();
    for (let i = 1; i <= 10; i++) {
        const x = new Node(`X${i}`);
        makeByzantine(x, 999);
        nodesB.push(x);
    }
    console.log("\n(b) 4 honest + 10 Sybils");
    new Simulator(nodesB).runConsensus(100);
    console.log("-> Attacker identities alone meet quorum. Safety lost.");
}

/* ------------------------------------------------------------------ */
header("E4: Equivocation + partition, weak vs correct quorum");
/*
 * A and B propose 100, C proposes 50 (honest but different input).
 * The network is partitioned: {A, B} | {C}.
 * D equivocates: tells A and B "100", tells C "50".
 */
{
    const views = {
        A: [{ value: 100 }, { value: 100 }, { value: 100 }], // A, B, D
        B: [{ value: 100 }, { value: 100 }, { value: 100 }], // A, B, D
        C: [{ value: 50 }, { value: 50 }]                     // C, D
    };

    const weak = { size: () => 2, reached: c => c >= 2 };
    console.log("\nWeak quorum (2):");
    for (const id of Object.keys(views)) localDecision(id, views[id], weak);
    console.log("-> A/B commit 100 while C commits 50. Conflicting commits.");

    const correct = new QuorumEngine(4);
    console.log("\nCorrect quorum (3):");
    for (const id of Object.keys(views)) localDecision(id, views[id], correct);
    console.log("-> C cannot commit. Any two quorums of 3 overlap in an honest node, so safety holds.");
}

/* ------------------------------------------------------------------ */
header("E5: Denial of service (dropped messages)");
/*
 * Network drops all messages from C and D (flooded / partitioned).
 */
{
    const all = [
        { nodeId: "A", value: 100 },
        { nodeId: "B", value: 100 },
        { nodeId: "C", value: 100 },
        { nodeId: "D", value: 100 }
    ];
    const delivered = all.filter(v => !["C", "D"].includes(v.nodeId));
    const q = new QuorumEngine(4);
    for (const id of ["A", "B"]) localDecision(id, delivered, q);
    console.log("-> Everyone honest, everyone agrees, yet nothing commits. Availability lost, safety intact.");
}
