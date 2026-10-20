/*
 * Part 8: replays each Part 2-7 attack against the hardened simulator.
 *
 * Run: node scenarios/hardened.js
 */
const Node = require("../node");
const { HardenedSimulator, verifyCertificate } = require("../hardened");
const { makeByzantine, makeEquivocator, stealKey, forgeVote } = require("../attacks");

function header(title) {
    console.log("\n\n############################################");
    console.log(title);
    console.log("############################################");
}

const fourNodes = () => ["A", "B", "C", "D"].map(id => new Node(id));

/* ------------------------------------------------------------------ */
header("8.1 Detect equivocation");
{
    const nodes = fourNodes();
    makeEquivocator(nodes[3], { A: 100, B: 50, C: 75 });
    new HardenedSimulator(nodes).runConsensus(100);
    console.log("-> D's conflicting signed votes are caught, D is blacklisted, A/B/C still commit.");
}

/* ------------------------------------------------------------------ */
header("8.2 Key theft: detect, revoke, rotate");
{
    const nodes = fourNodes();
    const sim = new HardenedSimulator(nodes);
    const stolen = stealKey(nodes[0]);

    console.log("\nRound 1: attacker injects a forged A vote for 999 using the stolen key");
    sim.runConsensus(100, [forgeVote("A", stolen, 999)]);
    console.log("-> Forgery verifies, but A now appears to have signed two values: flagged as equivocation.");
    console.log("   (Note: the protocol can't tell 'A lied' from 'A's key was stolen'.)");

    console.log("\nResponse: rotate A's key and clear the flag");
    sim.registry.rotateKey(nodes[0]);
    sim.blacklist.delete("A");

    console.log("\nRound 2: attacker tries the old stolen key again");
    sim.runConsensus(100, [forgeVote("A", stolen, 999)]);
    console.log("-> Stolen key no longer verifies. A's genuine vote counts again.");

    console.log("\nAlternative: revoke B entirely");
    sim.registry.revoke("B");
    sim.runConsensus(100);
    console.log("-> B is excluded; 3 of 4 still meet quorum, so the system keeps going.");

    console.log("\nScheduled rotation: rotateEvery = 2 rounds");
    const nodes2 = fourNodes();
    const sim2 = new HardenedSimulator(nodes2, { rotateEvery: 2 });
    const stolen2 = stealKey(nodes2[0]);
    sim2.runConsensus(100);
    sim2.runConsensus(100);
    sim2.runConsensus(100, [forgeVote("A", stolen2, 999)]);
    console.log("-> Key stolen in round 1 expires automatically at round 3.");
}

/* ------------------------------------------------------------------ */
header("8.3 Prevent Sybil attacks");
{
    const nodes = fourNodes();
    for (let i = 1; i <= 10; i++) {
        const x = new Node(`X${i}`);
        makeByzantine(x, 999);
        nodes.push(x);
    }
    new HardenedSimulator(nodes, { approvedValidators: ["A", "B", "C", "D"] }).runConsensus(100);
    console.log("-> All X votes rejected. Quorum stays 3 (based on approved set, not head-count).");
}

/* ------------------------------------------------------------------ */
header("8.4 Protect quorum rules");
{
    class WeakQuorum {
        size() { return 2; }
        reached(c) { return c >= 2; }
    }
    try {
        new HardenedSimulator(fourNodes(), { quorumEngine: new WeakQuorum() });
    } catch (e) {
        console.log(`  Refused to start: ${e.message}`);
    }

    console.log("\nAlso: the unsigned votes used in quorum_tampering.js are now rejected");
    const nodes = fourNodes();
    nodes.forEach((n, i) => { n.vote = () => ({ nodeId: n.id, value: i < 2 ? 100 : 50 }); });
    new HardenedSimulator(nodes).runConsensus(100);
}

/* ------------------------------------------------------------------ */
header("8.5 Commit certificate + independent audit");
{
    const nodes = fourNodes();
    makeByzantine(nodes[3], 50);
    const sim = new HardenedSimulator(nodes);
    const cert = sim.runConsensus(100);

    const ok = verifyCertificate(cert, sim.registry, sim.approvedValidators);
    console.log(`\n  Auditor verifies certificate: ${ok}`);

    const tampered = { ...cert, value: "999" };
    console.log(`  Auditor verifies certificate with value changed to 999: ${verifyCertificate(tampered, sim.registry, sim.approvedValidators)}`);

    const short = { ...cert, signatures: cert.signatures.slice(0, 2) };
    console.log(`  Auditor verifies certificate with only 2 signatures: ${verifyCertificate(short, sim.registry, sim.approvedValidators)}`);
}

/* ------------------------------------------------------------------ */
header("Part 7 E1 replay: garbage signatures");
{
    const nodes = fourNodes();
    nodes.slice(1).forEach(n => { n.vote = () => ({ nodeId: n.id, value: 999, signature: "fake" }); });
    new HardenedSimulator(nodes).runConsensus(100);
    console.log("-> Previously committed 999. Now nothing commits: safety restored, availability lost.");
}
