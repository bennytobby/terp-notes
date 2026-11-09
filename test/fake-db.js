// Minimal in-memory stand-in for the MongoDB calls our modules make (unit tests only).
function matches(doc, filter) {
    return Object.entries(filter).every(([k, v]) => {
        const actual = k.split(".").reduce((o, p) => (o == null ? undefined : o[p]), doc);
        if (v && typeof v === "object" && !(v instanceof Date) && !Array.isArray(v)) {
            if ("$in" in v) return v.$in.some((x) => x === actual);
            if ("$ne" in v) return actual !== v.$ne;
        }
        return actual === v || (v === null && actual === undefined);
    });
}

function collection() {
    const docs = [];
    let id = 0;
    const cursor = (list) => ({
        sort() { return cursor(list); },
        limit(n) { return cursor(list.slice(0, n)); },
        toArray: async () => list.map((d) => ({ ...d })),
    });
    return {
        docs,
        createIndex: async () => {},
        insertOne: async (d) => { const doc = { _id: ++id, ...d }; docs.push(doc); return { insertedId: doc._id }; },
        findOne: async (f) => { const d = docs.find((x) => matches(x, f)); return d ? { ...d } : null; },
        find: (f = {}) => cursor(docs.filter((x) => matches(x, f))),
        countDocuments: async (f = {}) => docs.filter((x) => matches(x, f)).length,
        updateOne: async (f, u, opts = {}) => {
            let d = docs.find((x) => matches(x, f));
            if (!d) {
                if (!opts.upsert) return { matchedCount: 0, modifiedCount: 0 };
                d = { _id: ++id, ...Object.fromEntries(Object.entries(f).filter(([, v]) => typeof v !== "object")), ...(u.$setOnInsert || {}) };
                docs.push(d);
            }
            Object.assign(d, u.$set || {});
            return { matchedCount: 1, modifiedCount: 1 };
        },
        deleteOne: async (f) => { const i = docs.findIndex((x) => matches(x, f)); if (i >= 0) docs.splice(i, 1); return { deletedCount: i >= 0 ? 1 : 0 }; },
        deleteMany: async (f) => { const before = docs.length; for (let i = docs.length - 1; i >= 0; i--) if (matches(docs[i], f)) docs.splice(i, 1); return { deletedCount: before - docs.length }; },
    };
}

function fakeDb() {
    const cols = {};
    return { collection: (name) => (cols[name] ||= collection()) };
}

module.exports = { fakeDb };
