/**
 * Rate-limit counters kept in MongoDB, for express-rate-limit.
 *
 * The default store keeps counts in the memory of one process. On Vercel every warm instance is
 * its own process, so a limit of 5 really meant "5 per instance". Keeping the counts in the
 * database makes one limit apply across every instance.
 *
 * Each key is one document: { _id, hits, expiresAt }. The increment is a single atomic update,
 * so two requests arriving together can't both read the same count. A TTL index on expiresAt
 * (created in server.js) removes finished windows.
 *
 * If the database can't be reached the store counts in memory for that request instead of
 * failing it: a database blip should not lock everyone out of signing in.
 */

class MongoRateLimitStore {
    /**
     * @param {() => Promise<import('mongodb').Collection>} getCollection resolves to the counters collection
     * @param {string} prefix keeps different limiters' keys apart
     */
    constructor(getCollection, prefix) {
        this.getCollection = getCollection;
        this.prefix = `${prefix}:`;
        this.windowMs = 60_000;
        this.localKeys = false;
        this.fallback = new Map();
    }

    init(options) {
        this.windowMs = options.windowMs;
    }

    async increment(key) {
        const now = new Date();
        const fresh = new Date(now.getTime() + this.windowMs);
        try {
            const collection = await this.getCollection();
            const live = { $gt: ['$expiresAt', now] };
            const doc = await collection.findOneAndUpdate(
                { _id: this.prefix + key },
                [
                    {
                        $set: {
                            hits: { $cond: [live, { $add: ['$hits', 1] }, 1] },
                            expiresAt: { $cond: [live, '$expiresAt', fresh] },
                        },
                    },
                ],
                { upsert: true, returnDocument: 'after' },
            );
            return { totalHits: doc.hits, resetTime: doc.expiresAt };
        } catch (error) {
            return this.incrementInMemory(key, now, fresh);
        }
    }

    incrementInMemory(key, now, fresh) {
        if (this.fallback.size > 10_000) this.fallback.clear();
        const row = this.fallback.get(key);
        if (!row || row.expiresAt <= now) {
            this.fallback.set(key, { hits: 1, expiresAt: fresh });
            return { totalHits: 1, resetTime: fresh };
        }
        row.hits += 1;
        return { totalHits: row.hits, resetTime: row.expiresAt };
    }

    async decrement(key) {
        try {
            const collection = await this.getCollection();
            await collection.updateOne({ _id: this.prefix + key, hits: { $gt: 0 } }, { $inc: { hits: -1 } });
        } catch (error) {
            const row = this.fallback.get(key);
            if (row && row.hits > 0) row.hits -= 1;
        }
    }

    async resetKey(key) {
        this.fallback.delete(key);
        try {
            const collection = await this.getCollection();
            await collection.deleteOne({ _id: this.prefix + key });
        } catch (error) {
            // Nothing to reset if the database is unreachable.
        }
    }
}

module.exports = { MongoRateLimitStore };
