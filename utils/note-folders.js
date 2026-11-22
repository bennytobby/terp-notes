const { ObjectId } = require('mongodb');
const { z } = require('zod');

const MAX_FOLDERS = 20;
const MAX_NOTES = 100;
const folderId = z.string().regex(/^[a-f0-9]{24}$/);
const name = z.string().trim().min(1).max(60);
const mutation = z.discriminatedUnion('action', [
    z.object({ action: z.literal('create'), name }),
    z.object({ action: z.literal('rename'), folderId, name }),
    z.object({ action: z.literal('delete'), folderId }),
    z.object({ action: z.literal('save'), folderId, filename: z.string().min(1).max(300) }),
    z.object({ action: z.literal('remove'), folderId, noteId: folderId }),
]);

async function list(users, userid) {
    const user = await users.findOne({ userid }, { projection: { noteFolders: 1 } });
    return user?.noteFolders || [];
}

async function update(users, files, userid, visibility, input) {
    const owner = { userid };
    if (input.action === 'create') {
        const id = new ObjectId();
        const result = await users.updateOne({
            ...owner, 'noteFolders.name': { $ne: input.name }, [`noteFolders.${MAX_FOLDERS - 1}`]: { $exists: false },
        }, { $push: { noteFolders: { id, name: input.name, notes: [] } } });
        if (result.matchedCount) return { folderId: id };
        const existing = await users.findOne({ ...owner, 'noteFolders.name': input.name }, {
            projection: { noteFolders: { $elemMatch: { name: input.name } } },
        });
        if (existing) return { folderId: existing.noteFolders[0].id };
        return { status: 409, error: `You can keep up to ${MAX_FOLDERS} folders.` };
    }

    const id = new ObjectId(input.folderId);
    const folder = { ...owner, 'noteFolders.id': id };
    let result;
    if (input.action === 'rename') {
        result = await users.updateOne({
            ...folder, $nor: [{ noteFolders: { $elemMatch: { id: { $ne: id }, name: input.name } } }],
        }, { $set: { 'noteFolders.$.name': input.name } });
        if (!result.matchedCount && await users.findOne(folder, { projection: { _id: 1 } })) {
            return { status: 409, error: 'You already have a folder with that name.' };
        }
    } else if (input.action === 'delete') {
        result = await users.updateOne(folder, { $pull: { noteFolders: { id } } });
    } else if (input.action === 'remove') {
        result = await users.updateOne(folder, { $pull: { 'noteFolders.$.notes': new ObjectId(input.noteId) } });
    } else {
        const note = await files.findOne({ filename: input.filename, ...visibility }, { projection: { _id: 1 } });
        if (!note) return { status: 404, error: 'That note is unavailable.' };
        result = await users.updateOne({
            ...owner, noteFolders: { $elemMatch: {
                id, $or: [{ [`notes.${MAX_NOTES - 1}`]: { $exists: false } }, { notes: note._id }],
            } },
        }, { $addToSet: { 'noteFolders.$.notes': note._id } });
        if (!result.matchedCount && await users.findOne(folder, { projection: { _id: 1 } })) {
            return { status: 409, error: `A folder can hold up to ${MAX_NOTES} notes.` };
        }
    }
    return result.matchedCount ? { folderId: id } : { status: 404, error: 'That folder is unavailable.' };
}

module.exports = { list, update, mutation, folderId };
